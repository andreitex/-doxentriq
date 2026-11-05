import amqp, { type ChannelModel, type ConfirmChannel, type ConsumeMessage } from 'amqplib';
import { readFile } from 'node:fs/promises';
import type { Store } from './store.ts';
import type { WorkflowEngine } from './engine.ts';
import { DrainDeadline, WorkDrain, drainTogether } from './shutdown.ts';
const queueName = 'autosoft.jobs';
type BrokerSession = { connection: ChannelModel; channel: ConfirmChannel | null; ready: boolean; consumerTag?: string; closed: boolean; connectionClosed: boolean; closing?: Promise<void> };
type RabbitTlsOptions = { ca?: Buffer[]; cert?: Buffer; key?: Buffer; rejectUnauthorized?: boolean };
export type DispatcherOptions = { connect?: (url: string, tls: RabbitTlsOptions) => Promise<ChannelModel>; readTlsFile?: (path: string) => Promise<Buffer>; reconnectMs?: number; flushMs?: number };

export class RabbitDispatcher {
  private session: BrokerSession | null = null;
  private sessions = new Set<BrokerSession>();
  private closing = false;
  private starting: Promise<void> | null = null;
  private flushing: Promise<void> | null = null;
  private closePromise: Promise<void> | null = null;
  private cancellations: Promise<void> | null = null;
  private drainFailures: unknown[] = [];
  private jobs = new WorkDrain();
  private interval: NodeJS.Timeout | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  constructor(private store: Store, private url: string, private options: DispatcherOptions = {}) {}

  start(engine?: Pick<WorkflowEngine, 'run'>): Promise<void> {
    if (this.closing) return Promise.resolve();
    if (this.starting) return this.starting;
    if (this.session && !this.session.closed) return Promise.resolve();
    const task = this.open(engine); this.starting = task;
    void task.then(() => { if (this.starting === task) this.starting = null; }, error => { if (this.starting === task) this.starting = null; if (this.closing) this.drainFailures.push(error); });
    return task;
  }
  private async open(engine?: Pick<WorkflowEngine, 'run'>): Promise<void> {
    const tls: RabbitTlsOptions = {};
    const read = this.options.readTlsFile ?? readFile;
    if (process.env.RABBITMQ_CA_FILE) { tls.ca = [await read(process.env.RABBITMQ_CA_FILE)]; tls.rejectUnauthorized = true; }
    if (process.env.RABBITMQ_CERT_FILE) tls.cert = await read(process.env.RABBITMQ_CERT_FILE);
    if (process.env.RABBITMQ_KEY_FILE) tls.key = await read(process.env.RABBITMQ_KEY_FILE);
    if (this.closing) return;
    const connection = await (this.options.connect ?? amqp.connect)(this.url, tls);
    const session: BrokerSession = { connection, channel: null, ready: false, closed: false, connectionClosed: false }; this.sessions.add(session);
    connection.on('error', () => undefined);
    connection.on('close', () => {
      session.closed = true; session.connectionClosed = true; this.sessions.delete(session);
      if (this.session !== session) return; this.session = null; this.reconnect(engine);
    });
    if (this.closing) { await this.closeConnection(session); return; }
    this.session = session;
    try {
      const channel = await connection.createConfirmChannel(); session.channel = channel;
      channel.on('error', () => undefined);
      channel.on('close', () => {
        session.closed = true;
        if (this.session !== session) return; this.session = null;
        void this.closeConnection(session).catch(() => undefined); this.reconnect(engine);
      });
      if (this.closing || session.closed) return;
      await channel.assertQueue(queueName, { durable: true, arguments: { 'x-queue-type': 'quorum' } });
      if (this.closing || session.closed) return;
      await channel.prefetch(1);
      if (this.closing || session.closed) return;
      if (engine) {
        const consumer = await channel.consume(queueName, message => this.delivery(session, channel, engine, message));
        session.consumerTag = consumer.consumerTag;
      }
      if (this.closing || session.closed) return;
      session.ready = true;
      if (!this.interval) { this.interval = setInterval(() => void this.flush().catch(() => undefined), this.options.flushMs ?? 1000); this.interval.unref(); }
      await this.flush();
    } catch (error) {
      if (this.session === session) this.session = null;
      await this.closeConnection(session); throw error;
    }
  }
  private delivery(session: BrokerSession, channel: ConfirmChannel, engine: Pick<WorkflowEngine, 'run'>, message: ConsumeMessage | null): void {
    if (!message) return;
    const nack = (requeue: boolean) => { if (!session.closed) try { channel.nack(message, false, requeue); } catch { /* Its original connection retains redelivery responsibility. */ } };
    if (this.closing || session.closed) { nack(true); return; }
    const task = this.jobs.run(async () => {
      let jobId: unknown;
      try { jobId = (JSON.parse(message.content.toString()) as { jobId?: unknown }).jobId; }
      catch { nack(false); return; }
      if (typeof jobId !== 'string' || !/^[a-f0-9-]{36}$/.test(jobId)) { nack(false); return; }
      try { await engine.run(jobId); if (!session.closed) channel.ack(message); }
      catch (error) { nack(true); throw error; }
    });
    if (!task) nack(true); else void task.catch(() => undefined);
  }
  flush(): Promise<void> {
    if (this.flushing) return this.flushing;
    if (this.closing || !this.session || !this.session.ready || this.session.closed) return Promise.resolve();
    return this.flushPending(false);
  }
  private flushPending(untilEmpty: boolean): Promise<void> {
    const session = this.session, channel = session?.channel;
    if (!session || !channel || !session.ready || session.closed) return Promise.resolve();
    const task = (async () => {
      do {
        const pending = await this.store.read(state => Object.values(state.outbox).filter(item => !item.publishedAt).slice(0, 100));
        if (!pending.length) return;
        for (const item of pending) {
          if (session.closed) return;
          await new Promise<void>((resolve, reject) => channel.sendToQueue(queueName, Buffer.from(JSON.stringify({ jobId: item.jobId })), { persistent: true, contentType: 'application/json', messageId: item.id }, value => value ? reject(value) : resolve()));
          // A confirmation lost with the connection leaves durable outbox state for a duplicate-safe retry.
          await this.store.transaction(state => { if (state.outbox[item.id]) state.outbox[item.id]!.publishedAt = new Date().toISOString(); });
        }
      } while (untilEmpty);
    })();
    this.flushing = task;
    void task.then(() => { if (this.flushing === task) this.flushing = null; }, error => { if (this.flushing === task) this.flushing = null; if (this.closing) this.drainFailures.push(error); });
    return task;
  }
  available(): boolean { return !this.closing && this.session !== null && this.session.channel !== null && this.session.ready && !this.session.closed; }
  private reconnect(engine?: Pick<WorkflowEngine, 'run'>): void {
    if (this.closing || this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => { this.reconnectTimer = null; void this.start(engine).catch(() => this.reconnect(engine)); }, this.options.reconnectMs ?? 5000); this.reconnectTimer.unref();
  }
  stopAdmission(): void {
    if (this.closing) return; this.closing = true; this.jobs.stopAdmission();
    if (this.interval) { clearInterval(this.interval); this.interval = null; }
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
    // cancel starts immediately; close also awaits startup because consume may still be returning its tag.
    this.cancellations = this.cancelConsumers(); void this.cancellations.catch(() => undefined);
  }
  private async cancelConsumers(): Promise<void> {
    await drainTogether([...this.sessions].filter(session => session.consumerTag && !session.closed).map(session => async () => {
      const tag = session.consumerTag!; delete session.consumerTag; await session.channel!.cancel(tag);
    }));
  }
  private closeConnection(session: BrokerSession): Promise<void> {
    if (session.closing) return session.closing;
    if (session.connectionClosed) return Promise.resolve();
    session.closing = session.connection.close(); return session.closing;
  }
  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.stopAdmission(); const deadline = new DrainDeadline();
    this.closePromise = (async () => {
      await deadline.wait(() => drainTogether([() => this.starting ?? Promise.resolve(), () => this.cancellations ?? Promise.resolve(), () => this.jobs.drain(), () => this.flushing ?? Promise.resolve()]));
      if (this.drainFailures.length) throw new AggregateError(this.drainFailures, 'Broker work failed after admission closed.');
      await deadline.wait(() => this.cancelConsumers());
      await deadline.wait(() => this.flushPending(true));
      await deadline.wait(() => drainTogether([...this.sessions].map(session => () => this.closeConnection(session))));
    })();
    return this.closePromise;
  }
}

export type LocalWorker = { stopAdmission: () => void; close: () => Promise<void>; tick: () => Promise<void> };
/** JSON persistence is deliberately single-process and loopback-only. */
export function startLocalWorker(store: Store, engine: Pick<WorkflowEngine, 'run'>, intervalMs = 1000): LocalWorker {
  const work = new WorkDrain(); let inFlight: Promise<void> | undefined, closePromise: Promise<void> | undefined;
  const tick = () => {
    if (inFlight) return inFlight;
    const task = work.run(async () => {
      const pending = await store.read(state => Object.values(state.outbox).find(item => !item.publishedAt));
      if (!pending) return;
      await store.transaction(state => { const item = state.outbox[pending.id]; if (item) item.publishedAt = new Date().toISOString(); }); await engine.run(pending.jobId);
    });
    if (!task) return Promise.resolve(); inFlight = task;
    void task.then(() => { if (inFlight === task) inFlight = undefined; }, () => { if (inFlight === task) inFlight = undefined; }); return task;
  };
  const timer = setInterval(() => void tick().catch(() => undefined), intervalMs); timer.unref();
  const stopAdmission = () => { clearInterval(timer); work.stopAdmission(); };
  return { tick, stopAdmission, close: () => { if (!closePromise) { stopAdmission(); closePromise = new DrainDeadline().wait(() => work.drain()); } return closePromise; } };
}
