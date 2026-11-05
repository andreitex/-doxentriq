import { Redis } from 'ioredis';
import { readFile } from 'node:fs/promises';
import type { State, Store } from './store.ts';
const channel = 'platform:events';
/** Redis carries only disposable wakeups. Every SSE replay is read from the durable store. */
export class ProgressBus {
  private listeners = new Map<string, Set<() => void>>();
  private publisher: Redis; private subscriber: Redis;
  constructor(url: string, ca?: Buffer) {
    const options = { lazyConnect: true, maxRetriesPerRequest: 1, connectTimeout: 5000, commandTimeout: 1500, ...(url.startsWith('rediss:') ? { tls: { ca, rejectUnauthorized: true } } : {}) };
    this.publisher = new Redis(url, options); this.subscriber = new Redis(url, options);
    this.publisher.on('error', () => undefined); this.subscriber.on('error', () => undefined);
    this.subscriber.on('message', (_channel: string, message: string) => {
      try { const jobs = JSON.parse(message) as unknown; if (!Array.isArray(jobs)) return; for (const jobId of jobs) if (typeof jobId === 'string') for (const listener of this.listeners.get(jobId) ?? []) listener(); } catch { /* Malformed wakeups never become workflow data. */ }
    });
  }
  async start(): Promise<void> { await Promise.allSettled([this.publisher.connect(), this.subscriber.connect()]); await this.subscriber.subscribe(channel).catch(() => undefined); }
  async publish(jobIds: string[]): Promise<void> { if (jobIds.length && this.publisher.status === 'ready') await this.publisher.publish(channel, JSON.stringify(jobIds)); }
  subscribe(jobId: string, listener: () => void): () => void { const listeners = this.listeners.get(jobId) ?? new Set(); listeners.add(listener); this.listeners.set(jobId, listeners); return () => { listeners.delete(listener); if (!listeners.size) this.listeners.delete(jobId); }; }
  async close(): Promise<void> { this.publisher.disconnect(); this.subscriber.disconnect(); this.listeners.clear(); }
}
export class ObservableStore implements Store {
  readonly mode: Store['mode'];
  constructor(private durable: Store, private bus: ProgressBus) { this.mode = durable.mode; }
  async transaction<T>(action: (state: State) => T | Promise<T>): Promise<T> {
    let jobs: string[] = [];
    const result = await this.durable.transaction(async state => { const cursor = state.nextEventId; const result = await action(state); jobs = [...new Set(state.events.filter(event => event.id >= cursor).map(event => event.jobId))]; return result; });
    await this.bus.publish(jobs).catch(() => undefined); return result;
  }
  read<T>(action: (state: State) => T): Promise<T> { return this.durable.read(action); }
  subscribe(jobId: string, listener: () => void): () => void { return this.bus.subscribe(jobId, listener); }
  async close(): Promise<void> { await this.bus.close(); await this.durable.close(); }
}
export async function observableStore(store: Store, redisUrl?: string): Promise<Store> {
  if (!redisUrl) return store;
  const bus = new ProgressBus(redisUrl, process.env.REDIS_CA_FILE ? await readFile(process.env.REDIS_CA_FILE) : undefined); await bus.start(); return new ObservableStore(store, bus);
}
