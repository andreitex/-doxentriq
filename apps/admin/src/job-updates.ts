import type { JobRecord, ProgressEvent } from './types';

export type JobSnapshot = { job: JobRecord; events: ProgressEvent[] };
export type StreamState = 'connecting' | 'live' | 'reconnecting' | 'idle';
type Source = { listen: (name: string, callback: (event: { data?: string }) => void) => void; close: () => void };
type Timer = ReturnType<typeof setTimeout>;
export type UpdateDependencies = {
  load: (signal: AbortSignal) => Promise<JobSnapshot>; source: () => Source;
  snapshot: (value: JobSnapshot) => void; event: (value: ProgressEvent) => void;
  stream: (value: StreamState) => void; error: (value: unknown) => void; expired: () => void;
  schedule?: (callback: () => void, milliseconds: number) => Timer; clear?: (timer: Timer) => void;
};
export const terminalStage = (stage: string) => ['completed', 'failed', 'cancelled'].includes(stage);
const stages = new Set(['queued', 'clarification', 'specification', 'implementation', 'verification', 'preview', 'awaiting_approval', 'deployment', 'observation', 'completed', 'failed', 'cancelled', 'needs_attention']);
const kinds = new Set(['status', 'message', 'tool', 'test', 'error', 'approval']);

export function recordedProgress(value: unknown, jobId: string): value is ProgressEvent {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const event = value as Partial<ProgressEvent>;
  return event.jobId === jobId && Number.isSafeInteger(event.id) && event.id! >= 0 && typeof event.stage === 'string' && stages.has(event.stage) && typeof event.kind === 'string' && kinds.has(event.kind) && typeof event.message === 'string' && typeof event.createdAt === 'string' && Number.isFinite(Date.parse(event.createdAt));
}

/** A late REST snapshot cannot undo a newer recorded SSE transition. */
export function mergeJobSnapshot(previous: ProgressEvent[], value: JobSnapshot): JobSnapshot {
  const incoming = value.events.filter(event => recordedProgress(event, value.job.id));
  const existing = previous.filter(event => recordedProgress(event, value.job.id));
  const merged = new Map(existing.map(event => [event.id, event]));
  incoming.forEach(event => merged.set(event.id, event));
  const events = [...merged.values()].sort((a, b) => a.id - b.id), latest = existing.sort((a, b) => a.id - b.id).at(-1);
  const incomingLast = incoming.reduce((id, event) => Math.max(id, event.id), -1);
  const job = latest && latest.id > incomingLast && Date.parse(latest.createdAt) >= Date.parse(value.job.updatedAt)
    ? { ...value.job, stage: latest.stage, updatedAt: latest.createdAt } : value.job;
  return { job, events };
}

/** This owns only browser reads. It never starts, resumes or cancels a job. */
export function startJobUpdates(jobId: string, dependencies: UpdateDependencies) {
  const schedule: NonNullable<UpdateDependencies['schedule']> = dependencies.schedule ?? ((callback, milliseconds) => setTimeout(callback, milliseconds) as Timer);
  const clear: NonNullable<UpdateDependencies['clear']> = dependencies.clear ?? (timer => clearTimeout(timer));
  let stopped = false, terminal = false, source: Source | undefined;
  let polling: Timer | undefined, debounced: Timer | undefined, deadline: Timer | undefined;
  let request: AbortController | undefined, inFlight: Promise<void> | undefined;
  const active = () => !stopped && !terminal;
  const cancelPolling = () => { if (polling !== undefined) clear(polling); polling = undefined; };
  function stop() {
    stopped = true; source?.close(); source = undefined; request?.abort(); cancelPolling();
    if (debounced !== undefined) clear(debounced); if (deadline !== undefined) clear(deadline);
    debounced = deadline = undefined;
  }
  function poll() {
    if (!active() || polling !== undefined) return;
    polling = schedule(() => { polling = undefined; if (active()) { void refresh(); poll(); } }, 8000);
  }
  function reconnect() { if (active()) { dependencies.stream('reconnecting'); poll(); } }
  function connect() {
    if (!active() || source) return;
    try { source = dependencies.source(); } catch { reconnect(); return; }
    source.listen('open', () => { if (!active()) return; cancelPolling(); dependencies.stream('live'); void refresh(); });
    const receive = (message: { data?: string }) => {
      if (!active() || typeof message.data !== 'string') return;
      try {
        const event: unknown = JSON.parse(message.data); if (!recordedProgress(event, jobId)) return;
        dependencies.event(event); if (debounced !== undefined) clear(debounced);
        debounced = schedule(() => { debounced = undefined; if (active()) void refresh(); }, 350);
      } catch { /* Malformed and non-progress messages cannot alter the job. */ }
    };
    source.listen('message', receive); source.listen('progress', receive);
    source.listen('error', reconnect); source.listen('unavailable', reconnect);
    source.listen('session_expired', () => { if (!active()) return; stop(); dependencies.stream('idle'); dependencies.expired(); });
  }
  function refresh(): Promise<void> {
    if (!active()) return Promise.resolve(); if (inFlight) return inFlight;
    const current = new AbortController(); request = current;
    deadline = schedule(() => current.abort(), 30000);
    inFlight = Promise.resolve().then(async () => {
      try {
        const data = await dependencies.load(current.signal);
        if (!active() || current.signal.aborted) return;
        if (!data || data.job?.id !== jobId || !Array.isArray(data.events) || !stages.has(data.job.stage)) throw new Error('The recorded job response is unavailable.');
        dependencies.snapshot(data);
        if (terminalStage(data.job.stage)) {
          terminal = true; source?.close(); source = undefined; cancelPolling();
          if (debounced !== undefined) clear(debounced); debounced = undefined; dependencies.stream('idle');
        } else connect();
      } catch (error) {
        if (stopped || terminal) return;
        dependencies.error(current.signal.aborted ? new Error('The job-status request timed out. Reconnecting to recorded progress…') : error);
        const status = error && typeof error === 'object' ? (error as { status?: number }).status : undefined;
        if (status === 401 || status === 403 || status === 404) { stop(); dependencies.stream('idle'); }
        else reconnect();
      } finally {
        if (deadline !== undefined) clear(deadline); deadline = undefined;
        if (request === current) request = undefined; inFlight = undefined;
      }
    });
    return inFlight;
  }
  dependencies.stream('connecting'); void refresh();
  return { refresh, stop };
}
