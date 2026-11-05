import assert from 'node:assert/strict';
import test from 'node:test';
import { mergeJobSnapshot, recordedProgress, startJobUpdates, type JobSnapshot, type StreamState, type UpdateDependencies } from '../src/job-updates';
import type { JobRecord, ProgressEvent } from '../src/types';

const job: JobRecord = { id: 'job-one', appId: 'app-one', request: 'Build folders', stage: 'implementation', baseReleaseId: null, costUsd: 0, budgetUsd: 1, attempts: 0, createdAt: '2026-10-11T08:00:00Z', updatedAt: '2026-10-11T08:01:00Z' };
const event = (id: number, stage: ProgressEvent['stage'] = 'verification'): ProgressEvent => ({ id, jobId: job.id, stage, kind: 'status', message: 'Recorded progress', createdAt: '2026-10-11T08:02:00Z' });
const snapshot = (stage = job.stage): JobSnapshot => ({ job: { ...job, stage }, events: [] });
async function settle() { for (let n = 0; n < 12; n++) await Promise.resolve(); }
class Clock {
  now = 0; sequence = 0; tasks = new Map<number, { at: number; callback: () => void }>();
  schedule: NonNullable<UpdateDependencies['schedule']> = (callback, milliseconds) => { const id = ++this.sequence; this.tasks.set(id, { at: this.now + milliseconds, callback }); return id as unknown as ReturnType<typeof setTimeout>; };
  clear: NonNullable<UpdateDependencies['clear']> = timer => { this.tasks.delete(timer as unknown as number); };
  async advance(milliseconds: number) {
    const end = this.now + milliseconds;
    for (;;) { const next = [...this.tasks.entries()].sort((a, b) => a[1].at - b[1].at).find(([, value]) => value.at <= end); if (!next) break; this.now = next[1].at; this.tasks.delete(next[0]); next[1].callback(); await settle(); }
    this.now = end; await settle();
  }
}
class Source {
  handlers = new Map<string, ((event: { data?: string }) => void)[]>(); closed = 0;
  listen = (name: string, callback: (event: { data?: string }) => void) => { this.handlers.set(name, [...this.handlers.get(name) ?? [], callback]); };
  close = () => { this.closed++; };
  emit(name: string, value?: unknown) { this.handlers.get(name)?.forEach(callback => callback({ data: value === undefined ? undefined : typeof value === 'string' ? value : JSON.stringify(value) })); }
}
function fixture(load: UpdateDependencies['load'] = async () => snapshot()) {
  const clock = new Clock(), source = new Source(), streams: StreamState[] = [], snapshots: JobSnapshot[] = [], events: ProgressEvent[] = [], errors: unknown[] = [];
  let reads = 0, sources = 0, expired = 0;
  const updates = startJobUpdates(job.id, { load: signal => { reads++; return load(signal); }, source: () => { sources++; return source; }, snapshot: value => snapshots.push(value), event: value => events.push(value), stream: value => streams.push(value), error: value => errors.push(value), expired: () => { expired++; }, schedule: clock.schedule, clear: clock.clear });
  return { clock, source, streams, snapshots, events, errors, updates, reads: () => reads, sources: () => sources, expired: () => expired };
}

test('initial network failure automatically recovers recorded history and starts one stream', async () => {
  let calls = 0; const f = fixture(async () => { if (++calls === 1) throw new Error('temporary read failure'); return snapshot(); });
  await settle(); assert.equal(f.streams.at(-1), 'reconnecting'); assert.equal(f.sources(), 0);
  await f.clock.advance(8000); assert.equal(f.reads(), 2); assert.equal(f.snapshots.length, 1); assert.equal(f.sources(), 1);
  f.source.emit('open'); await settle(); assert.equal(f.streams.at(-1), 'live'); assert.equal(f.sources(), 1);
  f.updates.stop(); assert.equal(f.clock.tasks.size, 0);
});

test('manual refresh after initial failure starts updates and simultaneous refreshes share one read', async () => {
  let resolve!: (value: JobSnapshot) => void, calls = 0;
  const f = fixture(() => { if (++calls === 1) throw new Error('synchronous read failure'); return new Promise(value => { resolve = value; }); });
  await settle(); const one = f.updates.refresh(), two = f.updates.refresh(); assert.equal(one, two); await settle(); assert.equal(f.reads(), 2);
  resolve(snapshot()); await one; assert.equal(f.sources(), 1); f.updates.stop();
});

test('SSE outage reads persisted state and reconnecting open clears fallback polling', async () => {
  const f = fixture(); await settle(); f.source.emit('open'); await settle();
  f.source.emit('error'); assert.equal(f.streams.at(-1), 'reconnecting'); await f.clock.advance(8000); assert.ok(f.reads() >= 3);
  f.source.emit('progress', event(2)); f.source.emit('message', event(1, 'implementation')); await f.clock.advance(350); assert.equal(f.events.length, 2);
  f.source.emit('open'); await settle(); const before = f.reads(); await f.clock.advance(16000); assert.equal(f.reads(), before); assert.equal(f.streams.at(-1), 'live'); f.updates.stop();
});

test('teardown aborts its read and ignores queued old-source events and delayed REST responses', async () => {
  let resolve!: (value: JobSnapshot) => void, signal!: AbortSignal;
  const slow = fixture(current => { signal = current; return new Promise(value => { resolve = value; }); }); await settle(); slow.updates.stop(); assert.equal(signal.aborted, true); resolve(snapshot()); await settle(); assert.equal(slow.snapshots.length, 0); assert.equal(slow.sources(), 0);
  const f = fixture(); await settle(); f.updates.stop(); const before = f.streams.length; f.source.emit('progress', event(1)); f.source.emit('error'); f.source.emit('open'); await f.clock.advance(60000); assert.equal(f.events.length, 0); assert.equal(f.streams.length, before); assert.equal(f.reads(), 1);
});

test('session expiry stops browser reads and never retries the event stream', async () => {
  const f = fixture(); await settle(); f.source.emit('error'); f.source.emit('session_expired'); assert.equal(f.expired(), 1); assert.equal(f.streams.at(-1), 'idle'); assert.equal(f.source.closed, 1); const reads = f.reads(); await f.clock.advance(60000); await f.updates.refresh(); assert.equal(f.reads(), reads);
});

test('confirmed terminal history stops timers and ignores delayed stream callbacks', async () => {
  let completed = false; const f = fixture(async () => snapshot(completed ? 'completed' : 'implementation')); await settle(); f.source.emit('error'); completed = true; await f.clock.advance(8000);
  assert.equal(f.snapshots.at(-1)?.job.stage, 'completed'); assert.equal(f.streams.at(-1), 'idle'); assert.equal(f.clock.tasks.size, 0); const reads = f.reads(); f.source.emit('error'); f.source.emit('progress', event(3)); await f.clock.advance(60000); assert.equal(f.events.length, 0); assert.equal(f.reads(), reads);
});

test('a stalled initial status read is aborted before fallback recovery', async () => {
  let first = true; const f = fixture(signal => { if (!first) return Promise.resolve(snapshot()); first = false; return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('abort')))); });
  await settle(); await f.clock.advance(30000); assert.match(String(f.errors.at(-1)), /timed out/); assert.equal(f.streams.at(-1), 'reconnecting'); await f.clock.advance(8000); assert.equal(f.snapshots.length, 1); assert.equal(f.sources(), 1); f.updates.stop();
});

test('denied or missing jobs stop fallback reads while malformed snapshots remain unavailable', async () => {
  for (const status of [401, 403, 404]) { const f = fixture(async () => { throw Object.assign(new Error('denied'), { status }); }); await settle(); assert.equal(f.streams.at(-1), 'idle'); await f.clock.advance(60000); assert.equal(f.reads(), 1); }
  const f = fixture(async () => ({ ...snapshot(), job: { ...job, id: 'foreign-job' } })); await settle(); assert.equal(f.snapshots.length, 0); assert.equal(f.sources(), 0); assert.equal(f.streams.at(-1), 'reconnecting'); f.updates.stop();
});

test('foreign and malformed progress cannot alter the selected job', async () => {
  const f = fixture(); await settle();
  for (const value of ['{', { ...event(1), jobId: 'foreign-job' }, { ...event(1), id: Infinity }, { ...event(1), stage: 'invented' }, { ...event(1), createdAt: 'invalid' }]) f.source.emit('progress', value);
  assert.equal(f.events.length, 0); assert.equal(recordedProgress({ ...event(1), id: -1 }, job.id), false); f.updates.stop();
});

test('snapshot replay deduplicates events without undoing a newer SSE transition', () => {
  const incoming = { ...snapshot(), events: [event(1, 'implementation')] }, previous = [event(3), { ...event(100), jobId: 'foreign-job' }, event(1, 'implementation')];
  const merged = mergeJobSnapshot(previous, incoming); assert.equal(merged.job.stage, 'verification'); assert.equal(merged.job.updatedAt, event(3).createdAt); assert.deepEqual(merged.events.map(value => value.id), [1, 3]); assert.deepEqual(previous.map(value => value.id), [3, 100, 1]);
  const fresh = mergeJobSnapshot(previous, { job: { ...job, stage: 'completed', updatedAt: '2026-10-11T08:03:00Z' }, events: [event(4, 'completed')] }); assert.equal(fresh.job.stage, 'completed');
});
