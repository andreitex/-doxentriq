import type { JobRecord, ProgressEvent } from './types';

const finished = new Set(['completed', 'failed', 'cancelled']);

/** Use persisted timestamps so reconnection and a throttled browser keep the same clock. */
export function progressTiming(job: JobRecord, events: ProgressEvent[], now: number) {
  const started = Date.parse(job.createdAt);
  const stopped = finished.has(job.stage);
  const end = stopped ? Date.parse(job.updatedAt) : now;
  const requestMs = Number.isFinite(started) && Number.isFinite(end) && end >= started ? end - started : null;
  if (requestMs === null || stopped) return { requestMs, stageMs: null };

  const recorded = events.filter(event => event.jobId === job.id && Number.isSafeInteger(event.id) && event.id >= 0)
    .sort((a, b) => a.id - b.id);
  if (recorded.length === 0) return { requestMs, stageMs: null };
  if (recorded.at(-1)?.stage !== job.stage) return { requestMs, stageMs: null };
  let first = recorded.length - 1;
  while (first > 0 && recorded[first - 1]?.stage === job.stage) first--;
  // Diagnostics expire after seven days. Without the preceding transition,
  // the first retained event cannot prove when this stage actually began.
  if (first === 0) return { requestMs, stageMs: null };
  const stageStart = Date.parse(recorded[first]!.createdAt);
  return { requestMs, stageMs: Number.isFinite(stageStart) && stageStart >= started && stageStart <= end ? end - stageStart : null };
}

export function formatElapsed(milliseconds: number): string {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return 'unavailable';
  const seconds = Math.floor(milliseconds / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}
