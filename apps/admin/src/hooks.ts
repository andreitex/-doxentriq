import { useCallback, useEffect, useRef, useState } from 'react';
import { api, errorMessage } from './api';
import type { JobRecord, ProgressEvent } from './types';
import { mergeJobSnapshot, recordedProgress, startJobUpdates } from './job-updates';
export { terminalStage } from './job-updates';

export function useResource<T>(path: string | null) {
  const [revision, setRevision] = useState(0);
  const lastPath = useRef<string | null>(null);
  const [state, setState] = useState<{ data?: T; loading: boolean; error?: string }>({ loading: Boolean(path) });
  const refresh = useCallback(() => setRevision(value => value + 1), []);
  useEffect(() => {
    if (!path) { lastPath.current = null; setState({ loading: false }); return; }
    const controller = new AbortController();
    const changed = lastPath.current !== path;
    lastPath.current = path;
    setState(previous => ({ data: changed ? undefined : previous.data, loading: true }));
    api<T>(path, { signal: controller.signal })
      .then(data => { if (!controller.signal.aborted) setState({ data, loading: false }); })
      .catch(error => {
        if (!controller.signal.aborted) setState(previous => ({ data: previous.data, loading: false, error: errorMessage(error) }));
      });
    return () => controller.abort();
  }, [path, revision]);
  return { ...state, refresh };
}

export function useJob(jobId: string | null) {
  const [state, setState] = useState<{ job?: JobRecord; events: ProgressEvent[]; loading: boolean; error?: string }>({ events: [], loading: false });
  const [stream, setStream] = useState<'connecting' | 'live' | 'reconnecting' | 'idle'>('idle');
  const generation = useRef(0);
  const refreshRef = useRef<() => Promise<void>>(async () => {});
  const refresh = useCallback(() => refreshRef.current(), []);
  useEffect(() => {
    const current = ++generation.current;
    setState({ events: [], loading: Boolean(jobId) });
    setStream(jobId ? 'connecting' : 'idle');
    if (!jobId) { refreshRef.current = async () => {}; return; }
    const updates = startJobUpdates(jobId, {
      load: signal => api(`/jobs/${encodeURIComponent(jobId)}`, { signal }),
      source: () => {
        const source = new EventSource(`/api/v1/jobs/${encodeURIComponent(jobId)}/events`, { withCredentials: true });
        return { listen: (name, callback) => source.addEventListener(name, callback as EventListener), close: () => source.close() };
      },
      snapshot: data => { if (current === generation.current) setState(previous => ({ ...mergeJobSnapshot(previous.events, data), loading: false })); },
      event: event => {
        if (current !== generation.current) return;
        setState(previous => {
          if (!recordedProgress(event, jobId)) return previous;
          const newer = event.id > (previous.events.at(-1)?.id ?? -1);
          const events = new Map(previous.events.map(item => [item.id, item])); events.set(event.id, event);
          return { ...previous, events: [...events.values()].sort((a, b) => a.id - b.id), job: previous.job && newer ? { ...previous.job, stage: event.stage, updatedAt: event.createdAt } : previous.job };
        });
      },
      stream: value => { if (current === generation.current) setStream(value); },
      error: error => { if (current === generation.current) setState(previous => ({ ...previous, loading: false, error: errorMessage(error) })); },
      expired: () => window.dispatchEvent(new Event('autosoft:session-expired'))
    });
    refreshRef.current = updates.refresh;
    return () => {
      updates.stop();
      refreshRef.current = async () => {};
    };
  }, [jobId]);
  return { ...state, stream, refresh };
}
