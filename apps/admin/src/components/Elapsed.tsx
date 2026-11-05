import { useEffect, useState } from 'react';
import { terminalStage } from '../hooks';
import { formatElapsed, progressTiming } from '../progress-time';
import type { JobRecord, ProgressEvent } from '../types';
import { humanize } from './ui';

export default function Elapsed({ job, events }: { job: JobRecord; events: ProgressEvent[] }) {
  const [now, setNow] = useState(Date.now);
  const stopped = terminalStage(job.stage);
  useEffect(() => {
    if (stopped) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [job.id, stopped]);
  const { requestMs, stageMs } = progressTiming(job, events, now);
  return <span role="timer" aria-live="off" aria-label="Request elapsed time" title="Request elapsed includes waiting for input and approval. Stage time uses recorded progress.">
    Elapsed {requestMs === null ? 'unavailable' : formatElapsed(requestMs)}
    {stageMs !== null && <> · {humanize(job.stage)} {formatElapsed(stageMs)}</>}
  </span>;
}
