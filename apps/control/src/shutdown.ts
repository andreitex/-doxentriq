/** Closing admission does not cancel a provider request or an external action. */
export class WorkDrain {
  private accepting = true;
  private pending = new Set<Promise<unknown>>();
  private failures: unknown[] = [];
  run<T>(action: () => Promise<T>): Promise<T> | undefined {
    if (!this.accepting) return undefined;
    const task = Promise.resolve().then(action); this.pending.add(task);
    void task.then(() => this.pending.delete(task), error => { this.pending.delete(task); if (!this.accepting) this.failures.push(error); });
    return task;
  }
  stopAdmission(): void { this.accepting = false; }
  async drain(): Promise<void> {
    this.stopAdmission();
    while (this.pending.size) await Promise.allSettled([...this.pending]);
    if (this.failures.length) throw new AggregateError(this.failures, 'Admitted work failed while draining.');
  }
}

export class DrainTimeoutError extends Error {
  constructor() { super('Shutdown deadline exceeded; running or uncertain work remains subject to durable recovery.'); this.name = 'DrainTimeoutError'; }
}

/** One deadline is shared by all phases. A timeout never advances to a later phase. */
export class DrainDeadline {
  private readonly expiresAt: number;
  constructor(timeoutMs = 50000) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 50000) throw new Error('The shutdown budget must be greater than zero and at most 50 seconds.');
    this.expiresAt = performance.now() + timeoutMs;
  }
  async wait<T>(action: () => Promise<T>): Promise<T> {
    const remaining = this.expiresAt - performance.now(); if (remaining <= 0) throw new DrainTimeoutError();
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([Promise.resolve().then(action), new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new DrainTimeoutError()), remaining); })]);
    } finally { if (timer) clearTimeout(timer); }
  }
}

export type ShutdownSteps = {
  stopAdmission: () => void;
  drain: () => Promise<void>;
  closeResources: () => Promise<void>;
  closeStore: () => Promise<void>;
};
export function createShutdown(steps: ShutdownSteps, timeoutMs = 50000): () => Promise<void> {
  let closing: Promise<void> | undefined;
  return () => {
    if (closing) return closing;
    // This must be synchronous: no delivery or timer can be admitted after the signal.
    const deadline = new DrainDeadline(timeoutMs);
    try { steps.stopAdmission(); } catch (error) { closing = Promise.reject(error); return closing; }
    closing = (async () => {
      await deadline.wait(steps.drain);
      await deadline.wait(steps.closeResources);
      await deadline.wait(steps.closeStore);
    })();
    return closing;
  };
}

export async function drainTogether(actions: (() => Promise<unknown>)[]): Promise<void> {
  const results = await Promise.allSettled(actions.map(action => Promise.resolve().then(action)));
  const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected').map(result => result.reason);
  if (failures.length) throw new AggregateError(failures, 'Shutdown could not complete every admitted operation.');
}

export function installTerminationHandlers(close: () => Promise<void>, report: (message: string) => void, target: Pick<NodeJS.Process, 'on' | 'exit'> = process): void {
  let terminating = false;
  const terminate = () => {
    if (terminating) return; terminating = true;
    void close().then(() => target.exit(0), () => {
      try { report('Shutdown failed or exceeded 50 seconds. Running and uncertain records are preserved; provider requests and external effects are not confirmed cancelled.'); }
      catch { /* Diagnostic failures must not prevent nonzero termination. */ }
      finally { target.exit(1); }
    });
  };
  target.on('SIGINT', terminate); target.on('SIGTERM', terminate);
}
