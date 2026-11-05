import type { Store, State } from './store.ts';
import { event, notify } from './store.ts';
import type { EngineDependencies } from './engine.ts';
import { redact } from '../../../packages/core/src/index.ts';
import { recordDatabaseSchema } from './schema-state.ts';
export function failDeployment(state: State, operationId: string, message: string): void {
  const current = state.operations[operationId]; if (!current || current.status !== 'running') return;
  current.status = 'failed'; current.error = message;
  for (const job of Object.values(state.jobs)) if (job.result?.releaseId === current.releaseId && job.stage === 'deployment') event(state, job, 'awaiting_approval', 'Publication did not occur. Review the diagnostics and request a new exact-release approval before trying again.', 'error', { operationId, error: message });
}
/** Reads trusted broker receipts; never replays a publication request. */
export async function reconcileDeployments(store: Store, dependencies: EngineDependencies, operationId?: string): Promise<void> {
  if (!dependencies.operation) return;
  const operations = await store.read(state => Object.values(state.operations).filter(item => item.status === 'running' && (!operationId || item.id === operationId)));
  for (const operation of operations) {
    try {
      let receipt = await dependencies.operation({ operationId: operation.id });
      // A signed broker tombstone closes the never-started crash gap under the broker's
      // app lock. We never infer non-publication from elapsed time or replay a request.
      if (receipt.status === 'unknown' && Date.now() - Date.parse(operation.createdAt) >= 5 * 60000 && dependencies.cancelOperation && operation.approvalId && operation.artifactHash) {
        receipt = await dependencies.cancelOperation({ operationId: operation.id, appId: operation.appId, releaseId: operation.releaseId, approvalId: operation.approvalId, artifactHash: operation.artifactHash });
      }
      if (receipt.status === 'unknown' || receipt.status === 'running') continue;
      await store.transaction(state => {
        const current = state.operations[operation.id]; if (!current || current.status !== 'running') return;
        if (receipt.appId !== operation.appId || receipt.releaseId !== operation.releaseId) { current.error = 'The trusted receipt did not identify the expected application release.'; return; }
        if (receipt.status === 'failed') { const message = 'The runtime confirmed this deployment failed without switching its active release.'; failDeployment(state, operation.id, message); notify(state, 'error', 'Deployment failed', message); return; }
        if (!receipt.healthy || !receipt.url || !/^https?:\/\//.test(receipt.url)) { current.error = 'The runtime receipt does not confirm a healthy release and URL.'; return; }
        const app = state.apps[operation.appId]; const release = state.releases[operation.releaseId]; if (!app || !release) return;
        if (app.activeReleaseId !== operation.baseReleaseId && app.activeReleaseId !== operation.releaseId) { current.error = 'A later release was recorded; manual reconciliation is required.'; return; }
        try { recordDatabaseSchema(state, app, release, receipt.schemaVersion, store.mode === 'mysql'); } catch (error) { current.error = error instanceof Error ? error.message : 'Database schema receipt is unavailable.'; return; }
        if (app.activeReleaseId && app.activeReleaseId !== release.id && state.releases[app.activeReleaseId]) state.releases[app.activeReleaseId]!.status = 'superseded';
        release.status = 'published'; release.publishedAt ??= new Date().toISOString(); app.activeReleaseId = release.id; app.url = receipt.url; app.status = 'published'; app.updatedAt = new Date().toISOString(); current.status = 'succeeded'; delete current.error;
        for (const job of Object.values(state.jobs)) if (job.result?.releaseId === release.id && ['awaiting_approval', 'deployment', 'observation'].includes(job.stage)) event(state, job, 'completed', 'Recovered the verified runtime receipt after an interruption. The release is healthy.', 'status', { releaseId: release.id, url: receipt.url });
        notify(state, 'info', 'Deployment recovered', `${app.name} ${release.version}: its trusted health-checked publication receipt was reconciled without repeating publication.`);
      });
    } catch (error) { await store.transaction(state => { const current = state.operations[operation.id]; if (current?.status === 'running') current.error = String(redact(error instanceof Error ? error.message : 'Operation receipt unavailable.')); }); }
  }
}
