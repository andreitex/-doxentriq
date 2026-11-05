import assert from 'node:assert/strict';
import test, { after } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import Chat from '../src/views/Chat';
import Telemetry from '../src/views/Telemetry';
import Security from '../src/views/Security';
import type { AppRecord, JobRecord, SecurityReport, Telemetry as TelemetryData } from '../src/types';

const job: JobRecord = { id: 'job-one', appId: 'app-one', request: 'Build document management', stage: 'needs_attention', baseReleaseId: null, budgetUsd: 5, costUsd: 0, attempts: 1, createdAt: '2026-10-10T00:00:00Z', updatedAt: '2026-10-10T00:00:00Z', result: { attentionKind: 'setup', recoveryHint: 'Contact the company operator to configure model credentials through protected setup.' } };
const previousWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
Object.defineProperty(globalThis, 'window', { configurable: true, value: { location: { origin: 'https://admin.example.com' } } });
after(() => { if (previousWindow) Object.defineProperty(globalThis, 'window', previousWindow); else Reflect.deleteProperty(globalThis, 'window'); });
const app: AppRecord = { id: 'app-one', name: 'Documents', slug: 'documents', description: '', kind: 'web', createdAt: job.createdAt, updatedAt: job.updatedAt, activeReleaseId: null, url: null, previewReleaseId: 'release-current', previewUrl: 'https://preview-documents.example.com', status: 'draft' };
function renderChat(record: JobRecord, application?: AppRecord) {
  return renderToStaticMarkup(createElement(Chat, { app: application, jobs: [record], jobsLoading: false, job: record, activeRequest: record, events: [], loading: false, stream: 'idle', draft: '', setDraft() {}, onSend: async () => {}, onResume: async () => true, onCancel: async () => {}, onSelectJob() {}, onViewReleases() {}, onIncreaseBudget() {}, busy: false }));
}

test('protected setup failures offer retry without a credential-inviting answer box', () => {
  const html = renderChat(job);
  assert.match(html, /Protected platform setup is needed/);
  assert.match(html, /Retry request/);
  assert.match(html, /company operator/);
  assert.doesNotMatch(html, /id="resume-answer"/);
  assert.doesNotMatch(html, /provide the requested information/);
});

test('genuine business clarification keeps its answer box and credential boundary', () => {
  const html = renderChat({ ...job, stage: 'clarification', result: { attentionKind: 'clarification' } });
  assert.match(html, /id="resume-answer"/);
  assert.match(html, /Enter integration credentials only in protected connection settings/);
});

test('uncertain model billing shows review guidance without retry or spending-increase controls', () => {
  const html = renderChat({ ...job, result: { modelBillingHold: true, budgetBlocked: true, attentionKind: 'runtime_unavailable', recoveryHint: 'The company operator must reconcile the interrupted provider outcome. Held costs remain reserved.' } });
  assert.match(html, /reconcile the interrupted provider outcome/); assert.match(html, /Held costs remain reserved/);
  assert.doesNotMatch(html, /Retry request|Review spending increase|id="resume-answer"/);
});

test('chat preview links bind to the current candidate and suppress replaced candidates', () => {
  const older = renderChat({ ...job, stage: 'awaiting_approval', result: { releaseId: 'release-older' } }, app);
  assert.doesNotMatch(older, /preview-launch/);
  const current = renderChat({ ...job, stage: 'awaiting_approval', result: { releaseId: 'release-current' } }, app);
  assert.match(current, /preview-launch\?releaseId=release-current/);
});

test('completed requests claim a live version only when their release is currently active', () => {
  const completed = { ...job, stage: 'completed' as const, result: { releaseId: 'release-current' } };
  for (const application of [undefined, app, { ...app, activeReleaseId: 'release-newer' }]) {
    const html = renderChat(completed, application);
    assert.match(html, /Check the current version in Releases/);
    assert.doesNotMatch(html, /This version is live/);
  }
  const published = renderChat(completed, { ...app, activeReleaseId: 'release-current' });
  assert.match(published, /This version is live/);
  assert.match(published, /does not automatically grant access inside the app/);
});

test('review guidance keeps candidate creation separate from publication and a running preview', () => {
  const review = renderChat({ ...job, stage: 'awaiting_approval', result: { releaseId: 'release-current' } }, app);
  assert.match(review, /Your next step: try the preview/);
  assert.match(review, /Publishing requires your approval/);
  assert.doesNotMatch(review, /This version is live/);
  const preparing = renderChat({ ...job, stage: 'preview' }, app);
  assert.match(preparing, /Preparing your preview/);
  assert.doesNotMatch(preparing, /Your next step: try the preview/);
});

test('host telemetry renders actual measurements and distinguishes the deployment broker', () => {
  const data: TelemetryData = { mode: 'production', uptimeSeconds: 400, counts: { apps: 0, jobs: 0, runningJobs: 0, publishedApps: 0 }, costUsd: 0, broker: { available: false, detail: 'Deployment broker unavailable' }, services: [{ name: 'vm', status: 'healthy', cpuCount: 4, loadAverage: [0.12, 0.2, 0.31], memoryTotalBytes: 8 * 1024 ** 3, memoryAvailableBytes: 2 * 1024 ** 3, diskTotalBytes: 100 * 1024 ** 3, diskFreeBytes: 75 * 1024 ** 3, uptimeSeconds: 86400, encryptedDataMounted: true }] };
  const html = renderToStaticMarkup(createElement(Telemetry, { data, loading: false, onRetry() {}, onIncreaseBudget() {} }));
  assert.match(html, /75%/);
  assert.match(html, /25%/);
  assert.match(html, /0.12/);
  assert.match(html, /Encrypted data mounted/);
  assert.match(html, /Build and deployment service/);
  assert.doesNotMatch(html, /Message broker connection/);
  const absent = renderToStaticMarkup(createElement(Telemetry, { data: { ...data, services: [] }, loading: false, onRetry() {}, onIncreaseBudget() {} }));
  assert.match(absent, /Not reported/);
  assert.doesNotMatch(absent, /Encrypted data mounted/);
});

test('unclassified findings remain distinct from confirmed medium and higher findings', () => {
  const report: SecurityReport = { findings: [], unclassifiedFindings: [{ id: 'CVE-unclassified', severity: 'UNKNOWN', package: 'dependency', installedVersion: '1.0.0', description: 'Severity has not been classified', source: 'scanner', appId: 'app-one' }], scans: [], vm: { status: 'unavailable' } };
  const html = renderToStaticMarkup(createElement(Security, { apps: [app], report, loading: false, onRetry() {}, onFix() {} }));
  assert.match(html, /Severity needs review/);
  assert.match(html, /Severity unclassified/);
  assert.match(html, /0 medium and above/);
});

test('application observation shows unavailable health and exact pending recovery without claiming success', () => {
  const data: TelemetryData = { mode: 'production', uptimeSeconds: 10, counts: { apps: 1, jobs: 0, runningJobs: 0, publishedApps: 1 }, costUsd: 0, broker: { available: true, detail: 'Connected' }, services: [], observations: [{ appId: app.id, releaseId: 'observed-release', publicationOperationId: 'publication-operation', checkedAt: '2026-10-10T00:00:00Z', status: 'unavailable', detail: 'Verified runtime health evidence unavailable', consecutiveFailures: ['check-one', 'check-two', 'check-three'], recoveryStatus: 'pending', recoveryReason: 'Exact recovery operation outcome is pending', recoveryOperationId: 'recovery-operation' }] };
  const html = renderToStaticMarkup(createElement(Telemetry, { data, apps: [app], loading: false, onRetry() {}, onIncreaseBudget() {} }));
  for (const value of ['Documents', 'observed-release', 'publication-operation', 'recovery-operation', 'Consecutive failed checks', 'Latest health check', 'Recovery is pending', 'Unavailable']) assert.ok(html.includes(value), `Missing actual observation field: ${value}`);
  assert.doesNotMatch(html, />Healthy<|Recovery completed/);
});

test('shared budget displays conservative unknown billing and hides increases beyond the company allowance', () => {
  const budget = { currency: 'USD' as const, month: '2026-10', requestLimitUsd: 1, monthlyLimitUsd: 30, spentUsd: 2.895128, reservedUsd: 0, remainingUsd: 27.104872, workflowSpentUsd: 0, externalConfirmedUsd: .895128, externalConservativeUsd: 2, authorityId: 'shared', authorityLimitUsd: 30, authorityExpired: false };
  const html = renderToStaticMarkup(createElement(Telemetry, { budget, loading: false, onRetry() {}, onIncreaseBudget() {} }));
  assert.match(html, /Conservative debit: invoice unknown/); assert.match(html, /Company tests: confirmed/);
  assert.match(html, /share one allowance/); assert.match(html, /Accounted for/);
  assert.doesNotMatch(html, /increase-monthly-budget/);
  const expired = renderToStaticMarkup(createElement(Telemetry, { budget: { ...budget, authorityExpired: true, remainingUsd: 0 }, loading: false, onRetry() {}, onIncreaseBudget() {} }));
  assert.match(expired, /allowance has expired/); assert.doesNotMatch(expired, /increase-monthly-budget/);
});
