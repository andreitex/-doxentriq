import assert from 'node:assert/strict';
import test, { after } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import Releases from '../src/views/Releases';
import { canRequestEmergencyRollback, EmergencyRiskAcknowledgment, EmergencyRollbackDisclosure, reviewEmergencyRollback } from '../src/components/EmergencyRollback';
import { releaseApprovalRequestBody, releaseDispatchRequest } from '../src/api';
import type { AppRecord, ApprovalRecord, Principal, ReleaseRecord, SecurityReport } from '../src/types';

const now = Date.parse('2026-10-10T12:00:00Z'), fresh = new Date(now - 60000).toISOString();
const owner: Principal = { id: 'local-owner', name: 'Owner', roles: ['platform-owner'], localOwner: true, mfa: true };
const app: AppRecord = { id: 'app-one', slug: 'documents', name: 'Documents', description: '', kind: 'web', status: 'published', activeReleaseId: 'release-new', databaseSchemaVersion: 1, url: null, previewUrl: null, createdAt: fresh, updatedAt: fresh };
const release: ReleaseRecord = { id: 'release-previous', appId: app.id, version: '1.0.0', summary: 'Previous document system', artifactHash: 'a'.repeat(64), commit: 'c'.repeat(40), images: ['registry/app@sha256:' + 'd'.repeat(64)], schemaVersion: 1, compatibleSchemaMin: 1, compatibleSchemaMax: 1, baseReleaseId: null, status: 'superseded', evidence: { status: 'passed', checkedAt: '2026-10-01T00:00:00Z', feedUpdatedAt: '2026-10-01T00:00:00Z', findings: [], checks: ['dependencies', 'build', 'application_tests', 'security', 'image_packaging', 'preview', 'migration_rehearsal', 'acceptance'].map(name => ({ name, passed: true, detail: 'Verified' })) }, migrations: [], createdAt: fresh, publishedAt: fresh };
const approval: ApprovalRecord = { id: 'emergency-approval', appId: app.id, releaseId: release.id, action: 'emergency_rollback', artifactHash: release.artifactHash, impact: ['Roll back Documents to version 1.0.0.', 'Known MEDIUM vulnerability: CVE-exact (library 1.2.3).', 'Known HIGH vulnerability: CVE-other (dependency 2.0.0).'], expiresAt: new Date(now + 30 * 60000).toISOString(), approvedBy: null, approvedAt: null, consumedAt: null, checkpointId: null };
const report: SecurityReport = { findings: [], unclassifiedFindings: [], scans: [{ releaseId: release.id, appId: app.id, status: 'failed', checkedAt: fresh, feedUpdatedAt: fresh, stale: false, coverage: [{ name: 'image', status: 'passed', detail: 'Exact image independently scanned' }, { name: 'source', status: 'passed', detail: 'Exact source scanned' }] }], vm: { status: 'unavailable' } };
const review = (overrides: Partial<Parameters<typeof reviewEmergencyRollback>[0]> = {}) => reviewEmergencyRollback({ principal: owner, app, release, approval, security: report, now, ...overrides });
const previousWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
Object.defineProperty(globalThis, 'window', { configurable: true, value: { location: { origin: 'https://admin.example.com' } } });
after(() => { if (previousWindow) Object.defineProperty(globalThis, 'window', previousWindow); else Reflect.deleteProperty(globalThis, 'window'); });

test('only an MFA-authenticated permanent owner receives an emergency action for a historical release', () => {
  const render = (principal: Principal, candidate = release) => renderToStaticMarkup(createElement(Releases, { app, releases: [candidate], principal, loading: false, onRetry() {}, onReview() {} }));
  assert.match(render(owner), /Review emergency rollback/);
  for (const principal of [{ ...owner, localOwner: false }, { ...owner, mfa: false }, { ...owner, roles: ['platform-admin'] }]) {
    assert.equal(canRequestEmergencyRollback(principal), false);
    assert.doesNotMatch(render(principal), /Review emergency rollback/);
  }
  assert.doesNotMatch(render(owner, { ...release, id: app.activeReleaseId! }), /Review emergency rollback/);
  assert.doesNotMatch(render(owner, { ...release, status: 'ready' }), /Review emergency rollback/);
  assert.doesNotMatch(render(owner, { ...release, evidence: { ...release.evidence, status: 'unavailable' } }), /Review emergency rollback/);
});

test('emergency disclosure uses exact approved findings and fresh release-specific coverage', () => {
  const result = review();
  assert.equal(result.allowed, true, result.reasons.join(' '));
  assert.deepEqual(result.findings, [{ severity: 'MEDIUM', detail: 'CVE-exact (library 1.2.3).' }, { severity: 'HIGH', detail: 'CVE-other (dependency 2.0.0).' }]);
  const html = renderToStaticMarkup(createElement(EmergencyRollbackDisclosure, { review: result }));
  for (const text of ['CVE-exact', 'library 1.2.3', 'CVE-other', 'Known security risk', 'Changed findings require a new owner approval', 'unknown severity', 'access policy are preserved']) assert.ok(html.includes(text), `Missing review detail: ${text}`);
  // Findings for another historical release cannot be substituted from the aggregate app overview.
  assert.deepEqual(review({ security: { ...report, findings: [{ id: 'CVE-foreign-release', severity: 'CRITICAL', appId: app.id, package: 'other', installedVersion: '9', description: 'Different release', source: 'scanner' }] } }).findings, result.findings);
});

test('emergency approval cannot override unknown severity, absent coverage, stale feeds or changed action/artifact', () => {
  const cases: Partial<Parameters<typeof reviewEmergencyRollback>[0]>[] = [
    { principal: { ...owner, mfa: false } }, { approval: { ...approval, action: 'rollback' } }, { approval: { ...approval, artifactHash: 'b'.repeat(64) } },
    { approval: { ...approval, appId: 'other-app' } }, { approval: { ...approval, releaseId: 'other-release' } },
    { approval: { ...approval, expiresAt: new Date(now).toISOString() } }, { approval: { ...approval, consumedAt: fresh } },
    { approval: { ...approval, impact: [...approval.impact, 'Known UNKNOWN vulnerability: CVE-no-severity (library 1.2.3).'] } },
    { approval: { ...approval, impact: ['Roll back without supplied findings.'] } },
    { security: { ...report, scans: [{ ...report.scans[0]!, coverage: [] }] } },
    { security: { ...report, scans: [{ ...report.scans[0]!, status: 'unavailable' }] } },
    { security: { ...report, scans: [{ ...report.scans[0]!, stale: true }] } },
    { security: { ...report, scans: [{ ...report.scans[0]!, coverage: [{ name: 'image', status: 'unavailable', detail: 'Feed unavailable' }] }] } },
    { security: { ...report, scans: [{ ...report.scans[0]!, coverage: [{ name: 'image', status: 'passed', detail: '' }, { name: 'image', status: 'passed', detail: '' }] }] } },
    { security: { ...report, scans: [{ ...report.scans[0]!, feedUpdatedAt: '2026-10-08T00:00:00Z' }] } },
    { security: { ...report, scans: [{ ...report.scans[0]!, checkedAt: new Date(now + 120000).toISOString() }] } },
    { security: { ...report, scans: [{ ...report.scans[0]!, appId: 'other-app' }] } },
    { security: { ...report, scans: [] } }, // Original evidence is old; its scan cannot stand in for a current daily scan.
    { security: { ...report, scans: undefined } as unknown as SecurityReport },
    { release: { ...release, status: 'ready' } }, { app: { ...app, activeReleaseId: release.id } }
  ];
  for (const input of cases) { const result = review(input); assert.equal(result.allowed, false, JSON.stringify(input)); assert.ok(result.reasons.length); }
});

test('owner risk acknowledgement starts unchecked and cannot be checked when evidence is blocked', () => {
  const html = renderToStaticMarkup(createElement(EmergencyRiskAcknowledgment, { checked: false, disabled: true, onChange() {} }));
  assert.match(html, /type="checkbox"/); assert.match(html, /disabled=""/); assert.doesNotMatch(html, /checked=""/);
  assert.match(html, /I accept the exact known security findings/);
});

test('emergency requests retain the distinct approval action and dispatch only its exact rollback tuple', () => {
  assert.deepEqual(releaseApprovalRequestBody('emergency_rollback'), { action: 'emergency_rollback' });
  assert.throws(() => releaseApprovalRequestBody('emergency_rollback', true), /only with publication/);
  assert.deepEqual(releaseDispatchRequest(app, release, approval, 'emergency_rollback'), { path: '/apps/app-one/rollback', body: { releaseId: release.id, approvalId: approval.id } });
  for (const changed of [{ ...approval, action: 'rollback' as const }, { ...approval, artifactHash: 'b'.repeat(64) }, { ...approval, releaseId: 'other-release' }, { ...approval, appId: 'other-app' }]) assert.throws(() => releaseDispatchRequest(app, release, changed, 'emergency_rollback'), /exact release approval changed/);
  assert.throws(() => releaseDispatchRequest({ ...app, id: 'other-app' }, release, approval, 'emergency_rollback'), /exact release approval changed/);
});
