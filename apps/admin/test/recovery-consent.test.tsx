import assert from 'node:assert/strict';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { RecoveryDisclosure, RecoveryOptIn, recoveryApprovalBody, type RecoveryGrantDraft } from '../src/components/RecoveryConsent';

const artifactHash = 'a'.repeat(64);
const authorizationHash = 'b'.repeat(64);
const grant: RecoveryGrantDraft = { id: 'recovery-one', appId: 'app-one', failedReleaseId: 'release-next', failedArtifactHash: artifactHash, failedImages: ['registry/app@sha256:' + 'c'.repeat(64)], targetReleaseId: 'release-previous', targetArtifactHash: 'd'.repeat(64), targetImages: ['registry/app@sha256:' + 'e'.repeat(64)], currentSchemaVersion: 2, approvedBy: null, approvedAt: null, expiresAt: '2026-11-09T00:00:00Z', authorizationHash, publicationApprovalId: 'approval-one', publicationOperationId: null };

test('automatic recovery is an unchecked explicit opt-in with concrete duration and data limits', () => {
  const html = renderToStaticMarkup(createElement(RecoveryOptIn, { checked: false, disabled: false, onChange() {} }));
  assert.match(html, /type="checkbox"/);
  assert.doesNotMatch(html, /checked=""/);
  assert.match(html, /Optional permission for 30 days/);
  assert.match(html, /Business data is preserved/);
});

test('automatic recovery disclosure binds an exact prior version, schema, images, authorization and expiry', () => {
  const html = renderToStaticMarkup(createElement(RecoveryDisclosure, { grant, targetVersion: '1.2.3' }));
  for (const value of ['1.2.3', grant.targetReleaseId, grant.targetArtifactHash, grant.authorizationHash, grant.targetImages[0]!, 'Reviewed database schema', 'Recovery permission expires', 'Unknown findings', 'Business data is kept']) assert.ok(html.includes(value), `Missing recovery review field: ${value}`);
  assert.match(html, /does not authorize a database restore, identity-policy change, or another release/);
});

test('approval sends both exact reviewed hashes only when recovery was explicitly requested', () => {
  assert.deepEqual(recoveryApprovalBody(artifactHash, false), { artifactHash });
  assert.deepEqual(recoveryApprovalBody(artifactHash, true, grant), { artifactHash, authorizationHash });
  assert.throws(() => recoveryApprovalBody(artifactHash, true), /authorization is missing/);
  assert.throws(() => recoveryApprovalBody(artifactHash, false, grant), /unrequested recovery grant/);
  assert.throws(() => recoveryApprovalBody('f'.repeat(64), true, grant), /authorization is missing or changed/);
  assert.throws(() => recoveryApprovalBody(artifactHash, true, { ...grant, authorizationHash: 'unreviewed' }), /authorization is missing or changed/);
});
