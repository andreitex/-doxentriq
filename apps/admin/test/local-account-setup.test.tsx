import assert from 'node:assert/strict';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { AppAccessSnapshot } from '../../../packages/core/src/access';
import { FirstLocalAccountSetup, firstLocalAdministratorDraft, localInvitationBlockedReason } from '../src/views/local-account-setup';

const roleId = '33333333-3333-4333-8333-333333333333';
const snapshot: AppAccessSnapshot = {
  appId: '11111111-1111-4111-8111-111111111111', releaseId: '22222222-2222-4222-8222-222222222222', identityHash: 'a'.repeat(64), policyHash: 'b'.repeat(64), checkedAt: '2026-11-05T00:00:00Z',
  permissions: ['dms.read', 'dms.search', 'dms.write', 'dms.admin'],
  policy: { schemaVersion: 1, appId: '11111111-1111-4111-8111-111111111111', invitationsEnabled: false, requireTotp: true, roles: [], groupMappings: [] }
};

test('first-admin draft copies only verified app permissions without modifying the approved policy', () => {
  const before = structuredClone(snapshot), draft = firstLocalAdministratorDraft(snapshot, [], roleId);
  assert.deepEqual(draft, { invitationsEnabled: true, roles: [{ id: roleId, name: 'App administrators', permissions: snapshot.permissions }] });
  assert.deepEqual(snapshot, before);
  draft.roles[0]!.permissions.push('changed-draft');
  assert.deepEqual(snapshot, before);
});

test('first-admin helper refuses overwriting roles or drafting from absent or ambiguous permission evidence', () => {
  const role = { id: roleId, name: 'Readers', permissions: ['dms.read'] };
  assert.throws(() => firstLocalAdministratorDraft(snapshot, [role], roleId));
  assert.throws(() => firstLocalAdministratorDraft({ ...snapshot, policy: { ...snapshot.policy, roles: [role] } }, [], roleId));
  for (const permissions of [[], ['dms.read', 'dms.read'], ['*'], ['dms.read', '']]) assert.throws(() => firstLocalAdministratorDraft({ ...snapshot, permissions }, [], roleId));
  assert.throws(() => firstLocalAdministratorDraft({ ...snapshot, appId: 'other-app' }, [], roleId));
  assert.throws(() => firstLocalAdministratorDraft(snapshot, [], 'existing-role'));
});

test('first-admin setup discloses full app rights and keeps both approvals and app credentials separate', () => {
  let actions = 0;
  const html = renderToStaticMarkup(createElement(FirstLocalAccountSetup, { snapshot, roles: [], ready: true, busy: false, onDraft() { actions++; } }));
  for (const text of ['every verified permission', 'deleting app records', 'grants no platform or other-app access', 'Review access policy', 'review the invitation separately', 'Drafting changes this form only', 'Draft first app administrator', ...snapshot.permissions]) assert.ok(html.includes(text), text);
  assert.doesNotMatch(html, /type="password"|Approve &amp; apply|Approve &amp; issue/);
  assert.equal(actions, 0);
});

test('missing evidence and busy state disable drafting; an existing policy hides first-admin setup', () => {
  const props = { snapshot, roles: [], ready: true, busy: false, onDraft() {} };
  for (const overrides of [{ ready: false }, { busy: true }, { snapshot: { ...snapshot, permissions: [] } }]) {
    const html = renderToStaticMarkup(createElement(FirstLocalAccountSetup, { ...props, ...overrides }));
    assert.match(html, /disabled=""/);
  }
  const roles = firstLocalAdministratorDraft(snapshot, [], roleId).roles;
  const draft = renderToStaticMarkup(createElement(FirstLocalAccountSetup, { ...props, roles }));
  assert.match(draft, /No access has been granted/);
  assert.doesNotMatch(draft, /<button/);
  assert.equal(renderToStaticMarkup(createElement(FirstLocalAccountSetup, { ...props, snapshot: { ...snapshot, policy: { ...snapshot.policy, roles } } })), '');
});

test('invitations require confirmed enabled policy and approved roles rather than a first-admin form draft', () => {
  const draft = firstLocalAdministratorDraft(snapshot, [], roleId);
  assert.match(localInvitationBlockedReason(snapshot.policy, true, false, 'person@example.com', [roleId])!, /Draft roles cannot be used/);
  const approved = { ...snapshot.policy, ...draft };
  assert.equal(localInvitationBlockedReason(approved, true, false, 'person@example.com', [roleId]), undefined);
  assert.match(localInvitationBlockedReason({ ...approved, invitationsEnabled: false }, true, false, 'person@example.com', [roleId])!, /review and approve/);
  assert.match(localInvitationBlockedReason(approved, false, false, 'person@example.com', [roleId])!, /pending change/);
  assert.match(localInvitationBlockedReason(approved, true, true, 'person@example.com', [roleId])!, /current access action/);
  assert.match(localInvitationBlockedReason(approved, true, false, 'person@example.com', [])!, /at least one approved role/);
  assert.match(localInvitationBlockedReason(approved, true, false, 'person@example.com', ['foreign-role'])!, /roles have changed/);
  assert.match(localInvitationBlockedReason(approved, true, false, '', [roleId])!, /email address/);
});
