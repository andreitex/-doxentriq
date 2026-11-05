import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { hashArtifact } from '../../../packages/core/src/security.ts';
import type { AppAccessSnapshot } from '../../../packages/core/src/access.ts';
import type { DirectoryActivation, DirectoryApproval, DirectoryScope } from '../../../packages/core/src/directory.ts';
import type { ConnectionRecord, Principal } from '../src/types';
import DirectoryAuthorization, { DirectoryOutcomeUncertain, DirectoryReviewContent, DirectoryStateContent, activateDirectoryReview, approvedDirectoryGroups, buildDirectoryProposal, canManageDirectory, directoryDisableImpact, disableDirectoryActivation, inspectDirectoryAttention, unresolvedDirectoryReview, validateDirectoryReview, validateDirectoryState, type DirectoryReviewContext } from '../src/components/DirectoryAuthorization';

const at = Date.parse('2026-10-10T17:00:00Z'), iso = (delta: number) => new Date(at + delta).toISOString();
const appId = '11111111-1111-4111-8111-111111111111', releaseId = '22222222-2222-4222-8222-222222222222', connectionId = '33333333-3333-4333-8333-333333333333', tenantId = '44444444-4444-4444-8444-444444444444', groupId = '55555555-5555-4555-8555-555555555555', roleId = '66666666-6666-4666-8666-666666666666', approvalId = '77777777-7777-4777-8777-777777777777', activationId = '88888888-8888-4888-8888-888888888888';
const owner: Principal = { id: 'permanent-owner', name: 'Owner', localOwner: true, mfa: true, roles: ['platform_owner'] };
const connection: ConnectionRecord = { id: connectionId, name: 'Dedicated directory reads', type: 'microsoft', endpoints: ['https://graph.microsoft.com/v1.0'], roots: [tenantId], capabilities: ['directory.groups.read'], appIds: [appId], expiresAt: iso(30 * 86400000), status: 'configured', secretRef: 'connection:protected-reference', dossier: { documentation: [], provenance: 'Metadata only.', license: 'unreviewed', reviewStatus: 'pending' }, createdAt: iso(0) };
const policy: AppAccessSnapshot['policy'] = { schemaVersion: 1, appId, invitationsEnabled: false, requireTotp: true, roles: [{ id: roleId, name: 'Document readers', permissions: ['documents.read'] }], groupMappings: [{ provider: 'microsoft', tenantId, groupId, connectionId, roleIds: [roleId], status: 'pending_validation' }] };
const snapshot: AppAccessSnapshot = { appId, releaseId, identityHash: 'a'.repeat(64), policyHash: hashArtifact(policy), permissions: ['documents.read'], policy, checkedAt: iso(0) };
const proposal = buildDirectoryProposal(snapshot, connection, { groupIds: [groupId], workspaceDomain: '', evidenceTtlSeconds: 60, accessExpiresAt: iso(86400000) }, at);
const context: DirectoryReviewContext = { snapshot, connection, proposal };
const scope: DirectoryScope = { schemaVersion: 1, appId, ...proposal, policyHash: snapshot.policyHash, identityBindingHash: 'b'.repeat(64), registryHash: hashArtifact(connection), credentialRef: connection.secretRef!, credentialCiphertextSha256: 'c'.repeat(64) };
const artifactHash = hashArtifact({ action: 'activate_directory', scope });
const approval: DirectoryApproval = { id: approvalId, action: 'activate_directory', appId, artifactHash, scope, impact: ['Read complete membership only for the reviewed app and immutable groups.', 'Do not grant platform roles or create permanent group roles.'], expiresAt: iso(300000), approvedAt: null, approvedBy: null, consumedAt: null };
const activation: DirectoryActivation = { id: activationId, appId, approvalId, artifactHash, scope, checkedAt: iso(0), activatedAt: iso(0), disabledAt: null };
const stateValue = (available = true) => ({ policyHash: snapshot.policyHash, approvals: [{ ...approval, approvedAt: iso(0), approvedBy: owner.id, consumedAt: iso(0) }], activations: [{ ...activation, available, detail: 'Current protected configuration. Membership is checked per request.' }] });

test('directory group selection uses only exact saved policy and configured app-authorized directory reads', () => {
  assert.deepEqual(approvedDirectoryGroups(snapshot, connection), [{ groupId, roleNames: ['Document readers'], permissions: ['documents.read'] }]);
  for (const change of [{ status: 'needs_credentials' as const }, { secretRef: null }, { appIds: [] }, { roots: ['other-tenant'] }, { capabilities: ['directory.groups.read','files.read'] }, { endpoints: ['https://graph.microsoft.com/v1.0/users'] }, { type: 'rest' as const }]) assert.deepEqual(approvedDirectoryGroups(snapshot, { ...connection, ...change }), []);
  for (const change of [{ provider: 'google' as const }, { tenantId: releaseId }, { connectionId: releaseId }]) assert.deepEqual(approvedDirectoryGroups({ ...snapshot, policy: { ...policy, groupMappings: [{ ...policy.groupMappings[0]!, ...change }] } }, connection), []);
  assert.throws(() => approvedDirectoryGroups({ ...snapshot, policy: { ...policy, roles: [{ ...policy.roles[0]!, permissions: ['platform.admin'] }] } }, connection));
  assert.throws(() => approvedDirectoryGroups({ ...snapshot, policy: { ...policy, groupMappings: [policy.groupMappings[0]!, policy.groupMappings[0]!] } }, connection));
});

test('directory proposal fixes provider identity and rejects arbitrary groups, permissions, evidence lifetime and expiry', () => {
  assert.deepEqual(proposal, { connectionId, provider: 'microsoft', tenantId, workspaceDomain: null, groupIds: [groupId], evidenceTtlSeconds: 60, accessExpiresAt: iso(86400000) });
  assert.doesNotMatch(JSON.stringify(proposal), /credential|secret|endpoints|registryHash|clientSecret|permissions/);
  const input = { groupIds: [groupId], workspaceDomain: '', evidenceTtlSeconds: 60, accessExpiresAt: iso(86400000) };
  for (const change of [{ groupIds: [releaseId] }, { groupIds: [groupId,groupId] }, { groupIds: [] }, { evidenceTtlSeconds: 0 }, { evidenceTtlSeconds: 301 }, { evidenceTtlSeconds: 1.5 }, { accessExpiresAt: iso(-1) }, { accessExpiresAt: iso(91 * 86400000) }, { accessExpiresAt: 'malformed' }]) assert.throws(() => buildDirectoryProposal(snapshot, connection, { ...input, ...change }, at));
  assert.throws(() => buildDirectoryProposal(snapshot, { ...connection, expiresAt: iso(1000) }, input, at));
  const google = { ...connection, type: 'google' as const, endpoints: ['https://admin.googleapis.com/admin/directory/v1'], roots: ['Ccustomer123'] }, googleSnapshot = { ...snapshot, policy: { ...policy, groupMappings: [{ ...policy.groupMappings[0]!, provider: 'google' as const, tenantId: 'Ccustomer123', groupId: 'immutable-google-group' }] } };
  assert.equal(buildDirectoryProposal(googleSnapshot, google, { ...input, groupIds: ['immutable-google-group'], workspaceDomain: ' Customer.Example ' }, at).workspaceDomain, 'customer.example');
  assert.throws(() => buildDirectoryProposal(googleSnapshot, google, { ...input, groupIds: ['immutable-google-group'], workspaceDomain: 'admin@customer.example' }, at));
});

test('directory review recomputes exact server action hash and current policy/registry scope', async () => {
  assert.equal((await validateDirectoryReview(approval, context, at)).artifactHash, artifactHash);
  for (const change of [{ artifactHash: 'f'.repeat(64) }, { action: 'approve_directory' }, { appId: releaseId }, { expiresAt: iso(-1) }, { expiresAt: iso(300001) }, { consumedAt: iso(0) }, { scope: { ...scope, groupIds: [releaseId] } }, { scope: { ...scope, credentialCiphertextSha256: 'd'.repeat(64) } }]) await assert.rejects(validateDirectoryReview({ ...approval, ...change }, context, at));
  for (const altered of [{ ...context, connection: { ...connection, name: 'Changed registry' } }, { ...context, connection: { ...connection, secretRef: 'replacement-ref' } }, { ...context, proposal: { ...proposal, accessExpiresAt: iso(2 * 86400000) } }, { ...context, snapshot: { ...snapshot, policy: { ...policy, invitationsEnabled: true } } }]) await assert.rejects(validateDirectoryReview(approval, altered, at));
});

test('directory state retains historical evidence but fails closed on stale, foreign, malformed and changed scope', async () => {
  const current = await validateDirectoryState(stateValue(), snapshot, [connection], at); assert.equal(current.activations[0]!.available, true);
  for (const value of [{ ...stateValue(), policyHash: 'f'.repeat(64) }, { ...stateValue(), approvals: [approval,approval] }, { ...stateValue(), activations: [stateValue().activations[0],stateValue().activations[0]] }, { ...stateValue(), activations: [{ ...activation, appId: releaseId, available: true, detail: 'Other app' }] }, { ...stateValue(), activations: [{ ...activation, available: 'yes', detail: 'Malformed' }] }]) await assert.rejects(validateDirectoryState(value, snapshot, [connection], at));
  assert.equal((await validateDirectoryState(stateValue(), snapshot, [], at)).activations[0]!.available, false);
  assert.equal((await validateDirectoryState(stateValue(), snapshot, [{ ...connection, status: 'disabled' }], at)).activations[0]!.available, false);
  assert.equal((await validateDirectoryState(stateValue(), snapshot, [{ ...connection, name: 'Registry changed' }], at)).activations[0]!.available, false);
  assert.equal((await validateDirectoryState(stateValue(), snapshot, [connection], at + 86400001)).activations[0]!.available, false);
  assert.equal((await validateDirectoryState(stateValue(false), snapshot, [connection], at)).activations[0]!.available, false);
});

test('directory activation requires permanent owner MFA and sends one exact approve followed by one activate', async () => {
  assert.equal(canManageDirectory(owner), true);
  for (const principal of [{ ...owner, localOwner: false }, { ...owner, mfa: false }]) { let count = 0; await assert.rejects(activateDirectoryReview(context, approval, principal, async () => { count++; return {}; }, () => at)); assert.equal(count, 0); }
  const calls: { path: string; body: unknown }[] = [];
  const result = await activateDirectoryReview(context, approval, owner, async (path, options) => { calls.push({ path, body: options.body }); return calls.length === 1 ? { approval: { ...approval, approvedAt: iso(0), approvedBy: owner.id } } : { activation }; }, () => at);
  assert.equal(result.id, activationId); assert.deepEqual(calls, [{ path: `/directory/approvals/${approvalId}/approve`, body: { artifactHash } }, { path: `/apps/${appId}/access/directory/activate`, body: { approvalId } }]);
});

test('changed approval, expiration or uncertain provider outcomes never automatically repeat activation', async () => {
  for (const change of [{ id: activationId }, { expiresAt: iso(299999) }, { approvedBy: 'sso-admin' }, { approvedAt: iso(1) }, { artifactHash: 'f'.repeat(64) }]) { let count = 0; await assert.rejects(activateDirectoryReview(context, approval, owner, async () => { count++; return { approval: { ...approval, approvedAt: iso(0), approvedBy: owner.id, ...change } }; }, () => at), DirectoryOutcomeUncertain); assert.equal(count, 1); }
  for (const outcome of ['provider-outage','lost-response','foreign-receipt']) { let count = 0; await assert.rejects(activateDirectoryReview(context, approval, owner, async () => { count++; if (count === 1) return { approval: { ...approval, approvedAt: iso(0), approvedBy: owner.id } }; if (outcome !== 'foreign-receipt') throw new Error(outcome); return { activation: { ...activation, approvalId: activationId } }; }, () => at), DirectoryOutcomeUncertain); assert.equal(count, 2); }
  let count = 0, clock = at; await assert.rejects(activateDirectoryReview(context, approval, owner, async () => { count++; clock = at + 300001; return { approval: { ...approval, approvedAt: iso(0), approvedBy: owner.id } }; }, () => clock)); assert.equal(count, 1);
});

test('uncertain activation requires exact retained receipt or a post-expiry read before any fresh review', async () => {
  const empty = await validateDirectoryState({ policyHash: snapshot.policyHash, approvals: [approval], activations: [] }, snapshot, [connection], at);
  const attention = { action: 'activation' as const, approval };
  assert.equal(inspectDirectoryAttention(empty, attention, at, at).mayPrepare, false);
  assert.equal(inspectDirectoryAttention(empty, attention, at, at + 300001).mayPrepare, false);
  assert.equal(inspectDirectoryAttention(empty, attention, at + 300001, at + 300002).mayPrepare, true);
  const consumed = { ...empty, approvals: [{ ...approval, consumedAt: iso(0) }] }; assert.equal(inspectDirectoryAttention(consumed, attention, at + 300001, at + 300002).mayPrepare, false);
  const retained = await validateDirectoryState({ ...stateValue(), approvals: [{ ...approval, approvedAt: iso(0), approvedBy: owner.id, consumedAt: iso(0) }] }, snapshot, [connection], at); assert.equal(inspectDirectoryAttention(retained, attention, at, at).confirmed, true);
  assert.equal(inspectDirectoryAttention({ ...empty, approvals: [{ ...approval, artifactHash: 'f'.repeat(64) }] }, attention, at + 300001, at + 300002).confirmed, false);
});

test('directory disable is one explicit exact-app mutation with preserved data and read-only uncertainty inspection', async () => {
  const calls: { path: string; body: unknown }[] = []; await disableDirectoryActivation(activation, appId, owner, async (path, options) => { calls.push({ path, body: options.body }); return { disabled: true }; }); assert.deepEqual(calls, [{ path: `/apps/${appId}/access/directory/${activationId}/disable`, body: {} }]);
  let count = 0; await assert.rejects(disableDirectoryActivation(activation, releaseId, owner, async () => { count++; return {}; })); assert.equal(count, 0);
  await assert.rejects(disableDirectoryActivation(activation, appId, { ...owner, mfa: false }, async () => { count++; return {}; })); assert.equal(count, 0);
  await assert.rejects(disableDirectoryActivation(activation, appId, owner, async () => { count++; throw new Error('Lost response'); })); assert.equal(count, 1);
  const state = await validateDirectoryState(stateValue(), snapshot, [connection], at); const attention = { action: 'disable' as const, activation }; assert.equal(inspectDirectoryAttention(state, attention, at, at).confirmed, false); assert.equal(inspectDirectoryAttention({ ...state, activations: [{ ...state.activations[0]!, disabledAt: iso(0), available: false }] }, attention, at, at).confirmed, true);
  assert.match(directoryDisableImpact(activation).join(' '), /does not delete accounts, local role assignments, documents or business data/); assert.match(directoryDisableImpact(activation).join(' '), /Code rollback does not restore/);
});

test('directory review and status show exact scope and honest eligibility without exposing credential bindings', async () => {
  const html = renderToStaticMarkup(createElement(DirectoryReviewContent, { approval, context })); assert.match(html, new RegExp(groupId)); assert.match(html, /Document readers/); assert.match(html, /documents.read/); assert.match(html, new RegExp(artifactHash)); assert.match(html, /does not establish ongoing tenant health/); assert.doesNotMatch(html, /connection:protected-reference|cccccccccccccccccccc|clientSecret|privateKey/);
  const state = await validateDirectoryState(stateValue(), snapshot, [connection], at), eligible = renderToStaticMarkup(createElement(DirectoryStateContent, { state })); assert.match(eligible, /Eligible · per-request checks required/); assert.match(eligible, /not proof of live tenant health/); assert.doesNotMatch(eligible, />Healthy<|tenant is healthy/);
  assert.match(renderToStaticMarkup(createElement(DirectoryStateContent, { state: { ...state, activations: [{ ...state.activations[0]!, disabledAt: iso(0), available: false }] } })), /Inactive · disabled/);
  assert.match(renderToStaticMarkup(createElement(DirectoryStateContent, { state: { ...state, activations: [{ ...state.activations[0]!, available: false }] } })), /Unavailable · expired or changed/);
});

test('SSO administrators and owners without MFA receive no directory mutation controls', () => {
  for (const principal of [{ ...owner, localOwner: false }, { ...owner, mfa: false }]) { const html = renderToStaticMarkup(createElement(DirectoryAuthorization, { snapshot, connections: [connection], principal, policyReady: true, onPolicyRefresh() {} })); assert.match(html, /Only the permanent local platform owner with MFA/); assert.doesNotMatch(html, /Prepare exact directory review|Approve &amp; activate|Review disable of/); assert.match(html, /disabled=""[^>]*>[^]*?Inspect directory state/); }
});


test('a reload or competing review cannot prepare another scope until an exact post-expiry read', async () => {
  const state = await validateDirectoryState({ policyHash: snapshot.policyHash, approvals: [approval], activations: [] }, snapshot, [connection], at);
  assert.equal(unresolvedDirectoryReview(state, at)?.id, approvalId);
  assert.equal(unresolvedDirectoryReview(state, at + 299999)?.id, approvalId);
  assert.equal(unresolvedDirectoryReview(state, at + 300001), undefined);
  assert.equal(unresolvedDirectoryReview(state, at, approvalId), undefined);
  assert.equal(unresolvedDirectoryReview({ ...state, approvals: [{ ...approval, approvedAt: iso(0), approvedBy: owner.id }] }, at)?.id, approvalId);
  assert.equal(unresolvedDirectoryReview({ ...state, approvals: [{ ...approval, consumedAt: iso(0) }] }, at), undefined);
});


test('closing the protected view after approval prevents a later activation dispatch', async () => {
  const controller = new AbortController(); let count = 0;
  await assert.rejects(activateDirectoryReview(context, approval, owner, async (_path, options) => { count++; assert.equal(options.signal, controller.signal); controller.abort(); return { approval: { ...approval, approvedAt: iso(0), approvedBy: owner.id } }; }, () => at, controller.signal), DirectoryOutcomeUncertain);
  assert.equal(count, 1);
  await assert.rejects(activateDirectoryReview(context, approval, owner, async () => { count++; return {}; }, () => at, controller.signal)); assert.equal(count, 1);
});


test('an activation requires its exact retained consumed approval and cannot duplicate an approval lifecycle', async () => {
  for (const change of [{ approvals: [] }, { approvals: [approval] }, { approvals: [{ ...approval, approvedAt: null, approvedBy: owner.id, consumedAt: iso(0) }] }, { approvals: [{ ...approval, approvedAt: iso(0), approvedBy: owner.id, consumedAt: iso(1) }] }, { activations: [stateValue().activations[0], { ...stateValue().activations[0], id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }] }]) await assert.rejects(validateDirectoryState({ ...stateValue(), ...change }, snapshot, [connection], at));
});
