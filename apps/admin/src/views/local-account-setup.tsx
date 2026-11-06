import type { AppAccessPolicy, AppAccessRole, AppAccessSnapshot } from '../../../../packages/core/src/access';

export function firstLocalAdministratorDraft(snapshot: AppAccessSnapshot, currentDraft: AppAccessRole[], roleId: string): Pick<AppAccessPolicy, 'roles' | 'invitationsEnabled'> {
  if (snapshot.appId !== snapshot.policy.appId || snapshot.policy.requireTotp !== true || snapshot.policy.roles.length || currentDraft.length) throw new Error('First-administrator setup requires an unchanged application policy with no existing or drafted roles.');
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(roleId)) throw new Error('A new application role identifier is required.');
  if (!snapshot.permissions.length || snapshot.permissions.length > 100 || new Set(snapshot.permissions).size !== snapshot.permissions.length || snapshot.permissions.some(permission => !/^[a-z][a-z0-9_.:-]{1,79}$/.test(permission))) throw new Error('Verified application permissions are required before drafting administrator access.');
  return { roles: [{ id: roleId, name: 'App administrators', permissions: [...snapshot.permissions] }], invitationsEnabled: true };
}

export function localInvitationBlockedReason(policy: AppAccessPolicy, ready: boolean, busy: boolean, email: string, selectedRoles: string[]): string | undefined {
  if (busy) return 'Wait for the current access action to finish.';
  if (!ready) return 'Wait for the current access policy to load or its pending change to finish. Refresh if an error is shown.';
  if (!policy.roles.length) return 'First add an app role and approve it with Review access policy. Draft roles cannot be used for invitations yet.';
  if (!policy.invitationsEnabled) return 'Enable Allow new invitation-based local accounts above, then review and approve the access policy.';
  if (!selectedRoles.length) return 'Select at least one approved role for this person.';
  if (selectedRoles.some(id => !policy.roles.some(role => role.id === id))) return 'The selected roles have changed. Refresh and choose the person’s roles again.';
  if (!email.trim()) return 'Enter the person’s email address, then review their invitation.';
  return undefined;
}

export function FirstLocalAccountSetup({ snapshot, roles, ready, busy, onDraft }: { snapshot: AppAccessSnapshot; roles: AppAccessRole[]; ready: boolean; busy: boolean; onDraft: () => void }) {
  if (snapshot.policy.roles.length) return null;
  return <section className="settings-card"><h2>Set up your first app administrator</h2>
    <p>Your platform account manages Doxentriq. To sign in inside this app, create an app account with its own password and authenticator.</p>
    <ol><li>Draft an <strong>App administrators</strong> role, then use <strong>Review access policy</strong> below to approve its permissions and allow local invitations.</li><li>Under <strong>Invite a local app user</strong>, enter your email, select the approved role, and review the invitation separately.</li><li>Open the private invitation link, choose your app password, then enroll your authenticator at app sign-in.</li></ol>
    <p><strong>This role includes every verified permission in this app.</strong> It may allow changing or deleting app records where those permissions exist. It grants no platform or other-app access. Create narrower roles for other users.</p>
    {snapshot.permissions.length ? <details><summary>Review all {snapshot.permissions.length} app permissions</summary><ul>{snapshot.permissions.map(permission => <li key={permission}><code>{permission}</code></li>)}</ul></details> : <p>No verified app permissions are available. Ask IT to check the published app before continuing.</p>}
    {roles.length ? <p role="status">Your role draft is ready to edit below. No access has been granted. Review and approve the policy before inviting anyone.</p> : <button type="button" className="button button-secondary" disabled={!ready || busy || !snapshot.permissions.length} onClick={onDraft}>Draft first app administrator</button>}
    <p className="field-hint">Drafting changes this form only. Applying the policy and issuing an invitation each require your review and approval.</p>
  </section>;
}
