# Local DMS accounts

DMS accounts are independent of platform administration. A local account uses
its own email/sign-in name, password and authenticator in the DMS application
realm. Microsoft and Google are not required. An organization sign-in provider
can also be offered when configured. Platform-owner credentials and permissions
do not automatically grant document access.

For the first account, sign into platform administration with owner MFA, select
the published DMS application, and open **Access**:

1. Add an **Application administrator** role. Select `dms.read`, `dms.search`,
   `dms.write` and `dms.admin`.
2. Enable **Allow new invitation-based local accounts**, then **Review access
   policy** and approve the exact permissions.
3. Under **Invite a local app user**, enter the intended email/sign-in name,
   select that role, review the invitation and approve issuing its link.
4. Open the private invitation link. Its recipient chooses a new password in
   the protected form, then follows app sign-in to enroll an authenticator.
   Keep the link, password and authenticator secrets out of chat.
5. Use **Sign in to documents** and the app-local credentials. Organization SSO
   is optional. Use narrower roles when inviting document readers or editors.

Invitations are shown once and expire after 48 hours. The platform does not
send their links by email automatically. A privately delivered invitation is
not proof of email ownership: the account's email remains unverified, and app
permissions come from separately approved app roles. Public self-registration
remains disabled. App-local invitations do not require an SMTP service.

Previews and published applications use separate identity realms and data.
A published application's local account does not automatically belong to its
preview. Changes to access policy are independent of code releases and rollback.

The DMS browser uses authorization-code PKCE S256 and the exact registered
`/auth/callback` address. That route serves the application shell, validates
the saved state and verifier, exchanges the code at the configured identity
service and clears the code from the browser URL. An app login correction must
pass the release pipeline and exact release approval before changing a
published application.
