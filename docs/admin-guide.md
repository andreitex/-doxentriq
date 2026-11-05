# Managing applications with AutoSoft

This guide is for the person who decides what an application should do and who
may use it. IT installs and maintains the platform. You describe the work, try
the result and approve changes. You do not need to choose a programming language
or an AI model.

AutoSoft is currently pre-production software. Some integrations and recovery
tasks still need company or IT assistance. A successful test of one application
does not mean every requested application or integration is ready for use.

## Start here

Your IT contact supplies the administration address and the application portal
address. Sign into administration using the account they set up. The permanent
local owner uses a password and an authenticator; authorized organization
accounts can use configured SSO. Keep recovery codes somewhere safe.

The administration account manages development. Each application has its own
users and permissions. Being the platform owner does not automatically make you
a user inside every application.

Choose an application in the sidebar. Its main sections are:

| Section | What you do here |
|---|---|
| Conversation | Describe a new app or a change, answer questions and follow progress. |
| Releases | Try a preview, review changes, publish or request a compatible rollback. |
| Access | Define app roles, invite local users and manage supported access policies. |
| Connections | Register external services and use protected credential forms. |
| Security | Review reported findings and prepare an app fix request. |
| Telemetry | Check service health, progress and spending. |

## Create your first application

1. Describe the task in **Conversation**, or choose one of the examples. Include
   who will use it, what they should do and what a successful result looks like.
2. When asked, give the application a name. **Web application** is appropriate
   for a tool people use in their browser. Ask IT if you need an API, background
   worker or MCP server.
3. Send the request. Leave the request budget empty to use the configured
   default, or enter a smaller maximum if desired. The platform chooses models
   automatically and must stay within the available allowance.
4. Answer any business questions in **Help AutoSoft continue**, then select
   **Continue request**. For example, explain who approves a purchase or which
   document fields the team must search.
5. Follow the recorded progress. You can close the browser and return later;
   closing the page does not cancel the server request.

A useful first request is:

> Build a document app for our office. Staff should upload and find documents;
> managers should organize folders. Keep older document versions. Start with
> upload, folder browsing and search, and ask me what roles we need.

Use invented examples while developing. Do not paste business documents,
passwords, API keys, invitation links or authenticator secrets into chat.
Credentials belong in the protected **Connections** forms. Production business
records should be shared with model providers only after the required consent.

## Try and publish a version

When the conversation says **Ready for your review**, choose **Open preview**
or go to **Releases** and select **Preview**. Try the tasks described in the
request, including what different users should be allowed to do. Previews can
have separate accounts and data from the published application; ask IT for
help if preview access is not configured.

If the result needs work, describe the correction in Conversation. A new
candidate may replace the older preview. Always review the current candidate.

When satisfied:

1. Select **Review & publish** for the current candidate in Releases.
2. Read the change summary, checks and data impact. If a destructive change is
   reported, review exactly what will be removed and the recovery information.
3. Approve only if the result matches your request. Approval applies to that
   exact version and expires if it becomes stale.
4. Wait until **Live version** appears. **Open application** opens the published
   version, which you can share with its intended users.

“Request completed” alone is not proof that its version is currently live. Use
Releases to check the current version, especially when several changes have
been made. A blocked security check, unavailable evidence or unsafe data
change must be resolved before ordinary publication.

## Give people access

Open **Access** for the intended app. Define roles in everyday terms, such as
Reader, Editor or Manager, and select only the permissions each role needs.
Review and approve the policy before inviting users. Access changes use their
own approvals; rolling back application code does not undo them.

For an app with no roles yet, **Set up your first app administrator** walks you
through the initial account. **Draft first app administrator** fills the form
with an **App administrators** role containing every verified permission in
that app and enables local invitations in the draft. Read the displayed
permission list: this role may include changing or deleting app records.
Drafting grants no access. Edit the draft if needed, use **Review access policy**
to approve it, then issue the account invitation as a separate reviewed step.
The role grants no platform administration or access to other apps.

For local accounts, enable **Allow new invitation-based local accounts** in
the policy. Then use **Invite a local app user**, select the person's roles and
approve the invitation. The recipient chooses their own password through the
private link and completes authenticator enrollment on app sign-in.

Invitation links are displayed once, expire after 48 hours and are not emailed
automatically. Share them privately. They grant access to that app only. For a
worked example, see [Local DMS accounts](dms-local-accounts.md).

SSO setup and directory group connections can require IT and provider consent.
An SSO login by itself does not grant app permissions. Ask IT to help connect
the correct organization groups to the app roles.

## Help people find the app

After publication, the platform owner can open **Access → Show in the app
directory → Review listing**. Review the name and description, then confirm
the directory change. Anyone who can open the application portal can see those
details and the app link; protected apps still require sign-in and their
approved permissions. Listing an app does not create accounts or grant access.

Use **Review hiding** to remove an app from the directory. Its direct link
continues to work. A hidden app can still be shared privately with its intended
users. New protected apps stay hidden until explicitly listed.

## Connect existing tools and files

Describe the business purpose in Conversation: which system to use, which data
to read and which actions the app should perform. Add connection details and
credentials only through **Connections**.

Registering a connection records what you want; it does not by itself make the
integration operational. The UI identifies supported configuration and review
steps. Several connection types currently require company implementation and
review. A status of “registered” is not proof of a working connection.

Start with read-only access where possible. A request to write files, send
email, submit invoices or take payments needs the appropriate explicit scope.
If an external action has an uncertain outcome, ask IT to reconcile it before
trying again; repeating it can duplicate a payment, message or invoice.

## Improve an existing app

Select the app and describe the change in Conversation. Explain what should
stay the same, especially existing records, permissions and integrations.
Follow the same preview and publishing steps as the first version. One app's
active development request must finish or pause before another begins.

## Return to an earlier version

In Releases, find the earlier version and choose **Review rollback**. Review
its compatibility and the impact before approving. A code rollback normally
preserves current business data. Restoring a database backup is a separate
recovery operation and can discard records created after that backup.

If compatibility or security checks block rollback, contact IT. An emergency
rollback with known vulnerabilities has a separate local-owner approval and
must show the exact security risk. Do not repeatedly retry a failed publication
or rollback while its outcome is uncertain.

## When something needs attention

| What you see | What to do |
|---|---|
| A business question | Answer it in **Help AutoSoft continue**. |
| Spending limit reached | Review the proposed new maximum, or leave the request paused. Monthly allowance may also need attention. |
| Protected setup is needed | Ask IT to correct configuration using protected settings, then retry. |
| Model billing needs review | Ask IT to reconcile the uncertain charge; do not repeat the request. |
| Reconnecting | Allow the page to reload recorded progress. Reopen the conversation if necessary. |
| Verification unavailable or failed | Read the reported cause. Ask IT when it concerns scanning, infrastructure or recovery. |
| Approval expired or candidate changed | Open the current release and prepare a new review. |
| App sign-in fails | Check that the person has an account and approved roles for that app; platform-owner credentials are separate. |

When contacting IT, include the application name, request time, last visible
step and the error message. Keep credentials and sensitive business records
out of support messages. Diagnostic logs are intended to cover seven days, so
report issues promptly and let IT verify the installation's retention status.

Security results describe recorded checks, not a guarantee that nothing can
go wrong. Use **Prepare a fix request** for an application finding, then review
the resulting candidate before publication. VM maintenance and reboots belong
to the IT operator.
