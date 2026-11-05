# Application portal

`portal.html` is a separate Vite entry using only `src/portal/**`. The apps host must serve this entry, not the administration page. The portal does not call the platform session API, send cookies/authorization to its catalog request, present administration links, or create app grants.

The first version is a **public-only directory**. Nonpublic apps, preview candidates, drafts, workers, and unavailable/unverified publications are omitted. Private apps use their direct app URL and their own app-scoped PKCE/local sign-in. A signed-in directory of private apps is not implemented; adding it requires app-scoped authorization and a separately approved discovery policy, not a shared platform cookie.

The backend contract is anonymous `GET /api/public/v1/apps` on the exact configured apps origin, with `Cache-Control: no-store`. Cookies and bearer tokens must not create, refresh, or grant a platform session. Response:

```json
{"schemaVersion":1,"portalOrigin":"https://apps.example.com","listingPolicy":"public_only","apps":[{"id":"app-id","name":"Public application","description":"Public description","kind":"web","access":"public","url":"https://application.apps.example.com/"}]}
```

Each entry must come from the protected broker's current active deployment and independent verified source manifest with explicit `auth: public`, matched to the control service's successful published release, image digests, and artifact evidence. Construct its HTTPS app URL from the installation origin and validated slug. Do not accept user-supplied public flags, arbitrary URLs, a cookie from an admin subdomain, or a client-side role check as authorization. Return only the minimal public fields; names/descriptions of private apps must not appear even in error messages or totals.

The exact apps host must reject administration `/api/v1/**`, `/auth/**`, `/assets/**`, the admin HTML entry, and internal/metrics routes. It may serve the portal HTML, manifest-whitelisted `/portal-assets/**`, and public catalog. Unpublished wildcard app hosts remain unavailable. The Vite manifest at `dist/.vite/manifest.json` records the portal asset dependency tree; the backend maps only that entry's recursive files/imports/CSS from physical `dist/assets` into `/portal-assets`. Compiled portal HTML references this separate prefix and its relative JS imports stay within it. App APIs continue to enforce their own identity and permissions; a portal link grants no additional access.

The browser independently rejects nonpublic catalog entries, origin mismatches, duplicate entries, foreign/credential/query/preview destinations, and invalid metadata. Empty and unavailable states contain no sample apps. Its text is escaped and it loads no remote app images.

Local regression checks: `tsx --tsconfig apps/admin/tsconfig.json --test apps/admin/test/*.test.tsx` and `tsc -p apps/admin/test/tsconfig.json --noEmit`. Backend tests must prove that a forged/copied admin cookie on the apps host cannot expose administration or nonpublic catalog records. These render/contract tests are not evidence of a live SSO or VM deployment.
