import assert from 'node:assert/strict';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { InvitationView, validInvitationAppUrl } from '../src/portal/Invitation';

test('app invitation form displays exact granted roles with protected password inputs and honest email/MFA status', () => {
  const html = renderToStaticMarkup(createElement(InvitationView, { busy: false, onSubmit: async () => {}, details: { app: { name: 'Documents', url: 'https://documents.apps.example.test/' }, email: 'reader@example.test', roles: [{ name: 'Readers', permissions: ['dms.read'] }], expiresAt: new Date(Date.now() + 3600000).toISOString(), status: 'pending', requireTotp: true, emailVerified: false } }));
  assert.match(html, /reader@example.test/); assert.match(html, /Readers/); assert.match(html, /dms.read/); assert.match(html, /type="password"/); assert.match(html, /minLength="12"/); assert.match(html, /does not verify this email/); assert.match(html, /authenticator MFA/i); assert.doesNotMatch(html, /\/api\/v1|\/auth\/login|Platform owner|name="role/);
});
test('pending invitation state hides the password composer and never reports account success', () => { const html = renderToStaticMarkup(createElement(InvitationView, { busy: false, pending: 'Original operation awaiting confirmation.', onSubmit: async () => {} })); assert.match(html, /Identity confirmation is pending/); assert.doesNotMatch(html, /type="password"|Account creation confirmed/); });
test('invitation redirects are generated for one direct app host and refuse previews, nested/foreign/credential links', () => {
  assert.equal(validInvitationAppUrl('https://documents.apps.example.test/', 'https://apps.example.test'), 'https://documents.apps.example.test/');
  for (const value of ['https://preview-documents.apps.example.test/', 'https://nested.documents.apps.example.test/', 'https://user:secret@documents.apps.example.test/', 'https://documents.apps.example.test/?token=x', 'https://documents.evil.test/', 'http://documents.apps.example.test/', 'javascript:alert(1)', 'https://documents.apps.example.test:444/']) assert.throws(() => validInvitationAppUrl(value, 'https://apps.example.test'));
});
