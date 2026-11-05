import { createPrivateKey, sign } from 'node:crypto';
import { z } from 'zod';
import type { DirectoryScope, DirectorySubject } from '../../../packages/core/src/directory.ts';
import type { DirectoryHttp } from './directory-http.ts';
import { directoryUrl } from './directory-http.ts';

const uuid = z.string().uuid(), immutable = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/), userId = z.string().regex(/^[0-9]{1,128}$/);
export const googleDirectoryScopes = ['https://www.googleapis.com/auth/admin.directory.customer.readonly', 'https://www.googleapis.com/auth/admin.directory.user.readonly', 'https://www.googleapis.com/auth/admin.directory.group.readonly', 'https://www.googleapis.com/auth/admin.directory.group.member.readonly'] as const;
export const microsoftDirectoryScopes = ['Organization.Read.All', 'User.Read.All'] as const;
const microsoftCredentials = z.object({ tenantId: uuid, clientId: uuid, clientSecret: z.string().min(1).max(4096), consentedScopes: z.array(z.enum(microsoftDirectoryScopes)).length(2) }).strict();
const googleCredentials = z.object({ clientEmail: z.string().regex(/^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com$/).max(254), privateKey: z.string().min(100).max(16000), delegatedSubject: z.string().email().max(254), consentedScopes: z.array(z.enum(googleDirectoryScopes)).length(4) }).strict();
export function validateDirectoryCredentials(scope: DirectoryScope, input: unknown): void {
  if (scope.provider === 'microsoft') {
    const credentials = microsoftCredentials.parse(input);
    if (credentials.tenantId !== scope.tenantId || new Set(credentials.consentedScopes).size !== 2) throw new Error('Directory credential tenant and exact consented read scopes must match the protected scope.');
  } else {
    const credentials = googleCredentials.parse(input);
    if (new Set(credentials.consentedScopes).size !== 4 || !/^C[A-Za-z0-9_-]{1,127}$/.test(scope.tenantId) || !scope.workspaceDomain || credentials.delegatedSubject.split('@')[1]?.toLowerCase() !== scope.workspaceDomain) throw new Error('Workspace directory requires explicit customer ID, hosted domain and delegated administrator consent.');
    const key = createPrivateKey(credentials.privateKey);
    if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error('Google directory signing credentials require an RSA private key of at least 2048 bits.');
  }
}
async function accessToken(http: DirectoryHttp, scope: DirectoryScope, input: unknown): Promise<string> {
  validateDirectoryCredentials(scope, input);
  let result: unknown;
  if (scope.provider === 'microsoft') {
    const c = microsoftCredentials.parse(input);
    result = await http({ method: 'POST', url: `https://login.microsoftonline.com/${scope.tenantId}/oauth2/v2.0/token`, form: new URLSearchParams({ grant_type: 'client_credentials', client_id: c.clientId, client_secret: c.clientSecret, scope: 'https://graph.microsoft.com/.default' }) });
  } else {
    const c = googleCredentials.parse(input), now = Math.floor(Date.now() / 1000);
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsigned = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({ iss: c.clientEmail, sub: c.delegatedSubject, aud: 'https://oauth2.googleapis.com/token', scope: googleDirectoryScopes.join(' '), iat: now, exp: now + 600 })}`;
    const assertion = unsigned + '.' + sign('RSA-SHA256', Buffer.from(unsigned), createPrivateKey(c.privateKey)).toString('base64url');
    result = await http({ method: 'POST', url: 'https://oauth2.googleapis.com/token', form: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }) });
  }
  const token = z.object({ access_token: z.string().regex(/^[\x21-\x7e]{1,16384}$/), token_type: z.string().refine(value => value.toLowerCase() === 'bearer'), expires_in: z.number().int().min(30).max(86400) }).parse(result);
  return token.access_token;
}
async function microsoftOrganization(http: DirectoryHttp, bearer: string, scope: DirectoryScope): Promise<void> {
  const value = z.object({ value: z.array(z.object({ id: uuid })).length(1), '@odata.nextLink': z.string().optional() }).parse(await http({ method: 'GET', url: 'https://graph.microsoft.com/v1.0/organization?$select=id', bearer }));
  if (value.value[0]!.id !== scope.tenantId || value['@odata.nextLink']) throw new Error('The directory token belongs to another or ambiguous tenant.');
}
async function googleGroups(http: DirectoryHttp, bearer: string, scope: DirectoryScope): Promise<Map<string, string>> {
  const customer = z.object({ id: immutable }).parse(await http({ method: 'GET', url: `https://admin.googleapis.com/admin/directory/v1/customers/${scope.tenantId}`, bearer }));
  if (customer.id !== scope.tenantId) throw new Error('The Workspace directory belongs to another customer.');
  const groups = new Map<string, string>(), tokens = new Set<string>(); let next: string | undefined;
  for (let page = 0; page < 25; page++) {
    const query = new URLSearchParams({ customer: scope.tenantId, maxResults: '200', fields: 'groups(id,email),nextPageToken' }); if (next) query.set('pageToken', next);
    const result = z.object({ groups: z.array(z.object({ id: immutable, email: z.string().email().max(254) })).max(200).optional(), nextPageToken: z.string().min(1).max(8000).optional() }).parse(await http({ method: 'GET', url: `https://admin.googleapis.com/admin/directory/v1/groups?${query}`, bearer }));
    for (const group of result.groups ?? []) { if (groups.has(group.id) || groups.size >= 5000) throw new Error('Directory group inventory is duplicated or exceeds its bound.'); groups.set(group.id, group.email.split('@')[1]!.toLowerCase()); }
    next = result.nextPageToken; if (!next) return groups;
    if (tokens.has(next)) throw new Error('Directory pagination repeated.'); tokens.add(next);
  }
  throw new Error('Workspace group inventory is incomplete; no permission can be granted.');
}
/** This is read-only protocol verification, not a claim about SDK or upstream write privileges. */
export async function verifyDirectoryConnection(http: DirectoryHttp, scope: DirectoryScope, credentials: unknown): Promise<void> {
  const bearer = await accessToken(http, scope, credentials);
  if (scope.provider === 'microsoft') await microsoftOrganization(http, bearer, scope);
  else { const groups = await googleGroups(http, bearer, scope); if (scope.groupIds.some(id => groups.get(id) !== scope.workspaceDomain)) throw new Error('Configured immutable groups must belong to this Workspace customer and hosted domain; cross-domain nested groups are unsupported.'); }
}
export function microsoftNextLink(value: string, user: string): string {
  const url = directoryUrl(value, 'GET');
  if (url.origin !== 'https://graph.microsoft.com' || url.pathname !== `/v1.0/users/${user}/transitiveMemberOf` || [...url.searchParams.keys()].some(key => !['$select', '$top', '$skiptoken', '$skip', '$count'].includes(key)) || [...url.searchParams.keys()].some((key, index, values) => values.indexOf(key) !== index)) throw new Error('Directory pagination escaped the exact immutable user endpoint.');
  return url.href;
}
export async function resolveDirectoryMembership(http: DirectoryHttp, scope: DirectoryScope, subject: DirectorySubject, credentials: unknown): Promise<string[]> {
  if (subject.provider !== scope.provider || subject.tenantId !== scope.tenantId || subject.workspaceDomain !== scope.workspaceDomain || subject.appId !== scope.appId || subject.policyHash !== scope.policyHash) throw new Error('Immutable upstream identity does not match the exact approved directory scope.');
  const bearer = await accessToken(http, scope, credentials);
  if (scope.provider === 'microsoft') {
    uuid.parse(subject.upstreamUserId); await microsoftOrganization(http, bearer, scope);
    const user = z.object({ id: uuid, accountEnabled: z.literal(true) }).parse(await http({ method: 'GET', url: `https://graph.microsoft.com/v1.0/users/${subject.upstreamUserId}?$select=id,accountEnabled`, bearer }));
    if (user.id !== subject.upstreamUserId) throw new Error('The immutable directory user changed.');
    const groups = new Set<string>(), pages = new Set<string>(); let url = `https://graph.microsoft.com/v1.0/users/${user.id}/transitiveMemberOf?$select=id&$top=999`;
    // Signed token group lists and arbitrary overage URLs are never trusted.
    // Resolve the entire paginated directory membership before any positive decision.
    for (let page = 0; page < 25; page++) {
      if (pages.has(url)) throw new Error('Directory pagination repeated.'); pages.add(url);
      const result = z.object({ value: z.array(z.object({ id: uuid, '@odata.type': z.enum(['#microsoft.graph.group', '#microsoft.graph.directoryRole', '#microsoft.graph.administrativeUnit']) })).max(999), '@odata.nextLink': z.string().optional() }).parse(await http({ method: 'GET', url, bearer }));
      for (const item of result.value) if (item['@odata.type'] === '#microsoft.graph.group') { if (groups.has(item.id) || groups.size >= 5000) throw new Error('Directory membership is duplicated or exceeds its bound.'); groups.add(item.id); }
      if (!result['@odata.nextLink']) return scope.groupIds.filter(id => groups.has(id));
      url = microsoftNextLink(result['@odata.nextLink'], user.id);
    }
    throw new Error('Directory membership is incomplete; no permission can be granted.');
  }
  userId.parse(subject.upstreamUserId);
  const user = z.object({ id: userId, customerId: immutable, suspended: z.boolean(), archived: z.boolean().optional(), primaryEmail: z.string().email().max(254) }).parse(await http({ method: 'GET', url: `https://admin.googleapis.com/admin/directory/v1/users/${subject.upstreamUserId}?fields=id,customerId,suspended,archived,primaryEmail`, bearer }));
  if (user.id !== subject.upstreamUserId || user.customerId !== scope.tenantId || user.suspended || user.archived || user.primaryEmail.split('@')[1]!.toLowerCase() !== scope.workspaceDomain) throw new Error('The Workspace immutable user is inactive or belongs to another customer/domain.');
  const groups = await googleGroups(http, bearer, scope), memberships: string[] = [];
  for (const id of scope.groupIds) {
    if (groups.get(id) !== scope.workspaceDomain) throw new Error('The approved group is absent or cross-domain nested membership is unsupported.');
    const result = z.object({ isMember: z.boolean() }).strict().parse(await http({ method: 'GET', url: `https://admin.googleapis.com/admin/directory/v1/groups/${id}/hasMember/${user.id}`, bearer })); if (result.isMember) memberships.push(id);
  }
  return memberships;
}
