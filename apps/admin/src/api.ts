import type { AppRecord, ApprovalRecord, ReleaseAction, ReleaseRecord } from './types';

let csrfToken = '';

export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); }
}

export function setCsrfToken(token: string) { csrfToken = token; }

export function releaseApprovalRequestBody(action: ReleaseAction, automaticRecovery = false) {
  if (automaticRecovery && action !== 'publish') throw new Error('Automatic recovery is available only with publication.');
  return { action, ...(automaticRecovery ? { automaticRecovery: true } : {}) };
}

export function releaseDispatchRequest(app: AppRecord, release: ReleaseRecord, approval: ApprovalRecord, action: ReleaseAction) {
  if (release.appId !== app.id || approval.appId !== app.id || approval.releaseId !== release.id || approval.action !== action || approval.artifactHash !== release.artifactHash) throw new Error('The exact release approval changed. Prepare a new review.');
  return action === 'publish'
    ? { path: `/releases/${encodeURIComponent(release.id)}/publish`, body: { approvalId: approval.id } }
    : { path: `/apps/${encodeURIComponent(app.id)}/rollback`, body: { releaseId: release.id, approvalId: approval.id } };
}

export async function api<T>(path: string, options: { method?: string; body?: unknown; signal?: AbortSignal } = {}): Promise<T> {
  const method = options.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && method !== 'HEAD') {
    if (!csrfToken) throw new ApiError('Your session is not ready. Refresh the page and try again.', 403);
    headers['x-csrf-token'] = csrfToken;
  }
  const response = await fetch(`/api/v1${path}`, {
    method, headers, credentials: 'include', signal: options.signal,
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {})
  });
  const payload: unknown = response.status === 204 ? undefined : await response.json().catch(() => undefined);
  if (!response.ok) {
    const value = payload as { error?: string | { message?: string }; message?: string } | undefined;
    const message = typeof value?.error === 'string' ? value.error : value?.error?.message ?? value?.message;
    if (response.status === 401) window.dispatchEvent(new Event('autosoft:session-expired'));
    throw new ApiError(message ?? `The request could not be completed (${response.status}).`, response.status);
  }
  return payload as T;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong. Please try again.';
}

export function safeUrl(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value, window.location.origin);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : undefined;
  } catch { return undefined; }
}
