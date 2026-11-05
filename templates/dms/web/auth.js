const key = 'autosoft-dms-pkce';
const encode = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export async function login(config) {
  const verifier = encode(crypto.getRandomValues(new Uint8Array(48))), state = encode(crypto.getRandomValues(new Uint8Array(32))), redirectUri = new URL('/auth/callback', location.origin).href;
  const challenge = encode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
  sessionStorage.setItem(key, JSON.stringify({ verifier, state, redirectUri, createdAt: Date.now() }));
  const url = new URL(config.authorizationEndpoint); url.search = new URLSearchParams({ client_id: config.clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'openid profile', state, code_challenge: challenge, code_challenge_method: 'S256' }).toString(); location.assign(url);
}
export async function callback(config) {
  const query = new URLSearchParams(location.search); if (!query.has('code') && !query.has('error')) return null;
  const callbackPath = location.pathname, stored = sessionStorage.getItem(key); sessionStorage.removeItem(key); history.replaceState(null, '', '/');
  if (!stored) throw new Error('The sign-in request is missing. Please sign in again.');
  let attempt; try { attempt = JSON.parse(stored); } catch { throw new Error('The sign-in request is invalid.'); }
  if (callbackPath !== '/auth/callback' || typeof attempt.verifier !== 'string' || !/^[A-Za-z0-9_-]{64}$/.test(attempt.verifier) || !Number.isFinite(attempt.createdAt) || attempt.createdAt > Date.now() + 5000 || attempt.state !== query.get('state') || Date.now() - attempt.createdAt > 600000 || attempt.redirectUri !== new URL('/auth/callback', location.origin).href) throw new Error('The sign-in response does not match this browser request.');
  if (query.has('error')) throw new Error('Sign-in was not completed. Please try again.');
  const response = await fetch(config.tokenEndpoint, { method: 'POST', credentials: 'omit', redirect: 'error', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: config.clientId, code: query.get('code'), redirect_uri: attempt.redirectUri, code_verifier: attempt.verifier }) });
  if (!response.ok) throw new Error('The sign-in code could not be exchanged. Please sign in again.');
  const body = await response.json(); if (typeof body.access_token !== 'string' || body.access_token.length > 16384) throw new Error('The identity provider did not return a usable access token.');
  return body.access_token;
}
// This is only for displaying controls. Every API permission is independently checked by the server.
export function displayIdentity(token, clientId) {
  try { const value = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), claims = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(value), ch => ch.charCodeAt(0)))); return { name: claims.name ?? claims.preferred_username ?? 'App account', roles: claims.resource_access?.[clientId]?.roles ?? [], expiresAt: Number(claims.exp) * 1000 }; } catch { return { name: 'App account', roles: [], expiresAt: 0 }; }
}
