import { readFile } from 'node:fs/promises';

export async function loadTls(environment) {
  const certificate = environment.APP_TLS_CERT_FILE, key = environment.APP_TLS_KEY_FILE;
  if (Boolean(certificate) !== Boolean(key)) throw new Error('The app TLS certificate and private key must be supplied together.');
  if (certificate && key) return { cert: await readFile(certificate), key: await readFile(key), minVersion: 'TLSv1.2' };
  if (['test', 'local'].includes(environment.NODE_ENV)) return undefined;
  throw new Error('Production application traffic requires app-scoped TLS certificate and private-key files.');
}
