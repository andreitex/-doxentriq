import type { Config } from './config.ts';

/** Known platform values only; never export this list or decrypt application secrets. */
export function knownProtectedValues(config: Config): string[] {
  const values: (string | undefined)[] = [config.openaiApiKey, config.anthropicApiKey, config.brokerToken, config.reportToken, config.metricsToken, config.oidcClientSecret, config.secretKey.toString('base64')];
  for (const configuredUrl of [config.mysqlUrl, config.rabbitUrl, config.redisUrl, config.brokerUrl, config.oidcIssuer, config.publicOrigin, config.appsOrigin]) {
    if (!configuredUrl) continue;
    try {
      const password = new URL(configuredUrl).password;
      if (password) { values.push(password); try { values.push(decodeURIComponent(password)); } catch { /* Retain the exact encoded spelling. */ } }
    } catch { /* This helper does not validate or access configured endpoints. */ }
  }
  // Keep the existing redactor's four-character minimum and exact literal matching.
  // Serialized legacy metadata or documentation may contain JSON-escaped spellings.
  return [...new Set(values.filter((value): value is string => typeof value === 'string' && value.length >= 4).flatMap(value => [value, JSON.stringify(value).slice(1, -1)]))];
}
