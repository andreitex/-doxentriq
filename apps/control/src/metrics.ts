import { createHash, timingSafeEqual } from 'node:crypto';
import { Registry, collectDefaultMetrics, Gauge, Counter, Histogram } from 'prom-client';
import type { FastifyInstance } from 'fastify';
import type { Store } from './store.ts';
import type { Config } from './config.ts';
export async function installMetrics(server: FastifyInstance, store: Store, config: Config) {
  const registry = new Registry(); collectDefaultMetrics({ register: registry, prefix: 'autosoft_' });
  const requests = new Counter({ name: 'autosoft_http_requests_total', help: 'Completed control API requests', labelNames: ['method', 'route', 'status'], registers: [registry] });
  const latency = new Histogram({ name: 'autosoft_http_request_duration_seconds', help: 'Control request duration', labelNames: ['method', 'route'], buckets: [.01, .05, .1, .5, 1, 5, 15], registers: [registry] });
  const applications = new Gauge({ name: 'autosoft_applications', help: 'Recorded applications', labelNames: ['status'], registers: [registry] });
  const jobs = new Gauge({ name: 'autosoft_jobs', help: 'Durable workflow jobs', labelNames: ['stage'], registers: [registry] });
  const reservations = new Gauge({ name: 'autosoft_model_cost_usd', help: 'Monthly model costs and pending reservations', labelNames: ['kind'], registers: [registry] });
  server.addHook('onResponse', async (request, reply) => { const route = request.routeOptions.url ?? 'unmatched'; requests.inc({ method: request.method, route, status: reply.statusCode }); latency.observe({ method: request.method, route }, reply.elapsedTime / 1000); });
  server.get('/metrics', async (request, reply) => {
    if (config.authMode !== 'development') {
      if (!config.metricsToken || config.metricsToken.length < 32) return reply.status(503).send({ error: { message: 'Metrics authentication is not configured.' } });
      const supplied = request.headers.authorization?.replace(/^Bearer /, '') ?? ''; const a = createHash('sha256').update(supplied).digest(), b = createHash('sha256').update(config.metricsToken).digest();
      if (!timingSafeEqual(a, b)) return reply.status(401).send({ error: { message: 'Authenticated metrics scraping is required.' } });
    } else if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(request.ip)) return reply.status(403).send({ error: { message: 'Development metrics require loopback.' } });
    const state = await store.read(state => state); applications.reset(); jobs.reset();
    for (const app of Object.values(state.apps)) applications.inc({ status: app.status });
    for (const job of Object.values(state.jobs)) jobs.inc({ stage: job.stage });
    const month = new Date().toISOString().slice(0, 7); const costs = Object.values(state.reservations).filter(item => item.month === month);
    reservations.set({ kind: 'spent' }, costs.reduce((sum, item) => sum + (item.actualUsd ?? 0), 0)); reservations.set({ kind: 'reserved' }, costs.reduce((sum, item) => sum + (item.actualUsd === null ? item.amountUsd : 0), 0));
    reply.type(registry.contentType); return registry.metrics();
  });
}
