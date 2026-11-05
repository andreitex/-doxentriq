import { z } from 'zod';
import { redact } from '../../../packages/core/src/index.ts';

const text = z.string().max(5000);
const metric = z.union([z.string().max(200), z.number().finite().nonnegative()]);
const bytes = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const finite = z.number().finite().nonnegative();
const service = z.object({ name: z.string().min(1).max(300), status: z.string().min(1).max(100), detail: text.optional(), cpuPercent: metric.optional(), memoryUsage: metric.optional(), memoryPercent: metric.optional(), networkIO: metric.optional(), blockIO: metric.optional(), pids: metric.optional(), cpuCount: z.number().int().positive().optional(), loadAverage: z.tuple([finite, finite, finite]).optional(), memoryTotalBytes: bytes.optional(), memoryAvailableBytes: bytes.optional(), diskTotalBytes: bytes.optional(), diskFreeBytes: bytes.optional(), uptimeSeconds: finite.optional(), encryptedDataMounted: z.boolean().optional() }).strip();
const schema = z.object({ services: z.array(service).max(500), broker: z.object({ available: z.boolean(), detail: text }).strip() }).strip();
export function validatedTelemetry(value: unknown) { return redact(schema.parse(value)); }
