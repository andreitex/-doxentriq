import { z } from 'zod';
import { idSchema } from './schemas.js';

// This is the entire model-visible connection contract. Protected endpoints,
// credential versions, ACL artifacts and runtime receipts deliberately have no fields.
export const generationConnectionInventorySchema = z.object({
  schemaVersion: z.literal(1),
  connections: z.array(z.object({
    id: idSchema, name: z.string().min(1).max(120),
    type: z.enum(['filesystem','samba','microsoft','google','email','stripe','efactura','rest','mcp']),
    appIds: z.array(idSchema).length(1),
    roots: z.array(z.string().min(1).max(240).refine(value => !/[\\/:%<>|?*"\x00-\x1f\x7f]/.test(value) && !['.', '..'].includes(value), 'Only logical aliases enter model context')).max(20),
    capabilities: z.array(z.enum(['files.list','files.read'])).max(2),
    expiresAt: z.string().datetime().nullable(),
    status: z.enum(['usable','unavailable']),
    reason: z.enum(['disabled','expired','protected_setup_unavailable','not_configured','scope_changed','runtime_unavailable','unsupported']).nullable()
  }).strict()).max(64)
}).strict().superRefine((inventory, ctx) => {
  const ids = new Set<string>();
  for (const [index, item] of inventory.connections.entries()) {
    if (ids.has(item.id)) ctx.addIssue({ code: 'custom', path: ['connections', index, 'id'], message: 'Duplicate connection identity' });
    ids.add(item.id);
    if (item.status === 'usable' && (!['samba','filesystem'].includes(item.type) || item.reason !== null || item.roots.length !== 1 || item.capabilities.length !== 2 || new Set(item.capabilities).size !== 2 || !item.expiresAt)) ctx.addIssue({ code: 'custom', path: ['connections', index], message: 'Usable connections need an exact qualified read-only file adapter scope and expiry' });
    if (item.status === 'unavailable' && item.reason === null) ctx.addIssue({ code: 'custom', path: ['connections', index, 'reason'], message: 'Unavailable connections require a reason' });
  }
});
export type GenerationConnectionInventory = z.infer<typeof generationConnectionInventorySchema>;

export function validatedGenerationConnections(value: unknown, appId: string, now = Date.now()): GenerationConnectionInventory {
  const inventory = generationConnectionInventorySchema.parse(value ?? { schemaVersion: 1, connections: [] });
  for (const connection of inventory.connections) {
    if (connection.appIds[0] !== appId) throw new Error('Connection inventory belongs to another application');
    if (connection.status === 'usable' && Date.parse(connection.expiresAt!) <= now) throw new Error('A model-visible connection scope has expired');
  }
  return inventory;
}
