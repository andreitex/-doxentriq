import { z } from 'zod';

export const idSchema = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$/);
export const slugSchema = z.string().regex(/^[a-z][a-z0-9-]{1,47}$/).refine(s => !['admin','auth','api','registry','metrics','preview'].includes(s) && !s.startsWith('preview-'), 'Reserved hostname');
export const imageSchema = z.string().regex(/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/);
export const relativePathSchema = z.string().min(1).max(240).refine(p => !p.includes('\\') && !p.startsWith('/') && !p.includes('\0') && !p.split('/').some(s => s === '..' || s === '.' || s === ''), 'Path must stay inside the project');
export const stages = ['dependencies','build','application_tests','security','image_packaging','preview','migration_rehearsal','acceptance'] as const;
export const pipelineSchema = z.object({
  schemaVersion: z.literal(1),
  template: z.enum(['node-web','node-api','node-worker','node-mcp','python-api']),
  stages: z.array(z.object({ name: z.enum(stages), commands: z.array(z.string().min(1).max(4096)).max(16), timeoutSeconds: z.number().int().min(1).max(1800) }).strict()).length(stages.length)
}).strict().superRefine((p,ctx) => {
  for (const stage of stages) if (p.stages.filter(s=>s.name===stage).length!==1) ctx.addIssue({code:'custom',message:`Exactly one ${stage} stage is required`});
  for (const stage of p.stages) if (!['build','application_tests','acceptance'].includes(stage.name) && stage.commands.length) ctx.addIssue({code:'custom',message:`${stage.name} is executed by the platform and must have no custom commands`});
});
export const appManifestSchema = z.object({
  schemaVersion:z.literal(1), id:idSchema, slug:slugSchema, name:z.string().min(1).max(100),
  kind:z.enum(['web','api','worker','mcp']), template:z.enum(['node-web','node-api','node-worker','node-mcp','python-api']),
  auth:z.enum(['sso','local','public']), permissions:z.array(z.string().regex(/^[a-z][a-z0-9_.:-]{1,79}$/)).max(100),
  connections:z.array(idSchema).max(32),
  resources:z.object({cpu:z.number().min(.1).max(4),memoryMb:z.number().int().min(64).max(8192),pids:z.number().int().min(16).max(512)}).strict(),
  health:z.object({path:z.string().regex(/^\/[a-zA-Z0-9/_-]*$/),port:z.number().int().min(1024).max(65535)}).strict(),
  storage:z.array(z.object({name:idSchema,maxMb:z.number().int().positive().max(32768)}).strict()).max(1)
}).strict().superRefine((manifest,ctx) => {
  if ((manifest.kind === 'mcp' || manifest.template === 'node-mcp') && manifest.auth === 'public') {
    ctx.addIssue({code:'custom',path:['auth'],message:'Hosted MCP servers require authenticated access'});
  }
});
export const generationSchema = z.object({
  specification:z.object({title:z.string().min(1).max(200),summary:z.string().min(1).max(12000),acceptanceCriteria:z.array(z.string().min(1).max(1000)).min(1).max(32),questions:z.array(z.string().max(1000)).max(8)}).strict(),
  summary:z.string().min(1).max(4000), manifest:appManifestSchema, pipeline:pipelineSchema,
  files:z.array(z.object({path:relativePathSchema,content:z.string().max(500000)}).strict()).min(1).max(128),
  migrations:z.array(z.object({id:idSchema,sql:z.string().min(1).max(100000),destructive:z.boolean(),impact:z.string().max(4000)}).strict()).max(32)
}).strict();
export const connectionSchema=z.object({
  name:z.string().min(1).max(100),type:z.enum(['filesystem','samba','microsoft','google','email','stripe','efactura','rest','mcp']),
  endpoints:z.array(z.string().url()).max(32),roots:z.array(z.string().min(1).max(512)).max(16),
  capabilities:z.array(z.string().regex(/^[a-z][a-z0-9_.:-]{0,79}$/)).min(1).max(32),appIds:z.array(idSchema).max(64),
  credentials:z.string().max(65536).optional(),expiresAt:z.string().datetime().nullable().optional(),
  dossier:z.object({documentation:z.array(z.string().url()).max(32),provenance:z.string().max(2000),license:z.string().max(200),reviewStatus:z.enum(['pending','approved','rejected'])}).optional()
}).strict();
export type Generation = z.infer<typeof generationSchema>;
export type Pipeline = z.infer<typeof pipelineSchema>;
export type AppManifest = z.infer<typeof appManifestSchema>;
