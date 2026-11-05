import { createHash } from 'node:crypto';
import { pipelineSchema } from './schemas.js';

/** Version 1 binds input bytes using the existing runtime source-manifest digest. */
export const sourceBindingVersion = 1 as const;

function runtimeJson(value: unknown): string {
  // encoding/json.Marshal's default HTML and JavaScript line-separator escaping.
  return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

export function sourceFilesHash(files: readonly { path: string; content: string }[]): string {
  if (!Array.isArray(files) || files.length > 600) throw new Error('Source digest exceeds its file limit.');
  const paths = new Set<string>(); let bytes = 0;
  const records = files.map(file => {
    if (typeof file.path !== 'string' || typeof file.content !== 'string' || !file.path ||
        Buffer.from(file.path, 'utf8').toString('utf8') !== file.path || file.path.startsWith('/') ||
        file.path.includes('\\') || file.path.includes(':') || /[\x00-\x1f\x7f]/.test(file.path) ||
        file.path.split('/').some((part: string) => !part || part === '.' || part === '..') || paths.has(file.path)) {
      throw new Error('Source digest requires unique canonical UTF-8 project paths.');
    }
    paths.add(file.path); const content = Buffer.from(file.content, 'utf8'); bytes += content.length;
    if (bytes > 20 * 1024 ** 2) throw new Error('Source digest exceeds its byte limit.');
    return { path: file.path, hash: createHash('sha256').update(content).digest('hex') };
  });
  records.sort((a, b) => Buffer.compare(Buffer.from(a.path, 'utf8'), Buffer.from(b.path, 'utf8')));
  return createHash('sha256').update(runtimeJson(records), 'utf8').digest('hex');
}

export function pipelineDefinitionHash(value: unknown): string {
  const p = pipelineSchema.parse(value);
  // Go's JSON decoder replaces unpaired surrogates; reject that lossy wire form.
  for (const stage of p.stages) for (const command of stage.commands) {
    if (Buffer.from(command, 'utf8').toString('utf8') !== command || command.includes('\0')) {
      throw new Error('Pipeline commands require exact UTF-8 strings without NUL.');
    }
  }
  // Match the runtime's explicit Pipeline/Stage field order, independent of input JSON order.
  const normalized = { schemaVersion: p.schemaVersion, template: p.template,
    stages: p.stages.map(stage => ({ name: stage.name, commands: stage.commands, timeoutSeconds: stage.timeoutSeconds })) };
  return createHash('sha256').update(runtimeJson(normalized), 'utf8').digest('hex');
}
