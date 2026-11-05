import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import { z } from 'zod';
import { hashArtifact } from './security.js';

export type PreviousSourceFile = { path: string; content: string };
export const previousSourceByteLimit = 48000;
export type SourceSelectionInput = {
  appId: string; jobId: string; attempt: number; baseReleaseId: string | null;
  request: string; answer?: string; acceptanceCriteria?: string[]; files?: PreviousSourceFile[];
};
const entry = z.object({ path: z.string().min(1).max(240), bytes: z.number().int().nonnegative(), sha256: z.string().regex(/^[a-f0-9]{64}$/), reason: z.enum(['requested', 'contract', 'relevant', 'neighbor', 'general', 'limit', 'excluded', 'requested_over_limit']) }).strict();
const selectionSchema = z.object({
  schemaVersion: z.literal(1), appId: z.string().min(1), jobId: z.string().min(1), attempt: z.number().int().nonnegative(), baseReleaseId: z.string().nullable(),
  inputHash: z.string().regex(/^[a-f0-9]{64}$/), snapshotHash: z.string().regex(/^[a-f0-9]{64}$/), acceptanceCriteria: z.array(z.string().max(1000)).max(32), maxBytes: z.literal(previousSourceByteLimit), selectedBytes: z.number().int().min(0).max(previousSourceByteLimit),
  truncated: z.boolean(), requestedPaths: z.array(z.string().max(240)).max(64), selected: z.array(entry).max(500), omitted: z.array(entry).max(500), questions: z.array(z.string().max(1000)).max(8)
}).strict();
export type PreviousSourceSelection = z.infer<typeof selectionSchema>;
const sha = (content: string) => createHash('sha256').update(content, 'utf8').digest('hex');
const excluded = /(?:^|\/)(?:package-lock\.json|[^/]+\.lock|dist|node_modules|artifacts|\.venv|venv|__pycache__|\.cache)(?:\/|$)/;
const contractFiles = new Set(['package.json', 'pyproject.toml', 'app.manifest.json', 'pipeline.json', 'migrations.json']);
const allowedPath = (path: string) => path.length <= 240 && !/^[\/]|[\\:\x00-\x1f\x7f]/.test(path) && !path.split('/').some(part => !part || part === '.' || part === '..' || /^\.(?:git|env|npmrc|codex|agents)(?:$|\.)/i.test(part));
const ignoredWords = new Set('the and for with that this from into should would could will must have has are was were when then every existing current unchanged keep preserve change changes add optional request application app code file files use using only allow return include includes ensure need want please user users test tests acceptance criteria'.split(' '));
/** Preservation constraints still reach the model and input hash, but do not
 * request source rewrites. Unknown or mixed instructions retain the old pause.
 * Excluded files never enter editable context, including through this path. */
function technicalTargetText(text: string): string {
  const mutation = /\b(?:change|changes|modify|modified|update|rewrite|regenerate|delete|remove|replace|touch|edit|rebuild|overwrite|write|generate)\b/i;
  const override = /\b(?:but|then|also|however|instead|except)\b|\band\s+(?:change|modify|update|rewrite|regenerate|delete|remove|replace|touch)\b/i;
  return text.split(/\n|[;.!?]\s+/).map(clause => {
    const preservation = /^\s*(?:(?:keep|preserve|retain|leave)\b|(?:all|every|the)?\s*(?:other|existing|current|unrelated)?\s*(?:inventory\s+)?files?\b)/i.exec(clause);
    if (preservation && /\b(?:unchanged|unmodified|untouched|identical|alone|as-is)\b/i.test(clause) &&
        !mutation.test(clause.slice(preservation[0].length)) && !override.test(clause)) return '';
    // An acceptance criterion can name the actual UI target and then state
    // that its focused test requires no package/lock changes in the same line.
    const noChange = /\b(?:that\s+)?(?:uses?|requires?|needs?)\s+no\b/i.exec(clause);
    if (noChange) {
      const suffix = clause.slice(noChange.index), verbs = [...suffix.matchAll(new RegExp(mutation.source, 'gi'))];
      if (!override.test(suffix) && (verbs.length === 0 || verbs.length === 1 && /^changes?$/i.test(verbs[0]![0]) && /\bchanges?\b[.,\s]*$/i.test(suffix))) return clause.slice(0, noChange.index);
    }
    return clause;
  }).join('\n');
}
function terms(text: string): string[] {
  return [...new Set(text.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase().match(/[a-z][a-z0-9]{2,39}/g) ?? [])].filter(word => !ignoredWords.has(word)).slice(0, 32);
}
function source(input: SourceSelectionInput): PreviousSourceFile[] {
  if (!input.appId || !input.jobId || !Number.isSafeInteger(input.attempt) || input.attempt < 0 || !(input.baseReleaseId === null || typeof input.baseReleaseId === 'string') || typeof input.request !== 'string' || input.request.length > 20000 || (input.answer !== undefined && (typeof input.answer !== 'string' || input.answer.length > 40000)) || (input.acceptanceCriteria !== undefined && (!Array.isArray(input.acceptanceCriteria) || input.acceptanceCriteria.length > 32 || input.acceptanceCriteria.some(value => typeof value !== 'string' || value.length > 1000)))) throw new Error('Previous source selection input is unavailable.');
  if (input.files !== undefined && (!Array.isArray(input.files) || input.files.length > 500)) throw new Error('Previous source exceeds the authorized selection inventory.');
  let total = 0; const paths = new Set<string>();
  return (input.files ?? []).map(file => {
    if (!file || typeof file.path !== 'string' || typeof file.content !== 'string' || !allowedPath(file.path) || paths.has(file.path.toLowerCase())) throw new Error('Previous source contains an invalid or duplicate project-relative path.');
    paths.add(file.path.toLowerCase()); total += Buffer.byteLength(file.content, 'utf8');
    if (total > 10 * 1024 * 1024) throw new Error('Previous source exceeds the authorized snapshot size.');
    return { path: file.path, content: file.content };
  }).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
function relativeImports(file: PreviousSourceFile, paths: Set<string>): Set<string> {
  const found = new Set<string>();
  // Text is inspected as data. No import, generated expression or package executes.
  const pattern = /(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s*)["'](\.[^"'\r\n]{1,240})["']/g;
  for (const match of file.content.matchAll(pattern)) {
    if (found.size >= 16) break;
    const base = posix.normalize(posix.join(posix.dirname(file.path), match[1]!));
    if (!allowedPath(base)) continue;
    const candidates = [base, ...['.ts', '.tsx', '.js', '.jsx', '.mjs', '.py'].map(ext => base + ext), ...['/index.ts', '/index.js'].map(ext => base + ext)];
    // NodeNext source often imports .js while the retained source is .ts.
    if (base.endsWith('.js')) candidates.push(base.slice(0, -3) + '.ts', base.slice(0, -3) + '.tsx');
    for (const candidate of candidates) if (paths.has(candidate)) { found.add(candidate); break; }
  }
  return found;
}
export function selectPreviousSource(input: SourceSelectionInput): PreviousSourceSelection {
  const files = source(input), byPath = new Map(files.map(file => [file.path, file])), paths = new Set(byPath.keys());
  const text = [input.request, input.answer ?? '', ...(input.acceptanceCriteria ?? [])].join('\n');
  const questions: string[] = [], requested = new Set<string>();
  const mentioned = [...new Set(technicalTargetText(text).match(/[A-Za-z0-9_./\\:-]+\.(?:tsx?|jsx?|mjs|py|json|sql|css|html|toml|ya?ml|md|txt|lock)\b/gi) ?? [])];
  if (mentioned.length > 64) questions.push('This request names too many parts of the application for one safe change. Please split it into smaller business changes.');
  for (const mention of mentioned.slice(0, 64)) {
    if (!allowedPath(mention)) { questions.push('A named file is outside the application workspace. Please describe the application page or business behavior to change; company operators manage platform and host files.'); continue; }
    const matches = byPath.has(mention) ? [mention] : mention.includes('/') ? [] : files.filter(file => posix.basename(file.path) === mention).map(file => file.path);
    if (matches.length === 1) requested.add(matches[0]!);
    else if (files.length && !(matches.length === 0 && /\b(?:new|create|add)\b.{0,60}\b(?:file|module|page|component)\b/i.test(text))) questions.push(matches.length ? `Several application areas use ${mention}. Which page or business operation should change?` : `The existing application does not contain ${mention}. Is this a new file, or which existing page or business operation should change?`);
  }
  // A named path identifies that file, rather than making every sibling with the same directory name relevant.
  const words = terms(mentioned.reduce((value, path) => value.split(path).join(' '), text)), scores = new Map<string, number>();
  for (const file of files) {
    const name = file.path.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase(), content = file.content.toLowerCase();
    let score = 0;
    for (const word of words) { if (name.includes(word)) score += 12; if (content.includes(word)) score += 1; }
    scores.set(file.path, score);
  }
  const seeds = files.filter(file => requested.has(file.path) || (scores.get(file.path) ?? 0) >= 3).sort((a, b) => Number(requested.has(b.path)) - Number(requested.has(a.path)) || (scores.get(b.path) ?? 0) - (scores.get(a.path) ?? 0) || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)).slice(0, 16);
  const neighbors = new Set<string>();
  for (const seed of seeds) for (const path of relativeImports(seed, paths)) neighbors.add(path);
  const ordered = [...files].sort((a, b) => {
    const rank = (f: PreviousSourceFile) => requested.has(f.path) ? 5 : contractFiles.has(f.path) ? 4 : (scores.get(f.path) ?? 0) >= 3 ? 3 : neighbors.has(f.path) ? 2 : /auth|permission|server|migration|schema/.test(f.path) ? 1 : 0;
    return rank(b) - rank(a) || (scores.get(b.path) ?? 0) - (scores.get(a.path) ?? 0) || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  });
  let selectedBytes = 0;
  const selected: PreviousSourceSelection['selected'] = [], omitted: PreviousSourceSelection['omitted'] = [];
  for (const file of ordered) {
    const item = { path: file.path, bytes: Buffer.byteLength(file.content, 'utf8'), sha256: sha(file.content) };
    if (excluded.test(file.path)) {
      omitted.push({ ...item, reason: 'excluded' });
      if (requested.has(file.path)) questions.push('Dependency locks and generated artifacts are maintained by the verified pipeline. Please describe the dependency or business change instead of requesting a lock or artifact rewrite.');
    } else if (selectedBytes + item.bytes > previousSourceByteLimit) {
      omitted.push({ ...item, reason: requested.has(file.path) ? 'requested_over_limit' : 'limit' });
      if (requested.has(file.path)) questions.push('The requested change needs more existing source than can be reviewed safely in one step. Please narrow the business change, or ask the company operator to support a larger application area. No partial file will be rewritten.');
    } else {
      selectedBytes += item.bytes;
      selected.push({ ...item, reason: requested.has(file.path) ? 'requested' : contractFiles.has(file.path) ? 'contract' : (scores.get(file.path) ?? 0) >= 3 ? 'relevant' : neighbors.has(file.path) ? 'neighbor' : 'general' });
    }
  }
  const truncated = omitted.some(file => file.reason === 'limit' || file.reason === 'requested_over_limit');
  if (truncated && !requested.size && !seeds.length) questions.push('Which page, form, or business operation should change? The application is larger than one review context, and the request does not identify a relevant area.');
  return { schemaVersion: 1, appId: input.appId, jobId: input.jobId, attempt: input.attempt, baseReleaseId: input.baseReleaseId, inputHash: hashArtifact({ request: input.request, answer: input.answer ?? null, acceptanceCriteria: input.acceptanceCriteria ?? [] }), snapshotHash: hashArtifact(files.map(file => ({ path: file.path, bytes: Buffer.byteLength(file.content, 'utf8'), sha256: sha(file.content) }))), acceptanceCriteria: [...(input.acceptanceCriteria ?? [])], maxBytes: previousSourceByteLimit, selectedBytes, truncated, requestedPaths: [...requested].sort(), selected, omitted, questions: [...new Set(questions)].slice(0, 8) };
}
export function validatedPreviousSourceSelection(value: unknown, input: SourceSelectionInput): PreviousSourceSelection {
  const record = selectionSchema.parse(value), expected = selectPreviousSource(input);
  if (hashArtifact(record) !== hashArtifact(expected)) throw new Error('Frozen previous source selection changed or belongs to another application, request or starting release.');
  return record;
}
export function selectedPreviousFiles(record: PreviousSourceSelection, input: SourceSelectionInput): PreviousSourceFile[] {
  validatedPreviousSourceSelection(record, input);
  const files = new Map((input.files ?? []).map(file => [file.path, file]));
  return record.selected.map(item => ({ ...files.get(item.path)! }));
}
/** Requirements see a bounded inventory; the persisted record retains every path and hash. */
export function previousSourceInventory(record: PreviousSourceSelection): { files: { path: string; bytes: number }[]; omittedCount: number } {
  const files: { path: string; bytes: number }[] = []; let bytes = 0;
  for (const item of [...record.selected, ...record.omitted]) {
    const row = { path: item.path, bytes: item.bytes }, size = Buffer.byteLength(JSON.stringify(row));
    if (bytes + size > 12000) break;
    files.push(row); bytes += size;
  }
  return { files, omittedCount: record.selected.length + record.omitted.length - files.length };
}
export function unreviewedExistingChanges(files: PreviousSourceFile[], previous: PreviousSourceFile[], selection: PreviousSourceSelection): string[] {
  const retained = new Map(previous.map(file => [file.path, file])), reviewed = new Set(selection.selected.map(file => file.path));
  return files.filter(file => retained.has(file.path) && !reviewed.has(file.path) && file.content !== retained.get(file.path)!.content).map(file => file.path);
}
/** Validate the complete proposed artifact map, including structured contracts and deletions. */
export function unreviewedExistingArtifactChanges(files: PreviousSourceFile[], previous: PreviousSourceFile[], selection: PreviousSourceSelection): string[] {
  const proposed = new Map(files.map(file => [file.path, file])), reviewed = new Set(selection.selected.map(file => file.path));
  return previous.filter(file => !reviewed.has(file.path) && proposed.get(file.path)?.content !== file.content).map(file => file.path);
}
/** An unseen, semantically unchanged contract keeps its exact original encoding. */
export function proposedJsonContract(path: string, value: unknown, previous: PreviousSourceFile[], selection: PreviousSourceSelection): PreviousSourceFile {
  const existing = previous.find(file => file.path === path);
  if (existing && !selection.selected.some(file => file.path === path)) {
    try { if (hashArtifact(JSON.parse(existing.content)) === hashArtifact(value)) return { ...existing }; }
    catch { /* An unreadable contract cannot authorize a replacement; the final artifact guard will pause. */ }
  }
  return { path, content: JSON.stringify(value, null, 2) };
}
