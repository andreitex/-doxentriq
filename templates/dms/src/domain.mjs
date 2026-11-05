import { randomUUID } from 'node:crypto';

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export function authorize(principal, appId, permission) {
  if (!principal || principal.appId !== appId) throw new HttpError(403, 'This account does not belong to this application.');
  if (!principal.roles.includes('dms.admin') && !principal.roles.includes(permission)) throw new HttpError(403, 'The required document permission is missing.');
}
const identifier = value => typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$/.test(value);
export function id(value) { if (!identifier(value)) throw new HttpError(400, 'Invalid identifier.'); return value; }
export function text(value, max = 240) { if (typeof value !== 'string' || !value.trim() || value.length > max || /[\x00-\x1f]/.test(value)) throw new HttpError(400, 'Invalid text field.'); return value.trim(); }
export function metadata(value = {}) {
  if (!value || Array.isArray(value) || typeof value !== 'object' || Object.keys(value).length > 32) throw new HttpError(400, 'Metadata must be a small object of text, number, or boolean fields.');
  for (const [key, item] of Object.entries(value)) if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(key) || !['string', 'number', 'boolean'].includes(typeof item) || typeof item === 'string' && item.length > 256 || typeof item === 'number' && !Number.isFinite(item)) throw new HttpError(400, 'Invalid metadata field.');
  if (Buffer.byteLength(JSON.stringify(value)) > 4096) throw new HttpError(400, 'Metadata is too large.');
  return structuredClone(value);
}

export class DmsService {
  constructor({ appId, repository, storage, connector }) { this.appId = id(appId); this.repository = repository; this.storage = storage; this.connector = connector; }
  check(principal, permission) { authorize(principal, this.appId, permission); }
  audit(principal, action, target, detail = {}) { return { id: randomUUID(), appId: this.appId, actor: principal.id, action, target, detail, createdAt: new Date().toISOString() }; }
  async listFolders(principal) { this.check(principal, 'dms.read'); return this.repository.listFolders(this.appId); }
  async createFolder(principal, input) {
    this.check(principal, 'dms.write'); const folder = { id: randomUUID(), appId: this.appId, name: text(input.name, 160), parentId: input.parentId ? id(input.parentId) : null, createdAt: new Date().toISOString() };
    return this.repository.transaction(async repo => {
      if (folder.parentId && !await repo.folder(this.appId, folder.parentId)) throw new HttpError(404, 'Parent folder was not found.');
      await repo.createFolder(folder); await repo.audit(this.audit(principal, 'folder.created', folder.id)); return folder;
    });
  }
  async search(principal, query = '', includeArchived = false) {
    this.check(principal, 'dms.search'); if (typeof query !== 'string' || query.length > 240) throw new HttpError(400, 'Search query is too long.');
    if (includeArchived) this.check(principal, 'dms.admin');
    return this.repository.search(this.appId, query, includeArchived);
  }
  async document(principal, documentId) { this.check(principal, 'dms.read'); const found = await this.repository.document(this.appId, id(documentId)); if (!found) throw new HttpError(404, 'Document was not found.'); return found; }
  async versions(principal, documentId) { await this.document(principal, documentId); return this.repository.versions(this.appId, documentId); }
  async upload(principal, input, documentId) {
    this.check(principal, 'dms.write');
    if (!Buffer.isBuffer(input.content) || !input.content.length) throw new HttpError(400, 'Document content is required.');
    const title = documentId ? null : text(input.title), folderId = input.folderId ? id(input.folderId) : null, fields = documentId ? null : metadata(input.metadata);
    const mime = typeof input.mime === 'string' && /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(input.mime) && input.mime.length < 120 ? input.mime : 'application/octet-stream';
    const target = documentId ? id(documentId) : randomUUID();
    // Check authorization and ownership before allocating persistent content.
    if (documentId && !await this.repository.document(this.appId, target)) throw new HttpError(404, 'Document was not found.');
    if (folderId && !await this.repository.folder(this.appId, folderId)) throw new HttpError(404, 'Folder was not found.');
    const blob = await this.storage.put(input.content);
    return this.repository.transaction(async repo => {
      let doc = await repo.document(this.appId, target, true);
      if (!documentId) { doc = { id: target, appId: this.appId, title, folderId, metadata: fields, currentVersion: 0, archived: false, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }; await repo.createDocument(doc); }
      if (!doc) throw new HttpError(404, 'Document was not found.');
      const version = { id: randomUUID(), appId: this.appId, documentId: target, number: doc.currentVersion + 1, ...blob, mime, actor: principal.id, restoredFrom: null, createdAt: new Date().toISOString() };
      await repo.appendVersion(version); await repo.audit(this.audit(principal, documentId ? 'document.version_added' : 'document.created', target, { versionId: version.id, checksum: blob.checksum, bytes: blob.bytes })); return { ...doc, currentVersion: version.number, version };
    });
  }
  async restore(principal, documentId, versionId) {
    this.check(principal, 'dms.write'); id(documentId); id(versionId);
    return this.repository.transaction(async repo => {
      const doc = await repo.document(this.appId, documentId, true), old = await repo.version(this.appId, documentId, versionId);
      if (!doc || !old) throw new HttpError(404, 'Document version was not found.');
      const version = { ...old, id: randomUUID(), number: doc.currentVersion + 1, actor: principal.id, restoredFrom: old.id, createdAt: new Date().toISOString() };
      await repo.appendVersion(version); await repo.audit(this.audit(principal, 'document.version_restored', documentId, { versionId: version.id, restoredFrom: old.id })); return version;
    });
  }
  async archive(principal, documentId) {
    this.check(principal, 'dms.admin'); id(documentId);
    return this.repository.transaction(async repo => { if (!await repo.document(this.appId, documentId, true)) throw new HttpError(404, 'Document was not found.'); await repo.archive(this.appId, documentId); await repo.audit(this.audit(principal, 'document.archived', documentId)); return { archived: true, preserved: true }; });
  }
  async content(principal, documentId, versionId) {
    await this.document(principal, documentId); const version = await this.repository.version(this.appId, documentId, id(versionId));
    if (!version) throw new HttpError(404, 'Document version was not found.');
    const content = await this.storage.read(version.blobId, version.checksum);
    await this.repository.audit(this.audit(principal, 'document.downloaded', documentId, { versionId })); return { content, mime: version.mime };
  }
  async auditRecords(principal) { this.check(principal, 'dms.admin'); return this.repository.auditRecords(this.appId); }
  async samba(principal, connectionId, operation, relativePath) {
    this.check(principal, 'dms.read'); if (!this.connector) throw new HttpError(503, 'No approved Samba connector is configured.');
    const result = await this.connector.perform({ appId: this.appId, connectionId: id(connectionId), operation, relativePath });
    await this.repository.audit(this.audit(principal, `samba.${operation}`, connectionId, { path: relativePath })); return result;
  }
}
