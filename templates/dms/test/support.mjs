import { createHash, randomUUID } from 'node:crypto';

// Test-only repositories. Production imports exclusively the MySQL repository.
export class MemoryRepository {
  constructor() { this.folders = []; this.documents = []; this.history = []; this.records = []; this.pending = Promise.resolve(); }
  async transaction(action) {
    const operation = this.pending.then(async () => { const saved = structuredClone([this.folders, this.documents, this.history, this.records]); try { return await action(this); } catch (error) { [this.folders, this.documents, this.history, this.records] = saved; throw error; } });
    this.pending = operation.then(() => {}, () => {}); return operation;
  }
  async listFolders(appId) { return structuredClone(this.folders.filter(item => item.appId === appId)); }
  async folder(appId, folderId) { return this.folders.find(item => item.appId === appId && item.id === folderId) ?? null; }
  async createFolder(folder) { this.folders.push(structuredClone(folder)); }
  async search(appId, query, archived) { return structuredClone(this.documents.filter(item => item.appId === appId && (archived || !item.archived) && JSON.stringify([item.title, item.metadata]).toLowerCase().includes(query.toLowerCase()))); }
  async document(appId, documentId) { return structuredClone(this.documents.find(item => item.appId === appId && item.id === documentId) ?? null); }
  async createDocument(doc) { this.documents.push(structuredClone(doc)); }
  async versions(appId, documentId) { return structuredClone(this.history.filter(item => item.appId === appId && item.documentId === documentId).sort((a, b) => b.number - a.number)); }
  async version(appId, documentId, versionId) { return structuredClone(this.history.find(item => item.appId === appId && item.documentId === documentId && item.id === versionId) ?? null); }
  async appendVersion(version) { this.history.push(structuredClone(version)); const doc = this.documents.find(item => item.appId === version.appId && item.id === version.documentId); doc.currentVersion = version.number; doc.updatedAt = version.createdAt; }
  async archive(appId, documentId) { this.documents.find(item => item.appId === appId && item.id === documentId).archived = true; }
  async audit(record) { this.records.push(structuredClone(record)); }
  async auditRecords(appId) { return structuredClone(this.records.filter(item => item.appId === appId)); }
}
export class MemoryStorage {
  constructor() { this.content = new Map(); }
  async put(content) { const blobId = randomUUID(), checksum = createHash('sha256').update(content).digest('hex'); this.content.set(blobId, Buffer.from(content)); return { blobId, checksum, bytes: content.length }; }
  async read(blobId) { return Buffer.from(this.content.get(blobId)); }
}
