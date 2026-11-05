import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath, stat } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { HttpError } from './domain.mjs';

export class FileStorage {
  constructor(root, quotaBytes, maxDocumentBytes = 16 * 1024 * 1024) {
    if (!root || !isAbsolute(root) || !Number.isSafeInteger(quotaBytes) || quotaBytes <= 0) throw new Error('An absolute encrypted quota storage mount and positive byte quota are required.');
    this.root = root; this.quotaBytes = quotaBytes; this.maxDocumentBytes = maxDocumentBytes; this.pending = Promise.resolve();
  }
  async initialize() {
    if (!(await stat(this.root)).isDirectory() || (await lstat(this.root)).isSymbolicLink()) throw new Error('The platform storage mount must be a real directory.');
    this.root = await realpath(this.root); this.blobs = join(this.root, 'blobs'); try { await mkdir(this.blobs, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    if ((await lstat(this.blobs)).isSymbolicLink() || await realpath(this.blobs) !== this.blobs) throw new Error('Unsafe document storage path.');
  }
  async put(content) {
    if (content.length > this.maxDocumentBytes) throw new HttpError(413, 'Document exceeds the allowed upload size.');
    const operation = this.pending.then(async () => {
      if (await realpath(this.blobs) !== this.blobs) throw new Error('Unsafe document storage path.');
      let used = 0;
      for (const item of await readdir(this.blobs, { withFileTypes: true })) { if (!item.isFile() || !/^[a-f0-9-]{36}\.blob$/.test(item.name)) throw new Error('Unexpected object in document storage.'); used += (await stat(join(this.blobs, item.name))).size; }
      if (used + content.length > this.quotaBytes) throw new HttpError(507, 'The document storage quota is full. Existing versions are preserved.');
      const blobId = randomUUID(), checksum = createHash('sha256').update(content).digest('hex');
      const file = await open(join(this.blobs, `${blobId}.blob`), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
      try { await file.writeFile(content); await file.sync(); } finally { await file.close(); }
      return { blobId, checksum, bytes: content.length };
    });
    this.pending = operation.then(() => {}, () => {}); return operation;
  }
  async read(blobId, checksum) {
    if (!/^[a-f0-9-]{36}$/.test(blobId) || !/^[a-f0-9]{64}$/.test(checksum) || await realpath(this.blobs) !== this.blobs) throw new Error('Invalid stored document reference.');
    const file = await open(join(this.blobs, `${blobId}.blob`), constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const details = await file.stat(); if (!details.isFile() || details.size > this.maxDocumentBytes) throw new Error('Invalid stored content.');
      const content = await file.readFile(); if (createHash('sha256').update(content).digest('hex') !== checksum) throw new Error('Stored document integrity check failed.'); return content;
    } finally { await file.close(); }
  }
}
