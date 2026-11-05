import assert from 'node:assert/strict';
import test from 'node:test';
import { DmsService } from '../src/domain.mjs';
import { MemoryRepository, MemoryStorage } from './support.mjs';

const admin = { id: 'owner', appId: 'dms-a', roles: ['dms.admin'] }, reader = { id: 'reader', appId: 'dms-a', roles: ['dms.read', 'dms.search'] }, writer = { id: 'writer', appId: 'dms-a', roles: ['dms.read', 'dms.write', 'dms.search'] };
function fixture() { const repository = new MemoryRepository(), storage = new MemoryStorage(); return { repository, storage, service: new DmsService({ appId: 'dms-a', repository, storage }) }; }
const input = content => ({ title: 'Contract', content: Buffer.from(content), metadata: { department: 'Finance' }, mime: 'application/pdf' });

test('version updates, restore and archive preserve every original document byte', async () => {
  const { service, repository, storage } = fixture();
  const first = await service.upload(writer, input('original content'));
  const second = await service.upload(writer, input('updated content'), first.id);
  const restored = await service.restore(writer, first.id, first.version.id);
  const versions = await service.versions(reader, first.id);
  assert.equal(versions.length, 3); assert.equal(restored.number, 3); assert.equal(restored.restoredFrom, first.version.id); assert.equal(restored.blobId, first.version.blobId);
  assert.equal((await service.content(reader, first.id, first.version.id)).content.toString(), 'original content');
  assert.equal((await service.content(reader, first.id, second.version.id)).content.toString(), 'updated content');
  await service.archive(admin, first.id);
  assert.equal((await service.search(reader)).length, 0); assert.equal((await service.search(admin, '', true)).length, 1);
  assert.equal(repository.history.length, 3); assert.equal(storage.content.size, 2);
  assert.deepEqual(repository.records.map(item => item.action), ['document.created', 'document.version_added', 'document.version_restored', 'document.downloaded', 'document.downloaded', 'document.archived']);
});
test('application and role boundaries deny reads, writes, archives and audit without altering data', async () => {
  const { service, repository, storage } = fixture(); const doc = await service.upload(writer, input('private'));
  for (const principal of [{ id: 'platform-owner', appId: 'dms-a', roles: ['platform.owner'] }, { ...admin, appId: 'dms-b' }]) {
    await assert.rejects(service.document(principal, doc.id), error => error.status === 403);
    await assert.rejects(service.upload(principal, input('unauthorized'), doc.id), error => error.status === 403);
  }
  await assert.rejects(service.upload(reader, input('readers cannot edit'), doc.id), error => error.status === 403);
  await assert.rejects(service.archive(writer, doc.id), error => error.status === 403);
  await assert.rejects(service.auditRecords(reader), error => error.status === 403);
  assert.equal(repository.history.length, 1); assert.equal(storage.content.size, 1); assert.equal(repository.documents[0].archived, false);
});
test('folder ownership and metadata search respect app identity and safe fields', async () => {
  const { service, repository } = fixture(); const folder = await service.createFolder(writer, { name: 'Contracts' });
  const doc = await service.upload(writer, { ...input('content'), folderId: folder.id });
  assert.equal((await service.search(reader, 'Finance'))[0].id, doc.id);
  repository.folders.push({ id: 'other-folder', appId: 'dms-b', name: 'Other' });
  await assert.rejects(service.upload(writer, { ...input('content'), folderId: 'other-folder' }), error => error.status === 404);
  await assert.rejects(service.createFolder(writer, { name: 'Bad', parentId: 'other-folder' }), error => error.status === 404);
  await assert.rejects(service.upload(writer, { ...input('content'), metadata: { invalid: { secret: 'nested' } } }), error => error.status === 400);
});
test('concurrent version appends serialize into unique monotonically increasing versions', async () => {
  const { service } = fixture(); const doc = await service.upload(writer, input('one'));
  await Promise.all([service.upload(writer, input('two'), doc.id), service.upload(writer, input('three'), doc.id)]);
  assert.deepEqual((await service.versions(reader, doc.id)).map(item => item.number), [3, 2, 1]);
});
test('audit failure rolls back metadata and preserves written content for recovery', async () => {
  const { service, repository, storage } = fixture(); repository.audit = async () => { throw new Error('unavailable'); };
  await assert.rejects(service.upload(writer, input('recoverable')), /unavailable/);
  assert.equal(repository.documents.length, 0); assert.equal(repository.history.length, 0); assert.equal(storage.content.size, 1);
});
