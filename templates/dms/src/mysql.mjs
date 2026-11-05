import { readFile } from 'node:fs/promises';
import mysql from 'mysql2/promise';

const decode = row => { if (!row) return null; const result = { ...row }; for (const key of ['metadata', 'detail']) if (typeof result[key] === 'string') result[key] = JSON.parse(result[key]); if ('archived' in result) result.archived = Boolean(result.archived); return result; };
const docColumns = 'id,app_id AS appId,title,folder_id AS folderId,metadata,current_version AS currentVersion,archived,created_at AS createdAt,updated_at AS updatedAt';
const versionColumns = 'id,app_id AS appId,document_id AS documentId,version_number AS number,blob_id AS blobId,checksum,bytes,mime,actor,restored_from AS restoredFrom,created_at AS createdAt';
export class MySqlRepository {
  constructor(connection, pool = connection) { this.connection = connection; this.pool = pool; }
  async rows(sql, values = []) { const [rows] = await this.connection.execute(sql, values); return rows.map(decode); }
  async transaction(action) { const connection = await this.pool.getConnection(); try { await connection.beginTransaction(); const value = await action(new MySqlRepository(connection, this.pool)); await connection.commit(); return value; } catch (error) { await connection.rollback(); throw error; } finally { connection.release(); } }
  async ready() { await this.connection.execute('SELECT id FROM documents LIMIT 0'); }
  async close() { await this.pool.end(); }
  async listFolders(appId) { return this.rows('SELECT id,app_id AS appId,name,parent_id AS parentId,created_at AS createdAt FROM folders WHERE app_id=? ORDER BY name,id LIMIT 1000', [appId]); }
  async folder(appId, folderId) { return (await this.rows('SELECT id FROM folders WHERE app_id=? AND id=?', [appId, folderId]))[0] ?? null; }
  async createFolder(folder) { await this.connection.execute('INSERT INTO folders (id,app_id,name,parent_id,created_at) VALUES (?,?,?,?,?)', [folder.id, folder.appId, folder.name, folder.parentId, folder.createdAt]); }
  async search(appId, query, includeArchived) { const escaped = `%${query.replace(/[!%_]/g, value => '!' + value)}%`; return this.rows(`SELECT ${docColumns} FROM documents WHERE app_id=? AND (?=1 OR archived=0) AND (title LIKE ? ESCAPE '!' OR CAST(metadata AS CHAR) LIKE ? ESCAPE '!') ORDER BY updated_at DESC,id LIMIT 100`, [appId, includeArchived ? 1 : 0, escaped, escaped]); }
  async document(appId, documentId, lock = false) { return (await this.rows(`SELECT ${docColumns} FROM documents WHERE app_id=? AND id=?${lock ? ' FOR UPDATE' : ''}`, [appId, documentId]))[0] ?? null; }
  async createDocument(doc) { await this.connection.execute('INSERT INTO documents (id,app_id,title,folder_id,metadata,current_version,archived,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)', [doc.id, doc.appId, doc.title, doc.folderId, JSON.stringify(doc.metadata), doc.currentVersion, 0, doc.createdAt, doc.updatedAt]); }
  async versions(appId, documentId) { return this.rows(`SELECT ${versionColumns} FROM document_versions WHERE app_id=? AND document_id=? ORDER BY version_number DESC LIMIT 1000`, [appId, documentId]); }
  async version(appId, documentId, versionId) { return (await this.rows(`SELECT ${versionColumns} FROM document_versions WHERE app_id=? AND document_id=? AND id=?`, [appId, documentId, versionId]))[0] ?? null; }
  async appendVersion(version) { await this.connection.execute('INSERT INTO document_versions (id,app_id,document_id,version_number,blob_id,checksum,bytes,mime,actor,restored_from,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)', [version.id, version.appId, version.documentId, version.number, version.blobId, version.checksum, version.bytes, version.mime, version.actor, version.restoredFrom, version.createdAt]); await this.connection.execute('UPDATE documents SET current_version=?,updated_at=? WHERE app_id=? AND id=?', [version.number, version.createdAt, version.appId, version.documentId]); }
  async archive(appId, documentId) { await this.connection.execute('UPDATE documents SET archived=1,updated_at=? WHERE app_id=? AND id=?', [new Date().toISOString(), appId, documentId]); }
  async audit(record) { await this.connection.execute('INSERT INTO audit_records (id,app_id,actor,action,target,detail,created_at) VALUES (?,?,?,?,?,?,?)', [record.id, record.appId, record.actor, record.action, record.target, JSON.stringify(record.detail), record.createdAt]); }
  async auditRecords(appId) { return this.rows('SELECT id,app_id AS appId,actor,action,target,detail,created_at AS createdAt FROM audit_records WHERE app_id=? ORDER BY created_at DESC,id LIMIT 500', [appId]); }
}
export async function connectMySql(environment) {
  for (const name of ['MYSQL_HOST', 'MYSQL_DATABASE', 'MYSQL_USER', 'MYSQL_PASSWORD_FILE', 'MYSQL_CA_FILE']) if (!environment[name]) throw new Error(`The app-scoped ${name} setting is required.`);
  const pool = mysql.createPool({ host: environment.MYSQL_HOST, port: Number(environment.MYSQL_PORT ?? 3306), database: environment.MYSQL_DATABASE, user: environment.MYSQL_USER, password: (await readFile(environment.MYSQL_PASSWORD_FILE, 'utf8')).trim(), ssl: { ca: await readFile(environment.MYSQL_CA_FILE, 'utf8'), rejectUnauthorized: true, verifyIdentity: true, minVersion: 'TLSv1.2' }, connectionLimit: 5, multipleStatements: false, dateStrings: true, supportBigNumbers: true, bigNumberStrings: false });
  const repository = new MySqlRepository(pool); await repository.ready(); return repository;
}
