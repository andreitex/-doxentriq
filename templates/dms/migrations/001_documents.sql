CREATE TABLE folders (
 id VARCHAR(80) NOT NULL, app_id VARCHAR(80) NOT NULL, name VARCHAR(160) NOT NULL,
 parent_id VARCHAR(80) NULL, created_at VARCHAR(30) NOT NULL,
 PRIMARY KEY (app_id,id),
 CONSTRAINT fk_folder_parent FOREIGN KEY (app_id,parent_id) REFERENCES folders(app_id,id)
);
CREATE TABLE documents (
 id VARCHAR(80) NOT NULL, app_id VARCHAR(80) NOT NULL, title VARCHAR(240) NOT NULL,
 folder_id VARCHAR(80) NULL, metadata JSON NOT NULL, current_version INT UNSIGNED NOT NULL DEFAULT 0,
 archived BOOLEAN NOT NULL DEFAULT FALSE, created_at VARCHAR(30) NOT NULL, updated_at VARCHAR(30) NOT NULL,
 PRIMARY KEY (app_id,id), INDEX ix_documents_search (app_id,archived,updated_at),
 CONSTRAINT fk_document_folder FOREIGN KEY (app_id,folder_id) REFERENCES folders(app_id,id)
);
CREATE TABLE document_versions (
 id VARCHAR(80) NOT NULL, app_id VARCHAR(80) NOT NULL, document_id VARCHAR(80) NOT NULL,
 version_number INT UNSIGNED NOT NULL, blob_id VARCHAR(36) NOT NULL, checksum CHAR(64) NOT NULL,
 bytes INT UNSIGNED NOT NULL, mime VARCHAR(120) NOT NULL, actor VARCHAR(255) NOT NULL,
 restored_from VARCHAR(80) NULL, created_at VARCHAR(30) NOT NULL,
 PRIMARY KEY (app_id,id), UNIQUE KEY ux_document_version (app_id,document_id,version_number),
 CONSTRAINT fk_version_document FOREIGN KEY (app_id,document_id) REFERENCES documents(app_id,id)
);
CREATE TABLE audit_records (
 id VARCHAR(80) NOT NULL, app_id VARCHAR(80) NOT NULL, actor VARCHAR(255) NOT NULL,
 action VARCHAR(80) NOT NULL, target VARCHAR(80) NOT NULL, detail JSON NOT NULL, created_at VARCHAR(30) NOT NULL,
 PRIMARY KEY (app_id,id), INDEX ix_audit_created (app_id,created_at)
);
