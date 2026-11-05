-- MySQL 8.4+; executed by the control service with only its own database rights.
CREATE TABLE IF NOT EXISTS platform_revision (
  id TINYINT PRIMARY KEY,
  revision BIGINT NOT NULL
) ENGINE=InnoDB;
INSERT IGNORE INTO platform_revision VALUES (1, 0);
CREATE TABLE IF NOT EXISTS platform_records (
  collection VARCHAR(32) NOT NULL,
  id VARCHAR(128) NOT NULL,
  app_id VARCHAR(128) NULL,
  payload JSON NOT NULL,
  PRIMARY KEY (collection, id),
  INDEX app_records (app_id, collection)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS platform_events (
  id BIGINT PRIMARY KEY,
  job_id VARCHAR(128) NOT NULL,
  created_at DATETIME(3) NOT NULL,
  payload JSON NOT NULL,
  INDEX job_events (job_id, id),
  INDEX event_retention (created_at)
) ENGINE=InnoDB;
