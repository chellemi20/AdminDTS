-- Enterprise security baseline migration (final)
-- Idempotent for MySQL 8+ and safe to rerun.

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS roles (
  role_id INT AUTO_INCREMENT PRIMARY KEY,
  role_key VARCHAR(50) NOT NULL UNIQUE,
  role_name VARCHAR(100) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS permissions (
  permission_id INT AUTO_INCREMENT PRIMARY KEY,
  permission_key VARCHAR(100) NOT NULL UNIQUE,
  description VARCHAR(255) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_roles (
  user_id INT NOT NULL,
  role_id INT NOT NULL,
  assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, role_id),
  INDEX idx_user_roles_role_id (role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id INT NOT NULL,
  permission_id INT NOT NULL,
  granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (role_id, permission_id),
  INDEX idx_role_permissions_permission_id (permission_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS document_acl (
  acl_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  doc_id INT NOT NULL,
  user_id INT NOT NULL,
  granted_by INT NOT NULL,
  grant_reason VARCHAR(255) NULL,
  status ENUM('active', 'revoked', 'expired') NOT NULL DEFAULT 'active',
  granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NULL,
  INDEX idx_document_acl_doc_user (doc_id, user_id),
  INDEX idx_document_acl_expires (expires_at),
  INDEX idx_document_acl_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS document_access_requests (
  request_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  doc_id INT NOT NULL,
  requester_id INT NOT NULL,
  owner_id INT NOT NULL,
  status ENUM('pending', 'approved', 'denied', 'cancelled') NOT NULL DEFAULT 'pending',
  reason TEXT NULL,
  decision_reason TEXT NULL,
  requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at DATETIME NULL,
  reviewed_by INT NULL,
  expires_at DATETIME NULL,
  INDEX idx_access_requests_owner_status (owner_id, status),
  INDEX idx_access_requests_doc_status (doc_id, status),
  INDEX idx_access_requests_requester (requester_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS document_signatures (
  signature_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  doc_id INT NOT NULL,
  signer_id INT NOT NULL,
  signer_name VARCHAR(255) NOT NULL,
  signer_role VARCHAR(100) NOT NULL,
  signature_image_path VARCHAR(512) NOT NULL,
  signed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  signer_ip VARCHAR(64) NOT NULL,
  user_agent VARCHAR(255) NULL,
  doc_hash_sha256 VARCHAR(64) NOT NULL,
  signature_hash VARCHAR(64) NOT NULL,
  is_revoked TINYINT(1) NOT NULL DEFAULT 0,
  revoked_at DATETIME NULL,
  INDEX idx_document_signatures_doc (doc_id),
  INDEX idx_document_signatures_signer (signer_id),
  UNIQUE KEY uq_document_signature_hash (signature_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS document_versions (
  version_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  doc_id INT NOT NULL,
  file_path VARCHAR(512) NOT NULL,
  file_hash_sha256 VARCHAR(64) NOT NULL,
  version_no INT NOT NULL DEFAULT 1,
  created_by INT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_document_versions_doc (doc_id, version_no),
  UNIQUE KEY uq_document_versions_doc_version (doc_id, version_no)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS document_audit_logs (
  audit_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  actor_user_id INT NULL,
  actor_role VARCHAR(100) NULL,
  action VARCHAR(100) NOT NULL,
  target_type VARCHAR(50) NOT NULL,
  target_id VARCHAR(100) NOT NULL,
  ip_address VARCHAR(64) NULL,
  metadata_json JSON NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_document_audit_target (target_type, target_id),
  INDEX idx_document_audit_actor (actor_user_id),
  INDEX idx_document_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS backups (
  backup_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  triggered_by INT NOT NULL,
  archive_path VARCHAR(512) NULL,
  status ENUM('running', 'completed', 'failed') NOT NULL DEFAULT 'running',
  size_bytes BIGINT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME NULL,
  error TEXT NULL,
  INDEX idx_backups_created (created_at),
  INDEX idx_backups_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Backfill columns on legacy databases. Uses information_schema guards so this
-- works on every MySQL 5.7+/MariaDB version (ADD COLUMN IF NOT EXISTS is only
-- supported on MySQL 8.0.29+ and recent MariaDB).

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'password_hash'),
  'SELECT 1',
  'ALTER TABLE users ADD COLUMN password_hash VARCHAR(255) NULL'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'password_migrated'),
  'SELECT 1',
  'ALTER TABLE users ADD COLUMN password_migrated TINYINT(1) NOT NULL DEFAULT 0'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'last_login'),
  'SELECT 1',
  'ALTER TABLE users ADD COLUMN last_login DATETIME NULL'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'destination_office_id'),
  'SELECT 1',
  'ALTER TABLE users ADD COLUMN destination_office_id INT NULL'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'profile_picture_path'),
  'SELECT 1',
  'ALTER TABLE users ADD COLUMN profile_picture_path VARCHAR(255) NULL'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'signature_path'),
  'SELECT 1',
  'ALTER TABLE users ADD COLUMN signature_path VARCHAR(255) NULL'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'documents' AND column_name = 'owner_id'),
  'SELECT 1',
  'ALTER TABLE documents ADD COLUMN owner_id INT NULL'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'documents' AND column_name = 'storage_path'),
  'SELECT 1',
  'ALTER TABLE documents ADD COLUMN storage_path VARCHAR(512) NULL'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'documents' AND column_name = 'file_hash_sha256'),
  'SELECT 1',
  'ALTER TABLE documents ADD COLUMN file_hash_sha256 VARCHAR(64) NULL'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'documents' AND column_name = 'visibility_scope'),
  'SELECT 1',
  "ALTER TABLE documents ADD COLUMN visibility_scope ENUM('private', 'destination', 'organization') NOT NULL DEFAULT 'destination'"
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- MariaDB/phpMyAdmin-safe conditional DDL (no PROCEDURE/DELIMITER required)
SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'documents' AND index_name = 'idx_documents_sender'),
  'SELECT 1',
  'CREATE INDEX idx_documents_sender ON documents(sender_id)'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'documents' AND index_name = 'idx_documents_destination'),
  'SELECT 1',
  'CREATE INDEX idx_documents_destination ON documents(destination_office_id)'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'documents' AND index_name = 'idx_documents_owner'),
  'SELECT 1',
  'CREATE INDEX idx_documents_owner ON documents(owner_id)'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'users' AND index_name = 'idx_users_destination_office_id'),
  'SELECT 1',
  'CREATE INDEX idx_users_destination_office_id ON users(destination_office_id)'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'user_roles' AND constraint_name = 'fk_user_roles_user' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'user_roles' AND constraint_name = 'fk_user_roles_role' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'role_permissions' AND constraint_name = 'fk_role_permissions_role' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE role_permissions ADD CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'role_permissions' AND constraint_name = 'fk_role_permissions_permission' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE role_permissions ADD CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'document_acl' AND constraint_name = 'fk_document_acl_doc' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE document_acl ADD CONSTRAINT fk_document_acl_doc FOREIGN KEY (doc_id) REFERENCES documents(doc_id) ON DELETE CASCADE'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'document_acl' AND constraint_name = 'fk_document_acl_user' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE document_acl ADD CONSTRAINT fk_document_acl_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'document_acl' AND constraint_name = 'fk_document_acl_granted_by' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE document_acl ADD CONSTRAINT fk_document_acl_granted_by FOREIGN KEY (granted_by) REFERENCES users(user_id) ON DELETE RESTRICT'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'document_access_requests' AND constraint_name = 'fk_access_requests_doc' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE document_access_requests ADD CONSTRAINT fk_access_requests_doc FOREIGN KEY (doc_id) REFERENCES documents(doc_id) ON DELETE CASCADE'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'document_access_requests' AND constraint_name = 'fk_access_requests_requester' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE document_access_requests ADD CONSTRAINT fk_access_requests_requester FOREIGN KEY (requester_id) REFERENCES users(user_id) ON DELETE CASCADE'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'document_access_requests' AND constraint_name = 'fk_access_requests_owner' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE document_access_requests ADD CONSTRAINT fk_access_requests_owner FOREIGN KEY (owner_id) REFERENCES users(user_id) ON DELETE CASCADE'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'document_access_requests' AND constraint_name = 'fk_access_requests_reviewed_by' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE document_access_requests ADD CONSTRAINT fk_access_requests_reviewed_by FOREIGN KEY (reviewed_by) REFERENCES users(user_id) ON DELETE SET NULL'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'document_signatures' AND constraint_name = 'fk_document_signatures_doc' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE document_signatures ADD CONSTRAINT fk_document_signatures_doc FOREIGN KEY (doc_id) REFERENCES documents(doc_id) ON DELETE CASCADE'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'document_signatures' AND constraint_name = 'fk_document_signatures_signer' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE document_signatures ADD CONSTRAINT fk_document_signatures_signer FOREIGN KEY (signer_id) REFERENCES users(user_id) ON DELETE RESTRICT'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'document_versions' AND constraint_name = 'fk_document_versions_doc' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE document_versions ADD CONSTRAINT fk_document_versions_doc FOREIGN KEY (doc_id) REFERENCES documents(doc_id) ON DELETE CASCADE'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'document_versions' AND constraint_name = 'fk_document_versions_created_by' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE document_versions ADD CONSTRAINT fk_document_versions_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE RESTRICT'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'backups' AND constraint_name = 'fk_backups_triggered_by' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE backups ADD CONSTRAINT fk_backups_triggered_by FOREIGN KEY (triggered_by) REFERENCES users(user_id) ON DELETE RESTRICT'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'documents' AND constraint_name = 'fk_documents_owner' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE documents ADD CONSTRAINT fk_documents_owner FOREIGN KEY (owner_id) REFERENCES users(user_id) ON DELETE SET NULL'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_schema = DATABASE() AND table_name = 'users' AND constraint_name = 'fk_users_destination_office' AND constraint_type = 'FOREIGN KEY'),
  'SELECT 1',
  'ALTER TABLE users ADD CONSTRAINT fk_users_destination_office FOREIGN KEY (destination_office_id) REFERENCES offices(destination_office_id) ON DELETE SET NULL'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

INSERT INTO roles (role_key, role_name) VALUES
  ('super_admin', 'Super Admin'),
  ('admin_head', 'Admin Head'),
  ('director', 'Director'),
  ('admin_staff', 'Admin Staff'),
  ('admin_assistant', 'Admin Assistant')
ON DUPLICATE KEY UPDATE role_name = VALUES(role_name);

INSERT INTO permissions (permission_key, description) VALUES
  ('document.view_all', 'View all tracked documents'),
  ('document.view_assigned', 'View assigned or granted documents'),
  ('document.request_access', 'Request access to restricted documents'),
  ('document.approve', 'Approve or reject documents'),
  ('document.sign', 'Apply digital signature to document'),
  ('routing.view_logs', 'View routing logs and movement history'),
  ('signature.view_all', 'View signature records'),
  ('audit.view_all', 'View all user activity and audit logs'),
  ('backup.run', 'Run one-click backup'),
  ('backup.restore', 'Restore from backup')
ON DUPLICATE KEY UPDATE description = VALUES(description);

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
JOIN permissions p
  ON (
    (r.role_key IN ('admin_head','director') AND p.permission_key IN (
      'document.view_all','document.approve','document.sign','routing.view_logs',
      'signature.view_all','backup.run','backup.restore'
    ))
    OR
    (r.role_key = 'super_admin' AND p.permission_key IN (
      'audit.view_all'
    ))
    OR
    (r.role_key IN ('admin_staff','admin_assistant') AND p.permission_key IN (
      'document.view_assigned','document.request_access','document.sign'
    ))
  )
LEFT JOIN role_permissions rp
  ON rp.role_id = r.role_id
 AND rp.permission_id = p.permission_id
WHERE rp.role_id IS NULL;

INSERT INTO user_roles (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u
JOIN roles r
  ON r.role_key = CASE
    WHEN LOWER(REPLACE(TRIM(u.role), ' ', '')) IN ('adminhead') THEN 'admin_head'
    WHEN LOWER(REPLACE(TRIM(u.role), ' ', '')) IN ('director') THEN 'director'
    WHEN LOWER(REPLACE(TRIM(u.role), ' ', '')) IN ('superadmin') THEN 'super_admin'
    WHEN LOWER(REPLACE(TRIM(u.role), ' ', '')) IN ('adminstaff','staff') THEN 'admin_staff'
    WHEN LOWER(REPLACE(TRIM(u.role), ' ', '')) IN ('adminassistant') THEN 'admin_assistant'
    ELSE NULL
  END
LEFT JOIN user_roles ur
  ON ur.user_id = u.user_id
 AND ur.role_id = r.role_id
WHERE r.role_id IS NOT NULL
  AND ur.user_id IS NULL;
