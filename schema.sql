-- DTS foundational schema.
-- Run this FIRST against an empty database, then run migrations/001_enterprise_security.sql.
-- Idempotent and safe to rerun.

SET NAMES utf8mb4;

-- ---------------------------------------------------------------------------
-- Offices (destination directory)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `offices` (
  `destination_office_id` INT AUTO_INCREMENT PRIMARY KEY,
  `office_name` VARCHAR(255) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uq_offices_office_name` (`office_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
  `user_id` INT AUTO_INCREMENT PRIMARY KEY,
  `full_name` VARCHAR(255) NOT NULL,
  `employee_id` VARCHAR(50) NULL,
  `role` VARCHAR(50) NOT NULL DEFAULT 'Admin Staff',
  `department` VARCHAR(100) NOT NULL DEFAULT 'General Services',
  `email_address` VARCHAR(255) NOT NULL,
  `username` VARCHAR(100) NOT NULL,
  -- Legacy plaintext column kept for backward compatibility during the
  -- password_hash migration. New code paths populate password_hash.
  `password` VARCHAR(255) NULL,
  `password_hash` VARCHAR(255) NULL,
  `password_migrated` TINYINT(1) NOT NULL DEFAULT 0,
  `status` ENUM('Pending', 'Approved', 'Disabled') NOT NULL DEFAULT 'Pending',
  `last_login` DATETIME NULL,
  `destination_office_id` INT NULL,
  `profile_picture_path` VARCHAR(255) NULL,
  `signature_path` VARCHAR(255) NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uq_users_username` (`username`),
  UNIQUE KEY `uq_users_email_address` (`email_address`),
  INDEX `idx_users_status` (`status`),
  INDEX `idx_users_role` (`role`),
  INDEX `idx_users_destination_office_id` (`destination_office_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Documents
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `documents` (
  `doc_id` INT AUTO_INCREMENT PRIMARY KEY,
  `tracking_number` VARCHAR(64) NOT NULL,
  `title` VARCHAR(255) NOT NULL,
  `category` VARCHAR(100) NULL,
  `description` TEXT NULL,
  `priority` VARCHAR(20) NOT NULL DEFAULT 'Normal',
  `destination_office_id` INT NULL,
  `owner_id` INT NULL,
  `sender_id` INT NULL,
  `due_date` DATE NULL,
  `current_status` VARCHAR(50) NOT NULL DEFAULT 'Pending',
  `admin_comment` TEXT NULL,
  `file_path` VARCHAR(512) NULL,
  `storage_path` VARCHAR(512) NULL,
  `file_hash_sha256` VARCHAR(64) NULL,
  `visibility_scope` ENUM('private', 'destination', 'organization') NOT NULL DEFAULT 'destination',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uq_documents_tracking_number` (`tracking_number`),
  INDEX `idx_documents_sender` (`sender_id`),
  INDEX `idx_documents_destination` (`destination_office_id`),
  INDEX `idx_documents_owner` (`owner_id`),
  INDEX `idx_documents_status` (`current_status`),
  INDEX `idx_documents_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Messaging
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `messages` (
  `msg_id` INT AUTO_INCREMENT PRIMARY KEY,
  `sender_id` INT NOT NULL,
  `receiver_id` INT NOT NULL,
  `message_text` TEXT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_messages_sender` (`sender_id`),
  INDEX `idx_messages_receiver` (`receiver_id`),
  INDEX `idx_messages_thread` (`sender_id`, `receiver_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Notifications
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `notifications` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NULL,
  `type` VARCHAR(50) NOT NULL,
  `ref_id` INT DEFAULT NULL,
  `title` VARCHAR(255) NOT NULL,
  `description` TEXT NULL,
  `is_read` TINYINT(1) NOT NULL DEFAULT 0,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_notifications_user_read` (`user_id`, `is_read`, `created_at`),
  INDEX `idx_notifications_is_read` (`is_read`),
  INDEX `idx_notifications_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
