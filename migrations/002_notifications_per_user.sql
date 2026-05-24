-- Per-user notifications so one user's read state does not clear alerts for everyone.

CREATE TABLE IF NOT EXISTS notifications (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  type VARCHAR(50) NOT NULL,
  ref_id INT DEFAULT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT NULL,
  is_read TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_notifications_user_read (user_id, is_read, created_at),
  INDEX idx_notifications_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE notifications ADD COLUMN user_id INT NULL AFTER id;
CREATE INDEX idx_notifications_user_read ON notifications (user_id, is_read, created_at);
