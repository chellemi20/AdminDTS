const path = require("path");

module.exports = {
  port: Number(process.env.PORT || 5000),
  jwtSecret: process.env.JWT_SECRET || "change-this-in-production",
  jwtExpiry: process.env.JWT_EXPIRY || "8h",
  accessGrantHoursDefault: Number(process.env.ACCESS_GRANT_HOURS_DEFAULT || 24),
  backupDir: process.env.BACKUP_DIR || path.join(__dirname, "..", "backups"),
  documentsDir:
    process.env.DOCUMENTS_DIR || path.join(__dirname, "..", "storage", "documents"),
  profileUploadsDir:
    process.env.PROFILE_UPLOADS_DIR ||
    path.join(__dirname, "..", "uploads", "users"),
};
