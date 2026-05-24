const db = require("../db.cjs");

async function logAudit({
  actorUserId = null,
  actorRole = null,
  action,
  targetType,
  targetId,
  ipAddress = null,
  metadata = null,
}) {
  try {
    await db.query(
      `INSERT INTO document_audit_logs
       (actor_user_id, actor_role, action, target_type, target_id, ip_address, metadata_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        actorUserId,
        actorRole,
        action,
        targetType,
        String(targetId),
        ipAddress,
        metadata ? JSON.stringify(metadata) : null,
      ]
    );
  } catch (error) {
    console.error("Audit log write failed:", error.message);
  }
}

module.exports = {
  logAudit,
};
