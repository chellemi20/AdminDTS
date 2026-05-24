const FULL_ACCESS_ROLE_KEYS = new Set(["adminhead", "director"]);
const RESTRICTED_ROLE_KEYS = new Set(["adminstaff", "adminassistant", "staff"]);
const AUDIT_VIEWER_ROLE_KEYS = new Set(["superadmin"]);

function normalizeRole(role) {
  return String(role || "")
    .toLowerCase()
    .replace(/\s+/g, "");
}

function isFullAccessRole(role) {
  return FULL_ACCESS_ROLE_KEYS.has(normalizeRole(role));
}

function isRestrictedRole(role) {
  return RESTRICTED_ROLE_KEYS.has(normalizeRole(role));
}

function canManageApprovals(role) {
  return isFullAccessRole(role);
}

function canRunBackups(role) {
  return isFullAccessRole(role);
}

function canViewAuditLogs(role) {
  return AUDIT_VIEWER_ROLE_KEYS.has(normalizeRole(role));
}

function isMonitoringOnlyRole(role) {
  return canViewAuditLogs(role);
}

function isDestinationAssignedToUser(document, user) {
  if (!document || !user) return false;
  const userOfficeId = user.destination_office_id;
  if (userOfficeId && document.destination_office_id) {
    return Number(userOfficeId) === Number(document.destination_office_id);
  }
  const userDept = String(user.department || "").trim().toLowerCase();
  const destination = String(document.destination || "").trim().toLowerCase();
  if (userDept && destination) return userDept === destination;
  return false;
}

function canViewDocument({ user, document, hasAclGrant }) {
  if (!user || !document) return false;
  if (isFullAccessRole(user.role)) return true;
  if (Number(document.sender_id) === Number(user.user_id)) return true;
  if (Number(document.owner_id || document.sender_id) === Number(user.user_id)) return true;
  if (isDestinationAssignedToUser(document, user)) return true;
  if (hasAclGrant) return true;
  return false;
}

module.exports = {
  normalizeRole,
  isFullAccessRole,
  isRestrictedRole,
  canManageApprovals,
  canRunBackups,
  canViewAuditLogs,
  isMonitoringOnlyRole,
  canViewDocument,
  isDestinationAssignedToUser,
};
