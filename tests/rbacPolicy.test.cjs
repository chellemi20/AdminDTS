const assert = require("assert");
const {
  canViewDocument,
  canViewAuditLogs,
  isMonitoringOnlyRole,
  isFullAccessRole,
  normalizeRole,
} = require("../src/security/rbac.cjs");

function run() {
  assert.strictEqual(normalizeRole("Admin Head"), "adminhead");
  assert.strictEqual(isFullAccessRole("Director"), true);
  assert.strictEqual(isFullAccessRole("Admin Staff"), false);
  assert.strictEqual(isFullAccessRole("Super Admin"), false);
  assert.strictEqual(canViewAuditLogs("Super Admin"), true);
  assert.strictEqual(canViewAuditLogs("Director"), false);
  assert.strictEqual(isMonitoringOnlyRole("SuperAdmin"), true);

  const document = {
    doc_id: 1,
    sender_id: 9,
    owner_id: 9,
    destination_office_id: 4,
    destination: "General Services",
  };

  const adminHead = { user_id: 1, role: "Admin Head", destination_office_id: 99 };
  const staffAssigned = { user_id: 2, role: "Admin Staff", destination_office_id: 4 };
  const staffAcl = { user_id: 3, role: "Admin Staff", destination_office_id: 8 };
  const staffDenied = { user_id: 4, role: "Admin Staff", destination_office_id: 8 };
  const superAdmin = { user_id: 5, role: "Super Admin", destination_office_id: 99 };

  assert.strictEqual(
    canViewDocument({ user: adminHead, document, hasAclGrant: false }),
    true,
    "Admin Head should be able to view all documents"
  );
  assert.strictEqual(
    canViewDocument({ user: staffAssigned, document, hasAclGrant: false }),
    true,
    "Destination-assigned staff should have access"
  );
  assert.strictEqual(
    canViewDocument({ user: staffAcl, document, hasAclGrant: true }),
    true,
    "ACL-granted staff should have access"
  );
  assert.strictEqual(
    canViewDocument({ user: staffDenied, document, hasAclGrant: false }),
    false,
    "Unassigned and non-granted staff should be denied"
  );
  assert.strictEqual(
    canViewDocument({ user: superAdmin, document, hasAclGrant: false }),
    false,
    "Super Admin is monitoring-only and should not inherit document access"
  );

  console.log("rbacPolicy.test.cjs: all assertions passed");
}

run();
