/**
 * DTS seed script.
 *
 * Run AFTER:
 *   1) Backend/schema.sql           (creates users / offices / documents / etc.)
 *   2) Backend/migrations/001_*.sql (creates roles, permissions, role_permissions)
 *
 * Then:
 *   npm run seed
 *
 * Idempotent: rerunning will not duplicate rows. It updates the password hash
 * on existing seeded users so you can always log in with the documented
 * credentials below.
 *
 * !!! IMPORTANT !!!
 *   These are DEMO credentials. Change every password immediately after first
 *   login in any non-development environment.
 */

const db = require("./src/db.cjs");
const { hashPassword } = require("./src/security/passwords.cjs");

const OFFICES = [
  { name: "PMED" },
  { name: "PRDP" },
  { name: "RSBSA" },
  { name: "RAED" },
  { name: "Research Office" },
  { name: "Finance Accounting" },
  { name: "Admin Department" },
  { name: "Regional Executive Director" },
  { name: "Records" },
  { name: "Operations" },
];

const USERS = [
  {
    full_name: "System Super Admin",
    employee_id: "EMP-0000",
    role: "SuperAdmin",
    department: "System Monitoring",
    email_address: "superadmin@dts.local",
    username: "superadmin",
    password: "SuperAdmin@2026",
    status: "Approved",
    office_name: "Regional Executive Director",
  },
  {
    full_name: "Alex Reyes",
    employee_id: "EMP-0001",
    role: "Admin Head",
    department: "Office of the Director",
    email_address: "admin.head@dts.local",
    username: "admin.head",
    password: "Admin@2026",
    status: "Approved",
    office_name: "Regional Executive Director",
  },
  {
    full_name: "Maria Santos",
    employee_id: "EMP-0002",
    role: "Director",
    department: "Office of the Director",
    email_address: "director@dts.local",
    username: "director",
    password: "Director@2026",
    status: "Approved",
    office_name: "Regional Executive Director",
  },
  {
    full_name: "Juan Dela Cruz",
    employee_id: "EMP-0003",
    role: "Admin Staff",
    department: "General Services",
    email_address: "staff@dts.local",
    username: "staff",
    password: "Staff@2026",
    status: "Approved",
    office_name: "Admin Department",
  },
  {
    full_name: "Liza Mendoza",
    employee_id: "EMP-0004",
    role: "Admin Assistant",
    department: "General Services",
    email_address: "assistant@dts.local",
    username: "assistant",
    password: "Assistant@2026",
    status: "Approved",
    office_name: "Admin Department",
  },
];

async function seedOffices() {
  console.log("[1/3] Seeding offices...");
  for (const office of OFFICES) {
    await db.query(
      `INSERT INTO offices (office_name)
       VALUES (?)
       ON DUPLICATE KEY UPDATE office_name = VALUES(office_name)`,
      [office.name]
    );
  }
  const [rows] = await db.query("SELECT destination_office_id, office_name FROM offices");
  const map = new Map(rows.map((r) => [r.office_name, r.destination_office_id]));
  console.log(`      offices in database: ${rows.length}`);
  return map;
}

async function seedUsers(officeMap) {
  console.log("[2/3] Seeding user accounts...");
  for (const user of USERS) {
    const passwordHash = await hashPassword(user.password);
    const officeId = officeMap.get(user.office_name) || null;

    // Insert if missing, otherwise refresh the seeded fields so the documented
    // demo credentials always work after a rerun.
    await db.query(
      `INSERT INTO users
        (full_name, employee_id, role, department, email_address, username,
         password, password_hash, password_migrated, status, destination_office_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
       ON DUPLICATE KEY UPDATE
         full_name = VALUES(full_name),
         employee_id = VALUES(employee_id),
         role = VALUES(role),
         department = VALUES(department),
         email_address = VALUES(email_address),
         password = VALUES(password),
         password_hash = VALUES(password_hash),
         password_migrated = 1,
         status = VALUES(status),
         destination_office_id = VALUES(destination_office_id)`,
      [
        user.full_name,
        user.employee_id,
        user.role,
        user.department,
        user.email_address,
        user.username,
        user.password,
        passwordHash,
        user.status,
        officeId,
      ]
    );
    console.log(`      ${user.role.padEnd(16)} -> ${user.username}`);
  }
}

async function syncUserRoles() {
  console.log("[3/3] Mapping users to RBAC roles...");
  const [result] = await db.query(`
    INSERT INTO user_roles (user_id, role_id)
    SELECT u.user_id, r.role_id
    FROM users u
    JOIN roles r
      ON r.role_key = CASE
        WHEN LOWER(REPLACE(TRIM(u.role), ' ', '')) IN ('superadmin') THEN 'super_admin'
        WHEN LOWER(REPLACE(TRIM(u.role), ' ', '')) IN ('adminhead') THEN 'admin_head'
        WHEN LOWER(REPLACE(TRIM(u.role), ' ', '')) IN ('director') THEN 'director'
        WHEN LOWER(REPLACE(TRIM(u.role), ' ', '')) IN ('adminstaff','staff') THEN 'admin_staff'
        WHEN LOWER(REPLACE(TRIM(u.role), ' ', '')) IN ('adminassistant') THEN 'admin_assistant'
        ELSE NULL
      END
    LEFT JOIN user_roles ur
      ON ur.user_id = u.user_id
     AND ur.role_id = r.role_id
    WHERE r.role_id IS NOT NULL
      AND ur.user_id IS NULL
  `);
  console.log(`      new user_roles rows inserted: ${result.affectedRows}`);
}

function printSummary() {
  console.log("");
  console.log("============================================================");
  console.log(" Seed complete. Demo credentials (change after first login):");
  console.log("============================================================");
  for (const u of USERS) {
    console.log(
      `  ${u.role.padEnd(16)}  username: ${u.username.padEnd(12)}  password: ${u.password}`
    );
  }
  console.log("============================================================");
}

(async () => {
  try {
    const officeMap = await seedOffices();
    await seedUsers(officeMap);
    await syncUserRoles();
    printSummary();
    process.exit(0);
  } catch (err) {
    console.error("\n[seed] ERROR:", err.message);
    if (err.code) console.error("       code:", err.code);
    if (err.sqlMessage) console.error("       sql :", err.sqlMessage);
    console.error(
      "\nMake sure schema.sql and migrations/001_enterprise_security.sql have run first."
    );
    process.exit(1);
  }
})();
