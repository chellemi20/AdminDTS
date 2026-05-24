
const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const util = require("util");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const archiver = require("archiver");
const mammoth = require("mammoth");

const db = require("./src/db.cjs");
const config = require("./src/config.cjs");
const requestLogger = require("./src/middleware/requestLogger.cjs");
const { requireAuth } = require("./src/middleware/auth.cjs");
const { requireFields } = require("./src/middleware/validators.cjs");
const { hashPassword, comparePassword } = require("./src/security/passwords.cjs");
const { createAuthToken } = require("./src/security/tokens.cjs");
const {
  canManageApprovals,
  canRunBackups,
  canViewAuditLogs,
  isMonitoringOnlyRole,
  canViewDocument,
} = require("./src/security/rbac.cjs");
const { logAudit } = require("./src/services/auditService.cjs");
const runMigrations = require("./src/bootstrap/runMigrations.cjs");

const mkdir = util.promisify(fs.mkdir);
const writeFile = util.promisify(fs.writeFile);

const app = express();
let httpServer = null;
let keepAliveTimer = null;

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: true, credentials: false }));
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));
app.use(requestLogger);

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/login", authLimiter);
app.use("/api/auth/login", authLimiter);

const diskStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, config.documentsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const safeExt = ext || ".bin";
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${safeExt}`);
  },
});
const uploadDocument = multer({
  storage: diskStorage,
  limits: { fileSize: 25 * 1024 * 1024 },
});

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return String(forwarded).split(",")[0].trim();
  return req.socket?.remoteAddress || req.ip || "unknown";
}

function hideSensitiveUserFields(user) {
  const clone = { ...user };
  delete clone.password;
  delete clone.password_hash;
  delete clone.password_migrated;
  return clone;
}

function makeTrackingNumber() {
  return `DA-${new Date().getFullYear()}-${Math.floor(10000 + Math.random() * 90000)}`;
}

const OFFICE_DIRECTORY = [
  "PMED",
  "PRDP",
  "RSBSA",
  "RAED",
  "Research Office",
  "Finance Accounting",
  "Admin Department",
  "Regional Executive Director",
  "Records",
  "Operations",
];

const OFFICE_ALIASES = [
  ["Admin Office", "Admin Department"],
  ["General Services Division", "Admin Department"],
  ["Records Section", "Records"],
  ["Finance and Administrative Division", "Finance Accounting"],
  ["Office of the Director", "Regional Executive Director"],
];

function detectMime(filePath) {
  const ext = path.extname(filePath || "").toLowerCase();
  if (ext === ".pdf") return "application/pdf";
  if (ext === ".png") return "image/png";
  if (ext === ".jpg" || ext === ".jpeg") return "image/jpeg";
  if (ext === ".doc") return "application/msword";
  if (ext === ".docx")
    return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
  return "application/octet-stream";
}

function resolveDocumentFilePath(doc) {
  if (!doc) return null;
  if (doc.storage_path && fs.existsSync(doc.storage_path)) return doc.storage_path;
  const fallback = path.join(__dirname, "uploads", doc.file_path || "");
  return fs.existsSync(fallback) ? fallback : null;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function sanitizePreviewHtml(html) {
  return String(html || "")
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "")
    .replace(/\son\w+="[^"]*"/gi, "")
    .replace(/\son\w+='[^']*'/gi, "")
    .replace(/\s(href|src)=["']javascript:[^"']*["']/gi, "");
}

function sha256FromBuffer(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function isRecordsUser(user) {
  const role = String(user?.role || "").toLowerCase().replace(/\s+/g, "");
  const department = String(user?.department || "").toLowerCase();
  return role === "records" || role === "recordsstaff" || department.includes("records");
}

function denyMonitoringOnlyWrites(req, res) {
  if (!isMonitoringOnlyRole(req.auth?.user?.role)) return false;
  res.status(403).json({ error: "Super Admin is monitoring-only and cannot modify operational data." });
  return true;
}

function blockMonitoringOnlyWrites(req, res, next) {
  if (denyMonitoringOnlyWrites(req, res)) return;
  next();
}

function sha256FromFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

async function findUserAclGrant(docId, userId) {
  const [aclRows] = await db.query(
    `SELECT acl_id FROM document_acl
     WHERE doc_id = ? AND user_id = ? AND status = 'active'
       AND (expires_at IS NULL OR expires_at > NOW())
     LIMIT 1`,
    [docId, userId]
  );
  return !!aclRows.length;
}

async function loadDocumentById(docId) {
  const [rows] = await db.query(
    `SELECT d.*, o.office_name AS destination
     FROM documents d
     LEFT JOIN offices o ON o.destination_office_id = d.destination_office_id
     WHERE d.doc_id = ?
     LIMIT 1`,
    [docId]
  );
  return rows.length ? rows[0] : null;
}

async function userCanViewDocument(user, document) {
  if (["Records Review", "Pending"].includes(document?.current_status) && isRecordsUser(user)) return true;
  const hasAclGrant = await findUserAclGrant(document.doc_id, user.user_id);
  return canViewDocument({ user, document, hasAclGrant });
}

async function logDocumentAction(req, action, targetId, metadata) {
  await logAudit({
    actorUserId: req.auth?.user?.user_id || null,
    actorRole: req.auth?.user?.role || null,
    action,
    targetType: "document",
    targetId,
    ipAddress: getClientIp(req),
    metadata,
  });
}

async function syncOfficeDirectory() {
  for (const [oldName, newName] of OFFICE_ALIASES) {
    const [oldRows] = await db.query(
      "SELECT destination_office_id FROM offices WHERE office_name = ? LIMIT 1",
      [oldName]
    );
    if (!oldRows.length) continue;

    const oldId = oldRows[0].destination_office_id;
    const [newRows] = await db.query(
      "SELECT destination_office_id FROM offices WHERE office_name = ? LIMIT 1",
      [newName]
    );

    if (!newRows.length) {
      await db.query("UPDATE offices SET office_name = ? WHERE destination_office_id = ?", [
        newName,
        oldId,
      ]);
      continue;
    }

    const newId = newRows[0].destination_office_id;
    await db.query("UPDATE users SET destination_office_id = ? WHERE destination_office_id = ?", [
      newId,
      oldId,
    ]);
    await db.query(
      "UPDATE documents SET destination_office_id = ? WHERE destination_office_id = ?",
      [newId, oldId]
    );
    await db.query("DELETE FROM offices WHERE destination_office_id = ?", [oldId]);
  }

  for (const officeName of OFFICE_DIRECTORY) {
    await db.query(
      `INSERT INTO offices (office_name)
       VALUES (?)
       ON DUPLICATE KEY UPDATE office_name = VALUES(office_name)`,
      [officeName]
    );
  }
}

async function getOfficeDirectory() {
  const placeholders = OFFICE_DIRECTORY.map(() => "?").join(", ");
  const [rows] = await db.query(
    `SELECT destination_office_id, office_name
     FROM offices
     WHERE office_name IN (${placeholders})
     ORDER BY FIELD(office_name, ${placeholders})`,
    [...OFFICE_DIRECTORY, ...OFFICE_DIRECTORY]
  );
  return rows;
}

async function createNotification({ userId = null, type, refId = null, title, description = null }) {
  await db.query(
    `INSERT INTO notifications
     (user_id, type, ref_id, title, description, is_read, created_at)
     VALUES (?, ?, ?, ?, ?, 0, NOW())`,
    [userId, type, refId, title, description]
  );
}

async function notifyAllUsers({ type, refId = null, title, description = null }) {
  try {
    const [users] = await db.query(
      "SELECT user_id FROM users WHERE status = 'Approved'"
    );
    const userIds = users
      .map((user) => Number(user.user_id))
      .filter((userId) => Number.isFinite(userId));

    if (!userIds.length) {
      await createNotification({ type, refId, title, description });
      return;
    }

    const placeholders = userIds.map(() => "(?, ?, ?, ?, ?, 0, NOW())").join(", ");
    const params = [];
    for (const userId of userIds) {
      params.push(userId, type, refId, title, description);
    }
    await db.query(
      `INSERT INTO notifications
       (user_id, type, ref_id, title, description, is_read, created_at)
       VALUES ${placeholders}`,
      params
    );
  } catch (error) {
    console.error("Notification write failed:", error.message);
  }
}

function formatActorName(user) {
  return user?.full_name || user?.username || "A user";
}

async function bootstrap() {
  await mkdir(config.documentsDir, { recursive: true });
  await mkdir(config.profileUploadsDir, { recursive: true });
  await mkdir(config.backupDir, { recursive: true });
  await runMigrations();
  await syncOfficeDirectory();
}

// serve profile/signature images only
app.use(
  "/uploads/users",
  express.static(path.join(__dirname, "uploads", "users"), { fallthrough: false })
);

async function handleLoginRequest(req, res) {
  try {
    const identifier = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const [rows] = await db.query(
      "SELECT * FROM users WHERE (username = ? OR email_address = ?) LIMIT 1",
      [identifier, identifier]
    );
    if (!rows.length) {
      return res.status(401).json({ error: "Invalid username/email or password." });
    }
    const user = rows[0];
    if (user.status !== "Approved") {
      return res.status(403).json({ error: "Account pending approval." });
    }

    let isValid = false;
    if (user.password_hash) {
      isValid = await comparePassword(password, user.password_hash);
    } else if (user.password) {
      isValid = password === user.password;
      if (isValid) {
        const nextHash = await hashPassword(password);
        await db.query(
          "UPDATE users SET password_hash = ?, password_migrated = 1 WHERE user_id = ?",
          [nextHash, user.user_id]
        );
      }
    }
    if (!isValid) {
      return res.status(401).json({ error: "Invalid username/email or password." });
    }

    try {
      await db.query("UPDATE users SET last_login = NOW() WHERE user_id = ?", [user.user_id]);
    } catch (error) {
      // Backward compatibility for databases that have not added users.last_login yet.
      if (String(error.message || "").toLowerCase().includes("unknown column")) {
        console.warn("users.last_login column missing; skipping last_login update.");
      } else {
        throw error;
      }
    }
    const token = createAuthToken(user);
    await logAudit({
      actorUserId: user.user_id,
      actorRole: user.role,
      action: "user.login",
      targetType: "user",
      targetId: user.user_id,
      ipAddress: getClientIp(req),
      metadata: { username: user.username },
    });
    return res.json({ success: true, token, user: hideSensitiveUserFields(user) });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

app.post("/api/auth/login", requireFields(["username", "password"]), handleLoginRequest);

// Compatibility route expected by existing frontend
app.post("/api/login", async (req, res) => {
  req.body = {
    username:
      req.body?.username ||
      req.body?.email ||
      req.body?.email_address ||
      req.body?.identifier ||
      "",
    password: req.body?.password || "",
  };
  if (!req.body.username || !req.body.password) {
    return res.status(400).json({ error: "Missing username/email or password." });
  }
  return handleLoginRequest(req, res);
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  return res.json({ user: hideSensitiveUserFields(req.auth.user) });
});

app.post(
  "/api/register",
  requireFields(["full_name", "employee_id", "role", "email_address", "password", "username"]),
  async (req, res) => {
    try {
      const {
        full_name,
        employee_id,
        role,
        email_address,
        password,
        username,
        department,
        destination_office_id,
        status,
      } = req.body;
      const destinationOfficeId = destination_office_id ? Number(destination_office_id) : null;
      let departmentName = department || "General Services";

      if (destinationOfficeId) {
        const [officeRows] = await db.query(
          "SELECT destination_office_id, office_name FROM offices WHERE destination_office_id = ? LIMIT 1",
          [destinationOfficeId]
        );
        if (!officeRows.length) {
          return res.status(400).json({ error: "Selected office/destination was not found." });
        }
        departmentName = officeRows[0].office_name;
      }

      const passwordHash = await hashPassword(String(password));
      const [result] = await db.query(
        `INSERT INTO users
         (full_name, employee_id, role, email_address, password, password_hash, password_migrated, username, department, destination_office_id, status)
         VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
        [
          full_name,
          employee_id,
          role,
          email_address,
          password,
          passwordHash,
          username,
          departmentName,
          destinationOfficeId,
          status || "Pending",
        ]
      );
      await logAudit({
        actorUserId: result.insertId,
        actorRole: role,
        action: "user.register",
        targetType: "user",
        targetId: result.insertId,
        ipAddress: getClientIp(req),
        metadata: {
          username,
          email_address,
          employee_id,
          destination_office_id: destinationOfficeId,
          status: status || "Pending",
        },
      });
      await notifyAllUsers({
        type: "user_registration",
        refId: result.insertId,
        title: "New Account Registration",
        description: `${full_name} submitted a ${role} account for approval.`,
      });
      return res.status(201).json({ success: true, user_id: result.insertId });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  }
);

app.get("/api/public/offices", async (req, res) => {
  try {
    const rows = await getOfficeDirectory();
    return res.json(rows);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/offices", requireAuth, async (req, res) => {
  try {
    const rows = await getOfficeDirectory();
    return res.json(rows);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/documents", requireAuth, blockMonitoringOnlyWrites, uploadDocument.single("file"), async (req, res) => {
  try {
    if (denyMonitoringOnlyWrites(req, res)) return;
    const user = req.auth.user;
    const body = req.body || {};
    const tracking_number = makeTrackingNumber();
    const title = String(body.title || body.document_title || "Untitled Document");
    const destinationOfficeId = body.destination_office_id
      ? Number(body.destination_office_id)
      : null;
    const storagePath = req.file
      ? req.file.path
      : body.storage_path
      ? String(body.storage_path)
      : null;
    const legacyFilePath = req.file
      ? req.file.filename
      : body.file_path
      ? String(body.file_path)
      : "no-file.pdf";

    let fileHash = null;
    if (storagePath && fs.existsSync(storagePath)) {
      fileHash = await sha256FromFile(storagePath);
    }

    const [result] = await db.query(
      `INSERT INTO documents
       (tracking_number, title, category, description, priority, destination_office_id, due_date, sender_id, owner_id, current_status, file_path, storage_path, file_hash_sha256, visibility_scope)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        tracking_number,
        title,
        body.category || null,
        body.description || null,
        body.priority || "Normal",
        destinationOfficeId,
        body.due_date || null,
        user.user_id,
        user.user_id,
        "Records Review",
        legacyFilePath,
        storagePath,
        fileHash,
        body.visibility_scope || "destination",
      ]
    );
    const docId = result.insertId;

    if (storagePath && fileHash) {
      await db.query(
        `INSERT INTO document_versions
         (doc_id, file_path, file_hash_sha256, version_no, created_by, created_at)
         VALUES (?, ?, ?, 1, ?, NOW())`,
        [docId, storagePath, fileHash, user.user_id]
      );
    }

    await logDocumentAction(req, "document.upload", docId, {
      tracking_number,
      title,
      destination_office_id: destinationOfficeId,
    });
    await notifyAllUsers({
      type: "document_upload",
      refId: docId,
      title: "New Document Route",
      description: `${formatActorName(user)} initialized route ${tracking_number} for ${title}.`,
    });

    return res.status(201).json({ success: true, doc_id: docId, tracking_number });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/documents", requireAuth, async (req, res) => {
  try {
    const user = req.auth.user;
    const [rows] = await db.query(
      `SELECT d.*, o.office_name AS destination
       FROM documents d
       LEFT JOIN offices o ON d.destination_office_id = o.destination_office_id
       ORDER BY d.created_at DESC`
    );
    const decorated = [];
    for (const row of rows) {
      const hasAclGrant = await findUserAclGrant(row.doc_id, user.user_id);
      const canView = canViewDocument({ user, document: row, hasAclGrant });
      decorated.push({
        ...row,
        can_view: canView,
        requires_access_request: !canView,
      });
    }
    return res.json(decorated);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/documents/:id", requireAuth, async (req, res) => {
  try {
    const doc = await loadDocumentById(Number(req.params.id));
    if (!doc) return res.status(404).json({ error: "Document not found." });
    const allowed = await userCanViewDocument(req.auth.user, doc);
    if (!allowed) {
      return res.status(403).json({
        error: "You do not have permission to view this document.",
        requires_access_request: true,
      });
    }
    return res.json(doc);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/documents/:id/file", requireAuth, async (req, res) => {
  try {
    const doc = await loadDocumentById(Number(req.params.id));
    if (!doc) return res.status(404).json({ error: "Document not found." });
    const allowed = await userCanViewDocument(req.auth.user, doc);
    if (!allowed) {
      return res.status(403).json({
        error: "You do not have access to open this document.",
        requires_access_request: true,
      });
    }
    const filePath = resolveDocumentFilePath(doc);
    if (!filePath) {
      return res.status(404).json({ error: "File was not found on storage." });
    }
    await logDocumentAction(req, "document.view", doc.doc_id, { mode: "file_stream" });
    res.setHeader("Content-Type", detectMime(filePath));
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Content-Disposition", `inline; filename="${path.basename(filePath)}"`);
    return fs.createReadStream(filePath).pipe(res);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/documents/:id/preview", requireAuth, async (req, res) => {
  try {
    const doc = await loadDocumentById(Number(req.params.id));
    if (!doc) return res.status(404).json({ error: "Document not found." });
    const allowed = await userCanViewDocument(req.auth.user, doc);
    if (!allowed) {
      return res.status(403).json({
        error: "You do not have access to preview this document.",
        requires_access_request: true,
      });
    }

    const filePath = resolveDocumentFilePath(doc);
    if (!filePath) {
      return res.status(404).json({ error: "File was not found on storage." });
    }

    const ext = path.extname(filePath).toLowerCase();
    const mime = detectMime(filePath);
    const filename = path.basename(filePath);

    if (ext === ".docx") {
      const result = await mammoth.convertToHtml({ path: filePath });
      const html = sanitizePreviewHtml(result.value);
      await logDocumentAction(req, "document.preview", doc.doc_id, { mode: "docx_html" });
      return res.json({
        type: "html",
        filename,
        title: doc.title,
        html,
        messages: result.messages || [],
      });
    }

    if ([".txt", ".csv", ".log"].includes(ext)) {
      const content = await fs.promises.readFile(filePath, "utf8");
      await logDocumentAction(req, "document.preview", doc.doc_id, { mode: "text" });
      return res.json({
        type: "html",
        filename,
        title: doc.title,
        html: `<pre>${escapeHtml(content)}</pre>`,
        messages: [],
      });
    }

    await logDocumentAction(req, "document.preview", doc.doc_id, { mode: "native", mime });
    return res.json({
      type: mime.startsWith("image/") ? "image" : mime === "application/pdf" ? "pdf" : "download",
      filename,
      title: doc.title,
      mime,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.put("/api/documents/:id/status", requireAuth, async (req, res) => {
  try {
    if (denyMonitoringOnlyWrites(req, res)) return;
    if (!canManageApprovals(req.auth.user.role)) {
      return res.status(403).json({ error: "Only Admin Head and Director can update status." });
    }
    const id = Number(req.params.id);
    const status = String(req.body.status || "").trim();
    const comment = req.body.comment || null;
    const signaturePosition = req.body.signaturePosition || null;
    if (!status) return res.status(400).json({ error: "status is required." });
    const doc = await loadDocumentById(id);
    if (!doc) return res.status(404).json({ error: "Document not found." });
    const [result] = await db.query(
      "UPDATE documents SET current_status = ?, admin_comment = ? WHERE doc_id = ?",
      [status, comment, id]
    );
    if (!result.affectedRows) return res.status(404).json({ error: "Document not found." });
    await logDocumentAction(req, "document.status.update", id, { status, comment, signaturePosition });
    const statusKey = status.toLowerCase();
    const notificationTitle = statusKey.includes("reject")
      ? "Document Rejected"
      : statusKey.includes("approve")
      ? "Document Approved"
      : "Document Status Updated";
    await notifyAllUsers({
      type: "document_status",
      refId: id,
      title: notificationTitle,
      description: `${formatActorName(req.auth.user)} set ${doc.tracking_number} - ${doc.title} to ${status}.`,
    });
    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/documents/:id/records-review", requireAuth, async (req, res) => {
  try {
    if (denyMonitoringOnlyWrites(req, res)) return;
    const id = Number(req.params.id);
    const user = req.auth.user;
    if (!isRecordsUser(user) && !canManageApprovals(user.role)) {
      return res.status(403).json({ error: "Only Records personnel can stamp received and release documents." });
    }
    const action = String(req.body?.action || "").toLowerCase();
    const comment = req.body?.comment || null;
    const stampPosition = req.body?.stampPosition || null;
    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ error: "action must be approve or reject." });
    }
    const doc = await loadDocumentById(id);
    if (!doc) return res.status(404).json({ error: "Document not found." });
    if (!["Records Review", "Pending"].includes(doc.current_status)) {
      return res.status(400).json({ error: "Only documents in Records Review can be processed by Records." });
    }
    const nextStatus = action === "approve" ? "For Review" : "Rejected";
    const [result] = await db.query(
      "UPDATE documents SET current_status = ?, admin_comment = ? WHERE doc_id = ?",
      [nextStatus, comment, id]
    );
    if (!result.affectedRows) return res.status(404).json({ error: "Document not found." });
    await logDocumentAction(req, action === "approve" ? "document.records.received" : "document.records.rejected", id, {
      status: nextStatus,
      comment,
      stampPosition,
      records_user_id: user.user_id,
      records_user_name: user.full_name,
    });
    await notifyAllUsers({
      type: "document_status",
      refId: id,
      title: action === "approve" ? "Document Stamped by Records" : "Document Rejected by Records",
      description:
        action === "approve"
          ? `${formatActorName(user)} stamped ${doc.tracking_number} - ${doc.title} as received and sent it for review.`
          : `${formatActorName(user)} rejected ${doc.tracking_number} - ${doc.title} from Records review.`,
    });
    return res.json({ success: true, status: nextStatus });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/documents/:id/access-requests", requireAuth, async (req, res) => {
  try {
    if (denyMonitoringOnlyWrites(req, res)) return;
    const docId = Number(req.params.id);
    const user = req.auth.user;
    const doc = await loadDocumentById(docId);
    if (!doc) return res.status(404).json({ error: "Document not found." });

    const alreadyAllowed = await userCanViewDocument(user, doc);
    if (alreadyAllowed) {
      return res.status(400).json({ error: "You already have access to this document." });
    }

    const [pendingRows] = await db.query(
      `SELECT request_id FROM document_access_requests
       WHERE doc_id = ? AND requester_id = ? AND status = 'pending'
       LIMIT 1`,
      [docId, user.user_id]
    );
    if (pendingRows.length) {
      return res.status(409).json({ error: "There is already a pending access request." });
    }

    const ownerId = Number(doc.owner_id || doc.sender_id);
    const [insert] = await db.query(
      `INSERT INTO document_access_requests
       (doc_id, requester_id, owner_id, status, reason, requested_at)
       VALUES (?, ?, ?, 'pending', ?, NOW())`,
      [docId, user.user_id, ownerId, req.body?.reason || null]
    );
    await logDocumentAction(req, "document.access_request.create", docId, {
      request_id: insert.insertId,
      owner_id: ownerId,
    });
    return res.status(201).json({ success: true, request_id: insert.insertId });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/access-requests/inbox", requireAuth, async (req, res) => {
  try {
    const user = req.auth.user;
    const [rows] = await db.query(
      `SELECT r.*, d.title AS document_title, d.tracking_number
       FROM document_access_requests r
       INNER JOIN documents d ON d.doc_id = r.doc_id
       WHERE r.owner_id = ? AND r.status = 'pending'
       ORDER BY r.requested_at DESC`,
      [user.user_id]
    );
    return res.json(rows);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/access-requests/:id/approve", requireAuth, async (req, res) => {
  try {
    if (denyMonitoringOnlyWrites(req, res)) return;
    const requestId = Number(req.params.id);
    const user = req.auth.user;
    const [rows] = await db.query(
      "SELECT * FROM document_access_requests WHERE request_id = ? LIMIT 1",
      [requestId]
    );
    if (!rows.length) return res.status(404).json({ error: "Request not found." });
    const request = rows[0];
    const canAct =
      Number(request.owner_id) === Number(user.user_id) || canManageApprovals(user.role);
    if (!canAct) return res.status(403).json({ error: "You cannot approve this request." });
    if (request.status !== "pending") {
      return res.status(400).json({ error: "Only pending requests can be approved." });
    }

    const hours = Number(req.body?.hours || config.accessGrantHoursDefault);
    await db.query(
      `UPDATE document_access_requests
       SET status = 'approved', reviewed_at = NOW(), reviewed_by = ?, decision_reason = ?, expires_at = DATE_ADD(NOW(), INTERVAL ? HOUR)
       WHERE request_id = ?`,
      [user.user_id, req.body?.decision_reason || null, hours, requestId]
    );
    await db.query(
      `INSERT INTO document_acl
       (doc_id, user_id, granted_by, grant_reason, status, granted_at, expires_at)
       VALUES (?, ?, ?, ?, 'active', NOW(), DATE_ADD(NOW(), INTERVAL ? HOUR))`,
      [
        request.doc_id,
        request.requester_id,
        user.user_id,
        req.body?.decision_reason || "Approved via request workflow",
        hours,
      ]
    );
    await logDocumentAction(req, "document.access_request.approve", request.doc_id, {
      request_id: requestId,
      requester_id: request.requester_id,
      hours,
    });
    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/access-requests/:id/deny", requireAuth, async (req, res) => {
  try {
    if (denyMonitoringOnlyWrites(req, res)) return;
    const requestId = Number(req.params.id);
    const user = req.auth.user;
    const [rows] = await db.query(
      "SELECT * FROM document_access_requests WHERE request_id = ? LIMIT 1",
      [requestId]
    );
    if (!rows.length) return res.status(404).json({ error: "Request not found." });
    const request = rows[0];
    const canAct =
      Number(request.owner_id) === Number(user.user_id) || canManageApprovals(user.role);
    if (!canAct) return res.status(403).json({ error: "You cannot deny this request." });
    if (request.status !== "pending") {
      return res.status(400).json({ error: "Only pending requests can be denied." });
    }
    await db.query(
      `UPDATE document_access_requests
       SET status = 'denied', reviewed_at = NOW(), reviewed_by = ?, decision_reason = ?
       WHERE request_id = ?`,
      [user.user_id, req.body?.decision_reason || null, requestId]
    );
    await logDocumentAction(req, "document.access_request.deny", request.doc_id, {
      request_id: requestId,
      requester_id: request.requester_id,
    });
    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/documents/:id/sign", requireAuth, async (req, res) => {
  try {
    if (denyMonitoringOnlyWrites(req, res)) return;
    const docId = Number(req.params.id);
    const user = req.auth.user;
    const doc = await loadDocumentById(docId);
    if (!doc) return res.status(404).json({ error: "Document not found." });
    const allowed = await userCanViewDocument(user, doc);
    if (!allowed) return res.status(403).json({ error: "You cannot sign this document." });

    const filePath =
      doc.storage_path && fs.existsSync(doc.storage_path)
        ? doc.storage_path
        : path.join(__dirname, "uploads", doc.file_path || "");
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "Document file missing; cannot sign." });
    }
    const docHash = await sha256FromFile(filePath);
    const signaturePath = user.signature_path || null;
    if (!signaturePath) {
      return res.status(400).json({
        error: "No saved signature for current user. Upload signature in settings first.",
      });
    }
    const signatureHash = crypto
      .createHash("sha256")
      .update(`${docHash}:${user.user_id}:${Date.now()}:${getClientIp(req)}`)
      .digest("hex");
    const [result] = await db.query(
      `INSERT INTO document_signatures
       (doc_id, signer_id, signer_name, signer_role, signature_image_path, signed_at, signer_ip, user_agent, doc_hash_sha256, signature_hash, is_revoked)
       VALUES (?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, 0)`,
      [
        docId,
        user.user_id,
        user.full_name,
        user.role,
        signaturePath,
        getClientIp(req),
        req.headers["user-agent"] || null,
        docHash,
        signatureHash,
      ]
    );
    await logDocumentAction(req, "document.signature.apply", docId, {
      signature_id: result.insertId,
      signature_hash: signatureHash,
      placement: req.body?.placement || null,
    });
    return res.status(201).json({ success: true, signature_id: result.insertId });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/documents/:id/signatures", requireAuth, async (req, res) => {
  try {
    const docId = Number(req.params.id);
    const doc = await loadDocumentById(docId);
    if (!doc) return res.status(404).json({ error: "Document not found." });
    const allowed = await userCanViewDocument(req.auth.user, doc);
    if (!allowed) return res.status(403).json({ error: "You cannot view signatures." });
    const [rows] = await db.query(
      `SELECT signature_id, doc_id, signer_id, signer_name, signer_role, signature_image_path, signed_at, signer_ip, user_agent, doc_hash_sha256, signature_hash, is_revoked
       FROM document_signatures
       WHERE doc_id = ?
       ORDER BY signed_at ASC`,
      [docId]
    );
    const filePath =
      doc.storage_path && fs.existsSync(doc.storage_path)
        ? doc.storage_path
        : path.join(__dirname, "uploads", doc.file_path || "");
    const currentHash = fs.existsSync(filePath) ? await sha256FromFile(filePath) : null;
    const mapped = rows.map((row) => ({
      ...row,
      tamper_detected: currentHash ? currentHash !== row.doc_hash_sha256 : true,
    }));
    return res.json({ signatures: mapped, current_document_hash: currentHash });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/documents/:id/signatures/verify", requireAuth, async (req, res) => {
  try {
    const docId = Number(req.params.id);
    const doc = await loadDocumentById(docId);
    if (!doc) return res.status(404).json({ error: "Document not found." });
    const allowed = await userCanViewDocument(req.auth.user, doc);
    if (!allowed) return res.status(403).json({ error: "You cannot verify signatures." });
    const [rows] = await db.query(
      "SELECT signature_id, doc_hash_sha256, is_revoked FROM document_signatures WHERE doc_id = ?",
      [docId]
    );
    const filePath =
      doc.storage_path && fs.existsSync(doc.storage_path)
        ? doc.storage_path
        : path.join(__dirname, "uploads", doc.file_path || "");
    const currentHash = fs.existsSync(filePath) ? await sha256FromFile(filePath) : null;
    const total = rows.length;
    const revoked = rows.filter((r) => Number(r.is_revoked) === 1).length;
    const tampered = rows.some((r) => currentHash && r.doc_hash_sha256 !== currentHash);
    return res.json({
      total_signatures: total,
      revoked_signatures: revoked,
      tamper_detected: tampered,
      current_document_hash: currentHash,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

async function exportDatabaseSnapshot(targetDir) {
  const snapshotPath = path.join(targetDir, "database-snapshot.json");
  const [tableRows] = await db.query("SHOW TABLES");
  const keyName = Object.keys(tableRows[0] || {})[0];
  const payload = {};
  for (const row of tableRows) {
    const tableName = row[keyName];
    const [records] = await db.query(`SELECT * FROM \`${tableName}\``);
    payload[tableName] = records;
  }
  await writeFile(snapshotPath, JSON.stringify(payload, null, 2), "utf8");
  return snapshotPath;
}

async function createZipArchive(sourceDir, zipPath) {
  await new Promise((resolve, reject) => {
    const output = fs.createWriteStream(zipPath);
    const archive = archiver("zip", { zlib: { level: 9 } });
    output.on("close", resolve);
    output.on("error", reject);
    archive.on("error", reject);
    archive.pipe(output);
    archive.directory(sourceDir, false);
    archive.finalize();
  });
}

app.post("/api/admin/backups/run", requireAuth, async (req, res) => {
  try {
    if (denyMonitoringOnlyWrites(req, res)) return;
    if (!canRunBackups(req.auth.user.role)) {
      return res.status(403).json({ error: "Only Admin Head and Director can run backups." });
    }
    const [ins] = await db.query(
      "INSERT INTO backups (triggered_by, status, created_at) VALUES (?, 'running', NOW())",
      [req.auth.user.user_id]
    );
    const backupId = ins.insertId;
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const workDir = path.join(config.backupDir, `backup-${backupId}-${stamp}`);
    await mkdir(workDir, { recursive: true });

    await exportDatabaseSnapshot(workDir);
    if (fs.existsSync(config.documentsDir)) {
      fs.cpSync(config.documentsDir, path.join(workDir, "documents"), { recursive: true });
    }
    if (fs.existsSync(path.join(__dirname, "uploads", "users"))) {
      fs.cpSync(path.join(__dirname, "uploads", "users"), path.join(workDir, "users"), {
        recursive: true,
      });
    }
    const zipPath = path.join(config.backupDir, `backup-${backupId}-${stamp}.zip`);
    await createZipArchive(workDir, zipPath);
    const size = fs.statSync(zipPath).size;
    await db.query(
      "UPDATE backups SET status = 'completed', archive_path = ?, size_bytes = ?, completed_at = NOW() WHERE backup_id = ?",
      [zipPath, size, backupId]
    );
    await logAudit({
      actorUserId: req.auth.user.user_id,
      actorRole: req.auth.user.role,
      action: "system.backup.run",
      targetType: "backup",
      targetId: backupId,
      ipAddress: getClientIp(req),
      metadata: { zipPath, size },
    });
    return res.json({ success: true, backup_id: backupId, archive_path: zipPath, size_bytes: size });
  } catch (error) {
    console.error("Backup error:", error.message);
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/admin/backups", requireAuth, async (req, res) => {
  try {
    if (!canRunBackups(req.auth.user.role)) {
      return res.status(403).json({ error: "Only Admin Head and Director can view backups." });
    }
    const [rows] = await db.query(
      "SELECT backup_id, triggered_by, archive_path, status, size_bytes, created_at, completed_at, error FROM backups ORDER BY created_at DESC LIMIT 100"
    );
    return res.json(rows);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/admin/audit-logs", requireAuth, async (req, res) => {
  try {
    if (!canViewAuditLogs(req.auth.user.role)) {
      return res.status(403).json({ error: "Only Super Admin can view activity logs." });
    }
    const limit = Math.min(Number(req.query.limit || 100), 500);
    const [rows] = await db.query(
      `SELECT l.audit_id, l.actor_user_id, u.full_name AS actor_name,
              l.actor_role, l.action, l.target_type, l.target_id,
              l.ip_address, l.metadata_json, l.created_at
       FROM document_audit_logs l
       LEFT JOIN users u ON u.user_id = l.actor_user_id
       ORDER BY l.created_at DESC
       LIMIT ?`,
      [limit]
    );
    return res.json(
      rows.map((row) => ({
        ...row,
        metadata:
          typeof row.metadata_json === "string"
            ? JSON.parse(row.metadata_json || "{}")
            : row.metadata_json || null,
      }))
    );
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/admin/backups/:id/restore", requireAuth, async (req, res) => {
  try {
    if (denyMonitoringOnlyWrites(req, res)) return;
    if (!canRunBackups(req.auth.user.role)) {
      return res.status(403).json({ error: "Only Admin Head and Director can restore backups." });
    }
    const id = Number(req.params.id);
    const [rows] = await db.query("SELECT * FROM backups WHERE backup_id = ? LIMIT 1", [id]);
    if (!rows.length) return res.status(404).json({ error: "Backup not found." });
    const backup = rows[0];
    return res.json({
      success: true,
      message:
        "Restore workflow requires controlled manual operation. Backup package is available for operator restore.",
      backup,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/admin/pending-users", requireAuth, async (req, res) => {
  try {
    if (!canManageApprovals(req.auth.user.role)) {
      return res.status(403).json({ error: "Only Admin Head and Director can view pending users." });
    }
    const [rows] = await db.query(
      `SELECT u.user_id, u.full_name, u.employee_id, u.role,
              COALESCE(o.office_name, u.department) AS department,
              o.office_name AS destination_office_name,
              u.destination_office_id, u.username, u.email_address, u.status
       FROM users u
       LEFT JOIN offices o ON o.destination_office_id = u.destination_office_id
       WHERE u.status = 'Pending'
       ORDER BY u.user_id DESC`
    );
    return res.json(rows);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.put("/api/admin/update-status", requireAuth, async (req, res) => {
  try {
    if (denyMonitoringOnlyWrites(req, res)) return;
    if (!canManageApprovals(req.auth.user.role)) {
      return res.status(403).json({ error: "Only Admin Head and Director can update users." });
    }
    const { userId, newStatus } = req.body || {};
    if (!userId || !newStatus) return res.status(400).json({ error: "Missing parameters" });
    const [userRows] = await db.query(
      "SELECT user_id, full_name, username, role FROM users WHERE user_id = ? LIMIT 1",
      [userId]
    );
    if (!userRows.length) return res.status(404).json({ error: "User not found." });
    const targetUser = userRows[0];
    const [result] = await db.query("UPDATE users SET status = ? WHERE user_id = ?", [
      newStatus,
      userId,
    ]);
    if (!result.affectedRows) return res.status(404).json({ error: "User not found." });
    await logAudit({
      actorUserId: req.auth.user.user_id,
      actorRole: req.auth.user.role,
      action: "user.status.update",
      targetType: "user",
      targetId: userId,
      ipAddress: getClientIp(req),
      metadata: { status: newStatus },
    });
    await notifyAllUsers({
      type: "user_status",
      refId: Number(userId),
      title: `User ${newStatus}`,
      description: `${formatActorName(req.auth.user)} marked ${targetUser.full_name || targetUser.username} as ${newStatus}.`,
    });
    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/notifications", requireAuth, async (req, res) => {
  try {
    const userId = req.auth.user.user_id;
    const [rows] = await db.query(
      `SELECT id, type, ref_id, title, description, is_read, created_at
       FROM notifications
       WHERE user_id = ? OR user_id IS NULL
       ORDER BY created_at DESC
       LIMIT 30`,
      [userId]
    );
    return res.json(
      rows.map((r) => ({
        id: String(r.id),
        type: r.type,
        refId: r.ref_id,
        title: r.title,
        description: r.description,
        time: r.created_at,
        isRead: !!r.is_read,
      }))
    );
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/notifications/mark-read", requireAuth, async (req, res) => {
  try {
    if (!req.body?.id) return res.status(400).json({ error: "Missing id" });
    await db.query(
      "UPDATE notifications SET is_read = 1 WHERE id = ? AND (user_id = ? OR user_id IS NULL)",
      [req.body.id, req.auth.user.user_id]
    );
    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/notifications/mark-all", requireAuth, async (req, res) => {
  try {
    await db.query(
      "UPDATE notifications SET is_read = 1 WHERE is_read = 0 AND (user_id = ? OR user_id IS NULL)",
      [req.auth.user.user_id]
    );
    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/users", requireAuth, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT u.user_id, u.full_name, u.role,
              COALESCE(o.office_name, u.department) AS department,
              o.office_name AS destination_office_name,
              u.username, u.email_address, u.status, u.last_login,
              u.profile_picture_path, u.signature_path, u.destination_office_id
       FROM users u
       LEFT JOIN offices o ON o.destination_office_id = u.destination_office_id
       WHERE u.status = 'Approved'
       ORDER BY u.full_name`
    );
    return res.json(rows);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/messages", requireAuth, async (req, res) => {
  try {
    const userId = Number(req.query.userId);
    const withUser = Number(req.query.withUser);
    if (!userId || !withUser) return res.status(400).json({ error: "Missing parameters" });
    if (userId !== Number(req.auth.user.user_id)) {
      return res.status(403).json({ error: "Cannot read another user's inbox." });
    }
    const [rows] = await db.query(
      `SELECT msg_id, sender_id, receiver_id, message_text AS text, created_at
       FROM messages
       WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
       ORDER BY created_at ASC`,
      [userId, withUser, withUser, userId]
    );
    return res.json(rows);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/messages", requireAuth, async (req, res) => {
  try {
    if (denyMonitoringOnlyWrites(req, res)) return;
    const senderId = Number(req.body?.sender_id);
    const receiverId = Number(req.body?.receiver_id);
    const text = String(req.body?.text || "");
    if (!senderId || !receiverId || !text) {
      return res.status(400).json({ error: "Missing parameters" });
    }
    if (senderId !== Number(req.auth.user.user_id)) {
      return res.status(403).json({ error: "Sender identity mismatch." });
    }
    const [result] = await db.query(
      "INSERT INTO messages (sender_id, receiver_id, message_text, created_at) VALUES (?, ?, ?, NOW())",
      [senderId, receiverId, text]
    );
    return res.status(201).json({ success: true, msg_id: result.insertId });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/users/:id/upload-profile", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (id !== Number(req.auth.user.user_id) && !canManageApprovals(req.auth.user.role)) {
      return res.status(403).json({ error: "You cannot update this profile." });
    }
    const { filename, data } = req.body || {};
    if (!filename || !data) return res.status(400).json({ error: "Missing file data or filename" });
    const matches = String(data).match(/^data:(.+);base64,(.*)$/);
    const base64 = matches ? matches[2] : data;
    const buffer = Buffer.from(base64, "base64");
    const userDir = path.join(__dirname, "uploads", "users", String(id));
    await mkdir(userDir, { recursive: true });
    const savePath = path.join(userDir, filename);
    await writeFile(savePath, buffer);
    const publicPath = `/uploads/users/${id}/${filename}`;
    await db.query("UPDATE users SET profile_picture_path = ? WHERE user_id = ?", [publicPath, id]);
    await logAudit({
      actorUserId: req.auth.user.user_id,
      actorRole: req.auth.user.role,
      action: "user.profile_image.upload",
      targetType: "user",
      targetId: id,
      ipAddress: getClientIp(req),
      metadata: { publicPath },
    });
    return res.json({ success: true, path: publicPath });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/users/:id/upload-signature", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (id !== Number(req.auth.user.user_id) && !canManageApprovals(req.auth.user.role)) {
      return res.status(403).json({ error: "You cannot update this signature." });
    }
    const { filename, data } = req.body || {};
    if (!filename || !data) return res.status(400).json({ error: "Missing file data or filename" });
    const matches = String(data).match(/^data:(.+);base64,(.*)$/);
    const base64 = matches ? matches[2] : data;
    const buffer = Buffer.from(base64, "base64");
    const userDir = path.join(__dirname, "uploads", "users", String(id));
    await mkdir(userDir, { recursive: true });
    const savePath = path.join(userDir, filename);
    await writeFile(savePath, buffer);
    const publicPath = `/uploads/users/${id}/${filename}`;
    await db.query("UPDATE users SET signature_path = ? WHERE user_id = ?", [publicPath, id]);
    return res.json({ success: true, path: publicPath });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.put("/api/users/:id/password", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { currentPassword, newPassword } = req.body || {};
    if (!newPassword || String(newPassword).length < 6) {
      return res.status(400).json({ error: "newPassword must be at least 6 characters." });
    }
    if (id !== Number(req.auth.user.user_id) && !canManageApprovals(req.auth.user.role)) {
      return res.status(403).json({ error: "You cannot change this user's password." });
    }
    const [rows] = await db.query(
      "SELECT user_id, password, password_hash FROM users WHERE user_id = ? LIMIT 1",
      [id]
    );
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    const target = rows[0];
    if (id === Number(req.auth.user.user_id)) {
      let ok = false;
      if (target.password_hash) ok = await comparePassword(String(currentPassword || ""), target.password_hash);
      else ok = String(currentPassword || "") === String(target.password || "");
      if (!ok) return res.status(403).json({ error: "Current password is incorrect" });
    }
    const nextHash = await hashPassword(String(newPassword));
    await db.query(
      "UPDATE users SET password = ?, password_hash = ?, password_migrated = 1 WHERE user_id = ?",
      [String(newPassword), nextHash, id]
    );
    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "dts-backend", time: new Date().toISOString() });
});

app.get("/analytics-summary", requireAuth, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT
         COUNT(*) AS total_documents,
         SUM(CASE WHEN current_status = 'Pending' THEN 1 ELSE 0 END) AS pending_documents,
         SUM(CASE WHEN current_status = 'Approved' THEN 1 ELSE 0 END) AS approved_documents,
         SUM(CASE WHEN current_status = 'Rejected' THEN 1 ELSE 0 END) AS rejected_documents
       FROM documents`
    );
    const summary = rows[0] || {};
    return res.json({
      total_documents: Number(summary.total_documents || 0),
      pending_documents: Number(summary.pending_documents || 0),
      approved_documents: Number(summary.approved_documents || 0),
      rejected_documents: Number(summary.rejected_documents || 0),
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.use((err, req, res, next) => {
  console.error("Unhandled server error:", err);
  return res.status(500).json({ error: "Internal Server Error" });
});

bootstrap()
  .then(() => {
    httpServer = app.listen(config.port, () => {
      console.log(`Server running on http://localhost:${config.port}`);
    });
    keepAliveTimer = setInterval(() => {}, 60 * 60 * 1000);
  })
  .catch((error) => {
    console.error("Failed to bootstrap backend:", error);
    process.exit(1);
  });
