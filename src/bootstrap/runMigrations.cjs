const fs = require("fs");
const path = require("path");
const db = require("../db.cjs");

function splitSqlStatements(sql) {
  return sql
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);
}

async function runMigrations() {
  const migrationsDir = path.join(__dirname, "..", "..", "migrations");
  if (!fs.existsSync(migrationsDir)) return;
  const files = fs
    .readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();

  for (const file of files) {
    const fullPath = path.join(migrationsDir, file);
    const sql = fs.readFileSync(fullPath, "utf8");
    const statements = splitSqlStatements(sql);
    for (const statement of statements) {
      try {
        await db.query(statement);
      } catch (error) {
        const message = String(error.message || "");
        const isSafeDuplicate =
          message.includes("Duplicate key name") ||
          message.includes("already exists") ||
          message.includes("Duplicate column name");
        if (!isSafeDuplicate) {
          console.error(`Migration failed in ${file}:`, statement);
          throw error;
        }
      }
    }
  }
  console.log("Migrations complete.");
}

module.exports = runMigrations;
