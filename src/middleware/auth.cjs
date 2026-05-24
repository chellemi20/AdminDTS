const db = require("../db.cjs");
const { verifyAuthToken } = require("../security/tokens.cjs");

function extractBearerToken(req) {
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice("Bearer ".length);
  return null;
}

async function requireAuth(req, res, next) {
  try {
    const token = extractBearerToken(req);
    if (!token) {
      return res.status(401).json({ error: "Authentication token is required." });
    }
    const payload = verifyAuthToken(token);
    const [rows] = await db.query("SELECT * FROM users WHERE user_id = ? LIMIT 1", [payload.sub]);
    if (!rows.length) return res.status(401).json({ error: "User no longer exists." });
    const user = rows[0];
    if (user.status !== "Approved") {
      return res.status(403).json({ error: "Your account is not approved." });
    }
    req.auth = { user, tokenPayload: payload };
    return next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired authentication token." });
  }
}

module.exports = {
  requireAuth,
};
