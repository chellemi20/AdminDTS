const jwt = require("jsonwebtoken");
const config = require("../config.cjs");

function createAuthToken(user) {
  return jwt.sign(
    {
      sub: user.user_id,
      role: user.role,
      fullName: user.full_name,
    },
    config.jwtSecret,
    { expiresIn: config.jwtExpiry }
  );
}

function verifyAuthToken(token) {
  return jwt.verify(token, config.jwtSecret);
}

module.exports = {
  createAuthToken,
  verifyAuthToken,
};
