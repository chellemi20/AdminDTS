function requireFields(fields) {
  return (req, res, next) => {
    const body = req.body || {};
    const missing = fields.filter((key) => {
      const value = body[key];
      return value === undefined || value === null || value === "";
    });
    if (missing.length) {
      return res.status(400).json({ error: `Missing required fields: ${missing.join(", ")}` });
    }
    return next();
  };
}

module.exports = {
  requireFields,
};
