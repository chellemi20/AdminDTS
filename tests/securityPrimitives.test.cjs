const assert = require("assert");
const { hashPassword, comparePassword } = require("../src/security/passwords.cjs");
const { createAuthToken, verifyAuthToken } = require("../src/security/tokens.cjs");

async function run() {
  const plain = "StrongPass123!";
  const hashed = await hashPassword(plain);
  assert.notStrictEqual(hashed, plain, "Password hash must not equal plaintext");
  assert.strictEqual(await comparePassword(plain, hashed), true, "Hash comparison should pass");
  assert.strictEqual(await comparePassword("wrong", hashed), false, "Wrong password must fail");

  const token = createAuthToken({ user_id: 10, role: "Director", full_name: "Jane Director" });
  const payload = verifyAuthToken(token);
  assert.strictEqual(payload.sub, 10, "Token sub should match user ID");
  assert.strictEqual(payload.role, "Director", "Token role should match");

  console.log("securityPrimitives.test.cjs: all assertions passed");
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
