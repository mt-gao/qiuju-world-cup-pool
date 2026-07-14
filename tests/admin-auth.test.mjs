import assert from "node:assert/strict";
import test from "node:test";

import {
  ADMIN_SESSION_COOKIE_NAME,
  createAdminSessionToken,
  DEFAULT_ADMIN_PIN,
  hasValidAdminSession,
  resolveAdminPin,
  verifyAdminPin,
  verifyAdminSessionToken,
} from "../lib/admin-auth.ts";

test("uses 6666 by default and rejects malformed configured PINs", () => {
  assert.equal(DEFAULT_ADMIN_PIN, "6666");
  assert.equal(resolveAdminPin(undefined), "6666");
  assert.equal(resolveAdminPin(""), "6666");
  assert.equal(resolveAdminPin(" 2468 "), "2468");
  assert.throws(() => resolveAdminPin("123"), /exactly 4 digits/);
  assert.throws(() => resolveAdminPin("12a4"), /exactly 4 digits/);
});

test("verifies a four-digit PIN without accepting alternate shapes", async () => {
  assert.equal(await verifyAdminPin("2468", "2468"), true);
  assert.equal(await verifyAdminPin("2467", "2468"), false);
  assert.equal(await verifyAdminPin(2468, "2468"), false);
  assert.equal(await verifyAdminPin("02468", "2468"), false);
});

test("creates deterministic signed tokens that rotate with the PIN", async () => {
  const first = await createAdminSessionToken("2468");
  const second = await createAdminSessionToken("2468");
  const rotated = await createAdminSessionToken("1357");

  assert.equal(first, second);
  assert.notEqual(first, rotated);
  assert.equal(await verifyAdminSessionToken(first, "2468"), true);
  assert.equal(await verifyAdminSessionToken(first, "1357"), false);
  assert.equal(
    await verifyAdminSessionToken(`${first.slice(0, -1)}A`, "2468"),
    false,
  );
});

test("reads the signed session from the request cookie", async () => {
  const token = await createAdminSessionToken("2468");
  const authenticatedRequest = new Request("https://example.test/api/state", {
    headers: {
      cookie: `unrelated=value; ${ADMIN_SESSION_COOKIE_NAME}=${token}`,
    },
  });
  const anonymousRequest = new Request("https://example.test/api/state");

  assert.equal(
    await hasValidAdminSession(authenticatedRequest, "2468"),
    true,
  );
  assert.equal(await hasValidAdminSession(authenticatedRequest, "1357"), false);
  assert.equal(await hasValidAdminSession(anonymousRequest, "2468"), false);
});
