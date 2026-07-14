export const DEFAULT_ADMIN_PIN = "6666";
export const ADMIN_SESSION_COOKIE_NAME = "qiuju_admin_session";

const ADMIN_PIN_PATTERN = /^\d{4}$/;
const SESSION_TOKEN_VERSION = "v1";
const SESSION_SIGNING_CONTEXT = "qiuju-world-cup-pool:admin-session:v1";
const textEncoder = new TextEncoder();

export function isAdminPin(value: unknown): value is string {
  return typeof value === "string" && ADMIN_PIN_PATTERN.test(value);
}

export function resolveAdminPin(configuredPin = process.env.ADMIN_PIN): string {
  const pin = configuredPin?.trim();
  if (!pin) return DEFAULT_ADMIN_PIN;
  if (!isAdminPin(pin)) {
    throw new Error("ADMIN_PIN must contain exactly 4 digits.");
  }
  return pin;
}

async function signSession(pin: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(`${SESSION_SIGNING_CONTEXT}:key:${pin}`),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    textEncoder.encode(`${SESSION_TOKEN_VERSION}:${SESSION_SIGNING_CONTEXT}`),
  );
  return new Uint8Array(signature);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;

  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export async function verifyAdminPin(
  candidate: unknown,
  configuredPin = resolveAdminPin(),
): Promise<boolean> {
  if (!isAdminPin(candidate)) return false;
  if (!isAdminPin(configuredPin)) {
    throw new Error("ADMIN_PIN must contain exactly 4 digits.");
  }

  const [candidateSignature, expectedSignature] = await Promise.all([
    signSession(candidate),
    signSession(configuredPin),
  ]);
  return bytesEqual(candidateSignature, expectedSignature);
}

export async function createAdminSessionToken(
  configuredPin = resolveAdminPin(),
): Promise<string> {
  if (!isAdminPin(configuredPin)) {
    throw new Error("ADMIN_PIN must contain exactly 4 digits.");
  }
  return `${SESSION_TOKEN_VERSION}.${toBase64Url(await signSession(configuredPin))}`;
}

export async function verifyAdminSessionToken(
  token: unknown,
  configuredPin = resolveAdminPin(),
): Promise<boolean> {
  if (typeof token !== "string" || !/^v1\.[A-Za-z0-9_-]{43}$/.test(token)) {
    return false;
  }
  const expectedToken = await createAdminSessionToken(configuredPin);
  return bytesEqual(textEncoder.encode(token), textEncoder.encode(expectedToken));
}

function readCookie(cookieHeader: string | null, name: string): string | null {
  if (!cookieHeader) return null;

  for (const part of cookieHeader.split(";")) {
    const separatorIndex = part.indexOf("=");
    if (separatorIndex < 0) continue;
    if (part.slice(0, separatorIndex).trim() !== name) continue;
    return part.slice(separatorIndex + 1).trim();
  }
  return null;
}

export async function hasValidAdminSession(
  request: Pick<Request, "headers">,
  configuredPin = resolveAdminPin(),
): Promise<boolean> {
  return verifyAdminSessionToken(
    readCookie(request.headers.get("cookie"), ADMIN_SESSION_COOKIE_NAME),
    configuredPin,
  );
}

export function adminSessionCookieOptions() {
  return {
    httpOnly: true,
    sameSite: "strict" as const,
    secure: process.env.NODE_ENV === "production",
    path: "/",
  };
}
