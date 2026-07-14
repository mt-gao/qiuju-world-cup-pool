import { NextResponse } from "next/server";
import {
  ADMIN_SESSION_COOKIE_NAME,
  adminSessionCookieOptions,
  createAdminSessionToken,
  hasValidAdminSession,
  isAdminPin,
  verifyAdminPin,
} from "@/lib/admin-auth";

export const dynamic = "force-dynamic";

const NO_STORE_HEADERS = { "Cache-Control": "no-store" };

export async function GET(request: Request) {
  const authenticated = await hasValidAdminSession(request);
  return NextResponse.json(
    { authenticated },
    { headers: NO_STORE_HEADERS },
  );
}

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { authenticated: false, error: "请输入4位数字管理密码。" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  const pin =
    typeof body === "object" && body !== null && "pin" in body
      ? (body as { pin?: unknown }).pin
      : undefined;
  if (!isAdminPin(pin)) {
    return NextResponse.json(
      { authenticated: false, error: "请输入4位数字管理密码。" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }
  if (!(await verifyAdminPin(pin))) {
    return NextResponse.json(
      { authenticated: false, error: "管理密码错误。" },
      { status: 401, headers: NO_STORE_HEADERS },
    );
  }

  const response = NextResponse.json(
    { authenticated: true },
    { headers: NO_STORE_HEADERS },
  );
  response.cookies.set(
    ADMIN_SESSION_COOKIE_NAME,
    await createAdminSessionToken(),
    adminSessionCookieOptions(),
  );
  return response;
}
