import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { isAuthenticated } from "./adminAuth.mjs";

// The guide account exists only to start and present the Defender for SQL attack walkthrough.
// It cannot manage orders, SQL logins, the built-in administrator, or any Security lab setting,
// and it can only trigger the unprivileged, bounded tests listed in walkthroughStory.mjs.
export const WALKTHROUGH_SESSION_COOKIE = "dojo_walkthrough_session";
const sessionSeconds = 60 * 60;

export function isWalkthroughLoginConfigured(environment = process.env) {
  return Boolean(
    environment.WALKTHROUGH_PORTAL_USERNAME &&
    environment.WALKTHROUGH_PORTAL_PASSWORD &&
    environment.USER_SESSION_SECRET,
  );
}

function equal(left, right) {
  const digest = (value) =>
    createHash("sha256")
      .update(String(value ?? ""))
      .digest();
  return timingSafeEqual(digest(left), digest(right));
}

function sign(payload) {
  // The "walkthrough" role tag and the guide credentials are bound into the signature, so a
  // manager cookie can never be replayed as a guide cookie (or vice versa) even though both
  // roles share USER_SESSION_SECRET, and rotating the guide password invalidates old sessions.
  return createHmac("sha256", process.env.USER_SESSION_SECRET)
    .update(
      JSON.stringify([
        "walkthrough",
        process.env.WALKTHROUGH_PORTAL_USERNAME,
        process.env.WALKTHROUGH_PORTAL_PASSWORD,
        payload,
      ]),
    )
    .digest("base64url");
}

export function verifyWalkthroughCredentials(username, password) {
  if (!isWalkthroughLoginConfigured()) return false;
  const userOk = equal(username, process.env.WALKTHROUGH_PORTAL_USERNAME);
  const passOk = equal(password, process.env.WALKTHROUGH_PORTAL_PASSWORD);
  return userOk && passOk;
}

export function createWalkthroughSession() {
  if (!isWalkthroughLoginConfigured())
    throw new Error("Walkthrough sign-in is not configured.");
  const payload = Buffer.from(
    JSON.stringify({
      role: "walkthrough",
      exp: Math.floor(Date.now() / 1000) + sessionSeconds,
      nonce: randomBytes(16).toString("hex"),
    }),
  ).toString("base64url");
  return `${payload}.${sign(payload)}`;
}

export function getWalkthroughUser(cookies) {
  if (!isWalkthroughLoginConfigured()) return null;
  const token = cookies.get(WALKTHROUGH_SESSION_COOKIE)?.value;
  if (typeof token !== "string" || token.length > 2048) return null;
  const parts = token.split(".");
  if (parts.length !== 2 || !equal(parts[1], sign(parts[0]))) return null;
  try {
    const payload = JSON.parse(
      Buffer.from(parts[0], "base64url").toString("utf8"),
    );
    const now = Math.floor(Date.now() / 1000);
    return payload.role === "walkthrough" &&
      Number.isInteger(payload.exp) &&
      payload.exp > now &&
      payload.exp <= now + sessionSeconds
      ? process.env.WALKTHROUGH_PORTAL_USERNAME
      : null;
  } catch {
    return null;
  }
}

// Administrators may also present the walkthrough; nobody else can view or drive it.
export function getWalkthroughViewer(cookies) {
  if (isAuthenticated(cookies))
    return { role: "admin", name: process.env.ADMIN_PORTAL_USERNAME };
  const guide = getWalkthroughUser(cookies);
  return guide ? { role: "guide", name: guide } : null;
}

export function authorizeWalkthroughMutation(request, cookies) {
  if (!getWalkthroughViewer(cookies))
    return Response.json(
      { error: "Walkthrough sign-in required." },
      { status: 401, headers: { "Cache-Control": "no-store" } },
    );
  if (request.headers.get("origin") !== new URL(request.url).origin)
    return Response.json(
      { error: "Same-origin request required." },
      { status: 403, headers: { "Cache-Control": "no-store" } },
    );
  return null;
}

export const walkthroughSessionCookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
  path: "/",
  maxAge: sessionSeconds,
};
