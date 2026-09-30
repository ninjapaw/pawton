import {
  checkPortalCredentials,
  createUserSession,
  USER_SESSION_COOKIE,
  userSessionCookieOptions,
} from "../../../lib/userAuth.mjs";
import {
  SESSION_COOKIE_NAME,
  ROTATED_SECRET_COOKIE_NAME,
  createSessionToken,
  sessionCookieOptions,
} from "../../../lib/adminAuth.mjs";
import {
  WALKTHROUGH_SESSION_COOKIE,
  createWalkthroughSession,
  walkthroughSessionCookieOptions,
} from "../../../lib/walkthroughAuth.mjs";

export async function POST({ request, cookies, redirect }) {
  if (request.headers.get("origin") !== new URL(request.url).origin)
    return new Response("Same-origin request required.", { status: 403 });
  let form;
  try {
    form = await request.formData();
  } catch {
    return new Response("Invalid form.", { status: 400 });
  }
  const username = String(form.get("username") ?? "");
  const password = String(form.get("password") ?? "");
  if (username.length > 100 || password.length > 1024)
    return redirect("/login?error=invalid", 303);
  const result = checkPortalCredentials(request, username, password);
  if (result !== "success" && result !== "admin" && result !== "walkthrough")
    return redirect(`/login?error=${result}`, 303);
  cookies.delete(SESSION_COOKIE_NAME, { path: "/" });
  cookies.delete(ROTATED_SECRET_COOKIE_NAME, { path: "/" });
  cookies.delete(USER_SESSION_COOKIE, { path: "/" });
  cookies.delete(WALKTHROUGH_SESSION_COOKIE, { path: "/" });
  if (result === "admin") {
    cookies.set(
      SESSION_COOKIE_NAME,
      createSessionToken(),
      sessionCookieOptions,
    );
    return redirect("/admin", 303);
  }
  if (result === "walkthrough") {
    // Signing in as the guide account is what kicks off the story: land on chapter one with the
    // mission briefing open, rather than on a menu the presenter has to navigate first.
    cookies.set(
      WALKTHROUGH_SESSION_COOKIE,
      createWalkthroughSession(),
      walkthroughSessionCookieOptions,
    );
    return redirect("/walkthrough?kickoff=1", 303);
  }
  cookies.set(
    USER_SESSION_COOKIE,
    createUserSession(),
    userSessionCookieOptions,
  );
  return redirect("/orders", 303);
}
