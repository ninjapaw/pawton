import {
  WALKTHROUGH_SESSION_COOKIE,
  getWalkthroughUser,
} from "../../../lib/walkthroughAuth.mjs";

export async function POST({ request, cookies, redirect }) {
  if (request.headers.get("origin") !== new URL(request.url).origin)
    return new Response("Same-origin request required.", { status: 403 });
  if (!getWalkthroughUser(cookies))
    return new Response("Walkthrough sign-in required.", { status: 401 });
  cookies.delete(WALKTHROUGH_SESSION_COOKIE, { path: "/" });
  return redirect("/login", 303);
}
