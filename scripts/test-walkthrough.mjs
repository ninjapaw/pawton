import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { POST as loginPost } from "../apps/pawton-manufacturing/src/pages/api/user/login.js";
import {
  POST as runPost,
  GET as runGet,
} from "../apps/pawton-manufacturing/src/pages/api/walkthrough/run.js";
import { POST as logoutPost } from "../apps/pawton-manufacturing/src/pages/api/walkthrough/logout.js";
import {
  WALKTHROUGH_SESSION_COOKIE,
  createWalkthroughSession,
  getWalkthroughUser,
  getWalkthroughViewer,
} from "../apps/pawton-manufacturing/src/lib/walkthroughAuth.mjs";
import {
  USER_SESSION_COOKIE,
  createUserSession,
  getUser,
} from "../apps/pawton-manufacturing/src/lib/userAuth.mjs";
import {
  SESSION_COOKIE_NAME,
  createSessionToken,
} from "../apps/pawton-manufacturing/src/lib/adminAuth.mjs";
import {
  chapters,
  glossary,
  glossaryKeysIn,
  segments,
  walkthroughRunnableScenarios,
} from "../apps/pawton-manufacturing/src/lib/walkthroughStory.mjs";
import {
  attackScenarios,
  sqlAttackRunner,
} from "../apps/pawton-manufacturing/src/lib/sqlAttackLab.mjs";

const origin = "https://portal.example";

function configure(context) {
  const values = {
    USER_PORTAL_USERNAME: "staff-test",
    USER_PORTAL_PASSWORD: "manager-only",
    USER_SESSION_SECRET: "test-shared-secret",
    ADMIN_PORTAL_USERNAME: "admin-test",
    ADMIN_PORTAL_PASSWORD: "admin-only",
    ADMIN_SESSION_SECRET: "test-shared-secret",
    WALKTHROUGH_PORTAL_USERNAME: "guide-test",
    WALKTHROUGH_PORTAL_PASSWORD: "guide-only",
  };
  const originals = Object.fromEntries(
    Object.keys(values).map((key) => [key, process.env[key]]),
  );
  Object.assign(process.env, values);
  context.after(() => {
    for (const [key, value] of Object.entries(originals)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
}

const jar = (entries = {}) => {
  const values = new Map(
    Object.entries(entries).map(([name, value]) => [name, { value }]),
  );
  return {
    values,
    get: (name) => values.get(name),
    set: (name, value, settings) => values.set(name, { value, settings }),
    delete: (name) => values.delete(name),
  };
};
const redirect = (location, status) =>
  new Response(null, { status, headers: { Location: location } });
const guideCookies = () =>
  jar({ [WALKTHROUGH_SESSION_COOKIE]: createWalkthroughSession() });
const post = (path, body, requestOrigin = origin) =>
  new Request(`${origin}${path}`, {
    method: "POST",
    headers: {
      ...(requestOrigin ? { Origin: requestOrigin } : {}),
      "X-Forwarded-For": randomUUID(),
    },
    body: new URLSearchParams(body),
  });

test("signing in as the guide account kicks off the walkthrough with only a guide session", async (context) => {
  configure(context);
  const cookies = jar({ [USER_SESSION_COOKIE]: "stale" });
  const response = await loginPost({
    request: post("/api/user/login", {
      username: "guide-test",
      password: "guide-only",
    }),
    cookies,
    redirect,
  });
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), "/walkthrough?kickoff=1");
  assert.deepEqual([...cookies.values.keys()], [WALKTHROUGH_SESSION_COOKIE]);
  const saved = cookies.values.get(WALKTHROUGH_SESSION_COOKIE);
  assert.equal(saved.settings.httpOnly, true);
  assert.equal(saved.settings.sameSite, "strict");
  assert.equal(getWalkthroughUser(cookies), "guide-test");
  assert.deepEqual(getWalkthroughViewer(cookies), {
    role: "guide",
    name: "guide-test",
  });

  const wrong = await loginPost({
    request: post("/api/user/login", {
      username: "guide-test",
      password: "manager-only",
    }),
    cookies: jar(),
    redirect,
  });
  assert.equal(wrong.headers.get("location"), "/login?error=invalid");
});

test("guide and manager sessions cannot be replayed as each other and the guide has no order or admin access", (context) => {
  configure(context);
  const guideToken = createWalkthroughSession();
  const managerToken = createUserSession();
  assert.equal(getUser(jar({ [USER_SESSION_COOKIE]: guideToken })), null);
  assert.equal(getUser(jar({ [WALKTHROUGH_SESSION_COOKIE]: guideToken })), null);
  assert.equal(
    getWalkthroughUser(jar({ [WALKTHROUGH_SESSION_COOKIE]: managerToken })),
    null,
  );
  assert.equal(getWalkthroughViewer(jar()), null);
  assert.deepEqual(
    getWalkthroughViewer(jar({ [SESSION_COOKIE_NAME]: createSessionToken() })),
    { role: "admin", name: "admin-test" },
  );
  process.env.WALKTHROUGH_PORTAL_PASSWORD = "rotated-guide";
  assert.equal(
    getWalkthroughUser(jar({ [WALKTHROUGH_SESSION_COOKIE]: guideToken })),
    null,
  );
  delete process.env.WALKTHROUGH_PORTAL_PASSWORD;
  assert.equal(
    getWalkthroughUser(jar({ [WALKTHROUGH_SESSION_COOKIE]: guideToken })),
    null,
  );
});

test("walkthrough run API refuses anonymous, cross-origin, unconfirmed, and privileged requests", async (context) => {
  configure(context);
  context.mock.method(sqlAttackRunner, "run", async () => {
    throw new Error("runner must not be reached");
  });
  const body = { scenario: "brute-force", confirm: "yes" };
  const call = async (cookies, request) =>
    (await runPost({ request, cookies })).status;
  assert.equal(await call(jar(), post("/api/walkthrough/run", body)), 401);
  assert.equal(
    await call(
      jar({ [USER_SESSION_COOKIE]: createUserSession() }),
      post("/api/walkthrough/run", body),
    ),
    401,
  );
  assert.equal(
    await call(
      guideCookies(),
      post("/api/walkthrough/run", body, "https://evil.example"),
    ),
    403,
  );
  assert.equal(
    await call(guideCookies(), post("/api/walkthrough/run", body, null)),
    403,
  );
  assert.equal(
    await call(
      guideCookies(),
      post("/api/walkthrough/run", { scenario: "brute-force" }),
    ),
    400,
  );
  for (const scenario of [
    "principal-anomaly",
    "external-source",
    "obfuscated-shell",
    "unknown",
  ])
    assert.equal(
      await call(
        guideCookies(),
        post("/api/walkthrough/run", { scenario, confirm: "yes" }),
      ),
      403,
      scenario,
    );
  assert.equal(sqlAttackRunner.run.mock.callCount(), 0);
});

test("walkthrough run API starts allow-listed tests and only reveals walkthrough runs", async (context) => {
  configure(context);
  const runId = randomUUID();
  context.mock.method(sqlAttackRunner, "run", async (scenario) => ({
    runId,
    scenario,
    state: "executed",
  }));
  const started = await runPost({
    request: post("/api/walkthrough/run", {
      scenario: "sql-injection",
      confirm: "yes",
    }),
    cookies: guideCookies(),
  });
  assert.equal(started.status, 200);
  assert.equal(started.headers.get("cache-control"), "no-store");
  assert.equal((await started.json()).run.scenario, "sql-injection");
  assert.deepEqual(sqlAttackRunner.run.mock.calls[0].arguments, [
    "sql-injection",
  ]);

  const get = async (cookies, id) =>
    runGet({
      request: new Request(`${origin}/api/walkthrough/run?runId=${id}`),
      cookies,
    });
  assert.equal((await get(jar(), runId)).status, 401);
  assert.equal((await get(guideCookies(), "not-a-run")).status, 400);
  context.mock.method(sqlAttackRunner, "getRun", () => ({
    runId,
    scenario: "obfuscated-shell",
  }));
  assert.equal((await get(guideCookies(), runId)).status, 404);
});

test("guide sign-out is same-origin only and clears the guide session", async (context) => {
  configure(context);
  const cookies = guideCookies();
  assert.equal(
    (
      await logoutPost({
        request: post("/api/walkthrough/logout", {}, "https://evil.example"),
        cookies,
        redirect,
      })
    ).status,
    403,
  );
  const response = await logoutPost({
    request: post("/api/walkthrough/logout", {}),
    cookies,
    redirect,
  });
  assert.equal(response.headers.get("location"), "/login");
  assert.equal(cookies.values.has(WALKTHROUGH_SESSION_COOKIE), false);
});

test("story is complete, uses only defined glossary terms, and only unprivileged tests are runnable", () => {
  const ids = chapters.map((chapter) => chapter.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(chapters[0].kind, "briefing");
  assert.equal(chapters.at(-1).kind, "debrief");
  const texts = JSON.stringify(chapters);
  for (const key of glossaryKeysIn(texts))
    assert.ok(glossary[key], `missing glossary term: ${key}`);
  assert.ok(
    segments("a {{sa}} b").some((part) => part.definition),
    "glossary tokens render as tooltips",
  );
  const scenarioIds = attackScenarios.map((scenario) => scenario.id);
  for (const chapter of chapters.filter((entry) => entry.kind === "attack")) {
    assert.ok(scenarioIds.includes(chapter.scenario), chapter.id);
    for (const field of ["alert", "alertType", "severity", "tactic"])
      assert.ok(chapter.with[field], `${chapter.id}.with.${field}`);
    assert.ok(
      walkthroughRunnableScenarios.includes(chapter.scenario)
        ? chapter.live
        : chapter.adminOnly,
      `${chapter.id} explains how it runs`,
    );
  }
  assert.deepEqual(walkthroughRunnableScenarios, [
    "brute-force",
    "suspicious-app",
    "sql-injection",
  ]);
});

test("IaC provisions the guide account through Key Vault and deploy never prints its password", async () => {
  const read = (path) =>
    readFile(new URL(`../${path}`, import.meta.url), "utf8");
  const template = JSON.parse(
    await read("infra/sql-defender-scenario/main.json"),
  );
  assert.equal(await read("azuredeploy.json"), await read("infra/sql-defender-scenario/main.json"));
  const config = JSON.parse(await read("config/deploy.config.json"));
  assert.equal(config.sqlScenario.walkthroughPortalUsername, "dojo-guide");
  assert.equal(
    template.parameters.walkthroughPortalPassword.type.toLowerCase(),
    "securestring",
  );
  assert.equal(template.parameters.walkthroughPortalPassword.defaultValue, undefined);
  assert.ok(!JSON.stringify(template.outputs).includes("walkthroughPortalPassword"));
  const settings = template.resources.find(
    (resource) => resource.type === "Microsoft.Web/sites",
  ).properties.siteConfig.appSettings;
  for (const [secretName, parameter, setting] of [
    ["walkthrough-portal-username", "walkthroughPortalUsername", "WALKTHROUGH_PORTAL_USERNAME"],
    ["walkthrough-portal-password", "walkthroughPortalPassword", "WALKTHROUGH_PORTAL_PASSWORD"],
  ]) {
    const secret = template.resources.find(
      (resource) =>
        resource.type === "Microsoft.KeyVault/vaults/secrets" &&
        resource.name.includes(secretName),
    );
    assert.ok(secret, secretName);
    assert.equal(secret.condition, "[parameters('deployWebApp')]");
    assert.equal(secret.properties.value, `[parameters('${parameter}')]`);
    assert.equal(
      settings.find((entry) => entry.name === setting).value,
      secret.properties.value,
    );
  }
  const script = await read("scripts/deploy.sh");
  assert.match(script, /walkthrough_portal_password="\$\(generate_password\)"/);
  assert.match(script, /walkthroughPortalPassword="\$walkthrough_portal_password"/);
  assert.match(script, /unset walkthrough_portal_password/);
  assert.doesNotMatch(script, /(echo|printf)[^\n]*walkthrough_portal_password/);
});
