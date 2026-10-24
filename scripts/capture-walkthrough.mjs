#!/usr/bin/env node
import { readFile, writeFile, mkdir, rename } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { attackScenarios } from "../apps/pawton-manufacturing/src/lib/sqlAttackLab.mjs";
import { SESSION_COOKIE_NAME } from "../apps/pawton-manufacturing/src/lib/adminAuth.mjs";
import {
  createWalkthroughCapture,
  isRecordedSqlRun,
  retainCapturedEvidence,
} from "../apps/pawton-manufacturing/src/lib/walkthroughEvidence.mjs";

const scenarioIds = attackScenarios.map(({ id }) => id);
const defaultOutput = fileURLToPath(
  new URL("../apps/pawton-manufacturing/src/data/walkthrough-capture.json", import.meta.url),
);

export function validatedCaptureOrigin(value, configuration) {
  const allowed = Object.values(configuration.environments).flatMap((environment) => [
    environment.webAppCustomDomain,
    environment.webAppName && `${environment.webAppName}.azurewebsites.net`,
  ]).filter(Boolean).map((hostname) => hostname.toLowerCase());
  const url = new URL(value);
  if (
    url.protocol !== "https:" || url.username || url.password || url.port ||
    url.pathname !== "/" || url.search || url.hash ||
    !allowed.includes(url.hostname.toLowerCase())
  )
    throw new Error("Capture credentials may only be sent to a configured Pawton HTTPS origin.");
  return url.origin;
}

export async function captureWalkthrough({
  origin,
  username,
  password,
  observeSeconds = 600,
  previous = null,
  fetchRequest = fetch,
  pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  now = Date.now,
  checkpoint = async () => {},
  progress = console.log,
}) {
  if (!username || !password)
    throw new Error("Set ADMIN_PORTAL_USERNAME and ADMIN_PORTAL_PASSWORD through the process environment.");
  if (!Number.isInteger(observeSeconds) || observeSeconds < 0 || observeSeconds > 600)
    throw new Error("Observation must be between 0 and 600 seconds; resume later without rerunning tests if ingestion is delayed.");
  if (previous && (
    previous.schemaVersion !== 1 || previous.source !== origin ||
    previous.defenderDisabledForComparison !== false ||
    !Array.isArray(previous.scenarios) || previous.scenarios.length === 0 ||
    previous.scenarios.some(({ run }) => !isRecordedSqlRun(run) || !scenarioIds.includes(run.scenario))
  ))
    throw new Error("The resume file must contain recorded runs from this Pawton origin.");
  let cookie = "";
  let signedInAt = -Infinity;
  const signIn = async () => {
    const response = await fetchRequest(`${origin}/api/admin/login`, {
      method: "POST",
      redirect: "manual",
      headers: { Origin: origin, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username, password }),
      signal: AbortSignal.timeout(30000),
    });
    cookie = response.headers.getSetCookie()
      .map((value) => value.split(";")[0])
      .find((value) => value.startsWith(`${SESSION_COOKIE_NAME}=`)) || "";
    if (![302, 303].includes(response.status) || !cookie)
      throw new Error("Administrator sign-in failed. No scenario was started by this sign-in request.");
    signedInAt = now();
  };
  const request = async (endpoint, body) => {
    if (!cookie || now() - signedInAt >= 8 * 60000) await signIn();
    const response = await fetchRequest(`${origin}${endpoint}`, {
      method: body ? "POST" : "GET",
      redirect: "manual",
      headers: {
        Origin: origin,
        Cookie: cookie,
        Accept: "application/json",
        ...(body ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
      },
      ...(body ? { body: new URLSearchParams(body) } : {}),
      signal: AbortSignal.timeout(90000),
    });
    if (!response.headers.get("content-type")?.includes("application/json"))
      throw new Error(`Portal returned a non-JSON response (HTTP ${response.status}); no POST is retried automatically.`);
    return { response, data: await response.json() };
  };
  const readProtection = async () => {
    const response = await fetchRequest(`${origin}/walkthrough`, {
      headers: { "Cache-Control": "no-cache" },
      signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) throw new Error(`Protection observation failed: HTTP ${response.status}.`);
    const html = await response.text();
    const tier = /data-defender-sql-tier="([^"]+)"/.exec(html)?.[1];
    if (!tier) throw new Error("The deployed walkthrough does not expose its observed SQL Defender plan tier.");
    return { checkedAt: new Date(now()).toISOString(), tier, source: "Live walkthrough managed-identity plan check" };
  };
  if (!previous) {
    const healthResponse = await fetchRequest(`${origin}/health`, {
      headers: { "Cache-Control": "no-cache" },
      signal: AbortSignal.timeout(30000),
    });
    if (!healthResponse.ok) throw new Error("SQL health could not be checked; no scenario was started.");
    const health = await healthResponse.json();
    if (health.status !== "healthy" || health.database !== "connected")
      throw new Error("SQL is not healthy and connected; no scenario was started.");
  }
  const bundle = previous ? structuredClone(previous) : {
    schemaVersion: 1,
    capturedAt: null,
    source: origin,
    comparison: "Native audit logs and Defender observations from the same protected runs",
    defenderDisabledForComparison: false,
    protectionAtStart: await readProtection(),
    protectionAtEnd: null,
    redactions: ["Host and non-test principal fields", "IP addresses", "Credential-like values"],
    scenarios: [],
  };
  if (bundle.protectionAtStart?.tier !== "Standard")
    throw new Error("The SQL Defender plan was not verified as Standard at the start. No protected-run comparison will be claimed.");
  const save = async () => {
    bundle.capturedAt = new Date(now()).toISOString();
    if (JSON.stringify(bundle).includes(password) || (cookie && JSON.stringify(bundle).includes(cookie)))
      throw new Error("Capture output contains an authentication value; refusing to write it.");
    await checkpoint(bundle);
  };
  if (!previous) {
    for (const scenario of scenarioIds) {
      let started;
      for (let attempt = 0; attempt < 3; attempt++) {
        const result = await request("/api/admin/defender-simulation", {
          simulation: scenario, sourceMode: "fixed", confirm: "yes",
        });
        if (result.response.status === 429) {
          const seconds = Number(/Wait (\d+) seconds/.exec(result.data.error || "")?.[1]);
          if (!Number.isInteger(seconds) || seconds < 1 || seconds > 120)
            throw new Error("The server cooldown is outside this capture's bounded wait; no scenario was retried.");
          progress(`Waiting ${seconds}s for the server cooldown; no scenario started.`);
          await pause(seconds * 1000);
          continue;
        }
        if (!result.data.runId && !result.data.run)
          throw new Error(`Scenario ${scenario} was not recorded (HTTP ${result.response.status}); resolve the lab configuration before continuing.`);
        started = result.data.run || result.data;
        if (!isRecordedSqlRun(started) || started.scenario !== scenario)
          throw new Error("The server returned an invalid or mismatched run record.");
        break;
      }
      if (!started) throw new Error(`Scenario ${scenario} is still rate-limited; no execution was assumed.`);
      bundle.scenarios.push(createWalkthroughCapture({
        run: started,
        nativeEvidence: { state: "not-queried", checkedAt: null, events: [], detail: "No audit query has run yet.", window: null },
        evidence: { state: "not-queried", checkedAt: null, alerts: [], detail: "No Defender query has run yet.", blocking: "Not confirmed." },
      }, new Date(now()).toISOString()));
      await save();
      progress(`Recorded ${scenario}: ${started.state}; run ${started.runId}.`);
      await pause(15000);
    }
  }
  const deadline = now() + observeSeconds * 1000;
  do {
    for (let index = 0; index < bundle.scenarios.length; index++) {
      const run = bundle.scenarios[index].run;
      const { response, data } = await request(`/api/admin/defender-simulation?runId=${encodeURIComponent(run.runId)}`);
      if (!response.ok)
        throw new Error(`Evidence lookup for ${run.scenario} failed (HTTP ${response.status}); resume the saved run IDs instead of rerunning activity.`);
      if (data.run?.runId !== run.runId || data.run?.scenario !== run.scenario)
        throw new Error("Evidence response does not match the requested recorded run.");
      bundle.scenarios[index] = retainCapturedEvidence(bundle.scenarios[index],
        createWalkthroughCapture(data, new Date(now()).toISOString()));
      await save();
    }
    progress(bundle.scenarios.map(({ run, native, defender }) =>
      `${run.scenario}: ${native.events.length} native record(s), ${defender.alerts.filter((alert) => alert.correlated).length} correlated Defender alert(s), states ${native.state}/${defender.state}`,
    ).join(" | "));
    if (bundle.scenarios.some(({ native, defender }) => native.state === "unavailable" || defender.state === "unavailable"))
      progress("An evidence read is unavailable; retaining prior actual records and retrying reads only within the observation window.");
    if (bundle.scenarios.every(({ native, defender }) =>
      native.state !== "unavailable" && defender.state !== "unavailable" &&
      native.events.length > 0 && defender.alerts.some((alert) => alert.correlated))) break;
    if (now() >= deadline) break;
    await pause(Math.min(30000, deadline - now()));
  } while (now() <= deadline);
  bundle.protectionAtEnd = await readProtection();
  await save();
  if (bundle.scenarios.some(({ native, defender }) => native.state === "unavailable" || defender.state === "unavailable"))
    throw new Error("The final evidence read is unavailable. Actual retained records and timestamps are saved; resume evidence only, not activity.");
  if (bundle.protectionAtEnd.tier !== "Standard")
    throw new Error("The SQL Defender plan was not verified as Standard at the end. Review the saved observations before publishing them as protected runs.");
  return bundle;
}

async function main() {
  const { values } = parseArgs({
    options: {
      origin: { type: "string", default: "https://pawton.ninjapaws.org" },
      output: { type: "string", default: defaultOutput },
      "observe-seconds": { type: "string", default: "600" },
      resume: { type: "string" },
      confirm: { type: "string" },
      help: { type: "boolean" },
    },
  });
  if (values.help) {
    console.log("Capture all six bounded live scenarios and their actual audit/Defender evidence.\nUse process-only ADMIN_PORTAL_USERNAME/PASSWORD.\nnode scripts/capture-walkthrough.mjs --confirm isolated-lab [--observe-seconds 600] [--output <json>]\nUse --resume <saved-json> to query existing runs without executing any scenario again.");
    return;
  }
  if (!values.resume && values.confirm !== "isolated-lab")
    throw new Error("Explicit --confirm isolated-lab is required before executing live scenarios.");
  const configuration = JSON.parse(await readFile(new URL("../config/deploy.config.json", import.meta.url), "utf8"));
  const origin = validatedCaptureOrigin(values.origin, configuration);
  const output = path.resolve(values.output);
  const previous = values.resume ? JSON.parse(await readFile(path.resolve(values.resume), "utf8")) : null;
  const bundle = await captureWalkthrough({
    origin,
    username: process.env.ADMIN_PORTAL_USERNAME,
    password: process.env.ADMIN_PORTAL_PASSWORD,
    observeSeconds: Number(values["observe-seconds"]),
    previous,
    checkpoint: async (capture) => {
      const serialized = `${JSON.stringify(capture, null, 2)}\n`;
      if (Buffer.byteLength(serialized) > 1024 * 1024)
        throw new Error("The sanitized capture exceeds the one-MiB publication bound.");
      await mkdir(path.dirname(output), { recursive: true });
      const temporary = `${output}.${process.pid}.tmp`;
      await writeFile(temporary, serialized, { mode: 0o600 });
      await rename(temporary, output);
    },
  });
  console.log(`Saved ${bundle.scenarios.length} real scenario captures to ${output}. Defender was not disabled; empty/uncertain observations are retained as such.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : "Capture failed.");
    process.exitCode = 1;
  });
}
