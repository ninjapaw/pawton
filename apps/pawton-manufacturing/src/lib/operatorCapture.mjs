import { readFile, writeFile, rename, mkdir } from "node:fs/promises";
import path from "node:path";
import fallbackCapture from "../data/walkthrough-capture.json" with { type: "json" };
import { attackScenarios, sqlAttackRunner } from "./sqlAttackLab.mjs";
import { getRunAuditEvidence } from "./auditLog.mjs";
import { getDefenderStatus, getRunDefenderEvidence } from "./defenderStatus.mjs";
import { createWalkthroughCapture, isRecordedSqlRun } from "./walkthroughEvidence.mjs";

const jobIdPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const ids = attackScenarios.map(({ id }) => id);

class CaptureJobError extends Error {}

export function createOperatorCapture({
  environment = process.env,
  directory = process.platform !== "win32" && environment.WEBSITE_SITE_NAME
    ? "/home/data/pawton-walkthrough" : null,
  runner = sqlAttackRunner,
  nativeEvidence = getRunAuditEvidence,
  defenderEvidence = getRunDefenderEvidence,
  protection = getDefenderStatus,
  now = Date.now,
  pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  observationMilliseconds = 600000,
  fallback = fallbackCapture,
  log = console.error,
} = {}) {
  let active;
  const attempted = new Set();
  const statePath = directory && path.join(directory, "job-state.json");
  const capturePath = directory && path.join(directory, "latest.json");
  const timestamp = () => new Date(now()).toISOString();
  async function readJson(file) {
    try {
      return JSON.parse(await readFile(file, "utf8"));
    } catch (error) {
      if (error.code === "ENOENT") return null;
      throw error;
    }
  }
  async function save(file, value) {
    const serialized = `${JSON.stringify(value, null, 2)}\n`;
    if (Buffer.byteLength(serialized) > 1024 * 1024)
      throw new CaptureJobError("The bounded capture exceeds its one-MiB storage limit.");
    await mkdir(directory, { recursive: true });
    const temporary = `${file}.${process.pid}.tmp`;
    await writeFile(temporary, serialized, { mode: 0o600 });
    await rename(temporary, file);
  }
  function validBundle(bundle) {
    return bundle?.schemaVersion === 1 &&
      bundle.defenderDisabledForComparison === false &&
      Array.isArray(bundle.scenarios) &&
      bundle.scenarios.every((capture) => isRecordedSqlRun(capture.run) &&
        Array.isArray(capture.native?.events) && Array.isArray(capture.defender?.alerts));
  }
  async function read() {
    if (!directory) return { ...fallback, operatorJob: null };
    try {
      const saved = await readJson(capturePath);
      if (saved && !validBundle(saved)) throw new CaptureJobError("Invalid saved capture format.");
      if (saved && (!fallback.capturedAt || Date.parse(saved.capturedAt) >= Date.parse(fallback.capturedAt)))
        return saved;
      return { ...fallback, operatorJob: null };
    } catch {
      log("Pawton recorded capture could not be loaded; no live evidence is being substituted.");
      return {
        ...fallback,
        operatorJob: { state: "unavailable", message: "Saved capture could not be loaded. No live evidence is being substituted." },
      };
    }
  }
  async function observeProtection() {
    const status = await protection();
    const tier = status.observations?.find(({ label }) => label === "Defender for SQL on machines")?.state;
    if (tier !== "Standard")
      throw new CaptureJobError("Defender for SQL was not verified as Standard; no protected-run comparison will be claimed.");
    return {
      checkedAt: status.checkedAt,
      tier,
      source: "App Service managed-identity read",
      observations: status.observations.map(({ label, state, detail }) => ({ label, state, detail })),
    };
  }
  async function publish(state, status, message) {
    state.bundle.capturedAt = timestamp();
    state.bundle.operatorJob = {
      id: state.id, state: status, message,
      executor: "Azure management-controlled App Service job using the existing SQL service identities",
      startedAt: state.startedAt,
    };
    await save(statePath, state);
    await save(capturePath, state.bundle);
  }
  async function run(id) {
    let state;
    try {
      const existing = await readJson(statePath);
      if (existing?.id === id) {
        state = existing;
        if (!Array.isArray(state.runs) || state.runs.length !== ids.length ||
          state.runs.some((record, index) => !isRecordedSqlRun(record) || record.scenario !== ids[index]) || state.inFlight)
          throw new CaptureJobError("An earlier execution was interrupted. Activity is not retried automatically; review the saved run IDs before requesting a new job.");
      } else {
        state = {
          id, startedAt: timestamp(), inFlight: null, runs: [],
          bundle: {
            schemaVersion: 1, capturedAt: null,
            source: `https://${environment.PORTAL_CUSTOM_DOMAIN || environment.WEBSITE_HOSTNAME}`,
            comparison: "Native audit logs and Defender observations from the same protected runs",
            defenderDisabledForComparison: false,
            protectionAtStart: null, protectionAtEnd: null,
            redactions: ["Host and non-test principal fields", "IP addresses", "Credential-like values"],
            scenarios: [],
          },
        };
        const configuredCooldown = Number(environment.SQL_ATTACK_COOLDOWN_SECONDS);
        const cooldown = Number.isInteger(configuredCooldown) && configuredCooldown >= 1 && configuredCooldown <= 3600
          ? configuredCooldown : 60;
        if (cooldown > 120)
          throw new CaptureJobError("The configured cooldown exceeds this job's bounded wait; no activity was started.");
        const available = await runner.availability();
        if (ids.length !== 6 || ids.some((scenario) => !available.ids.includes(scenario)))
          throw new CaptureJobError("All six existing lab scenarios must be configured before this capture starts.");
        state.bundle.protectionAtStart = await observeProtection();
        await publish(state, "executing", "Authorized bounded scenario capture is running. Evidence collection is not complete.");
        for (const scenario of ids) {
          state.inFlight = scenario;
          await save(statePath, state);
          let record;
          for (let attempt = 0; attempt < 3; attempt++) {
            try {
              record = await runner.run(scenario, { sourceMode: "fixed" });
              break;
            } catch (error) {
              if (error.status === 429) {
                await pause(cooldown * 1000);
                continue;
              }
              if (error.run && isRecordedSqlRun(error.run)) { record = error.run; break; }
              throw new CaptureJobError("A scenario has no completed run record. No uncertain activity is retried automatically.");
            }
          }
          if (!record || !isRecordedSqlRun(record) || record.scenario !== scenario)
            throw new CaptureJobError("The scenario did not return a valid run record; no execution is assumed.");
          state.runs.push(record);
          state.inFlight = null;
          state.bundle.scenarios.push(createWalkthroughCapture({
            run: record,
            nativeEvidence: { checkedAt: null, state: "not-queried", events: [], detail: "Audit query has not run yet.", window: null },
            evidence: { checkedAt: null, state: "not-queried", alerts: [], detail: "Defender query has not run yet.", blocking: "Not confirmed." },
          }, timestamp()));
          await publish(state, "executing", `${state.runs.length} of ${ids.length} executions recorded. No detection verdict is assumed.`);
          await pause(cooldown * 1000);
        }
      }
      const deadline = now() + observationMilliseconds;
      do {
        for (let index = 0; index < state.runs.length; index++) {
          const record = state.runs[index];
          const [native, defender] = await Promise.all([nativeEvidence(record), defenderEvidence(record)]);
          state.bundle.scenarios[index] = createWalkthroughCapture({
            run: record, nativeEvidence: native, evidence: defender,
          }, timestamp());
          await publish(state, "observing", "Collecting actual native audit and Defender observations. Empty and uncertain results are not negative verdicts.");
          if (native.state === "unavailable" || defender.state === "unavailable")
            throw new CaptureJobError("An evidence source is unavailable. Recorded executions are saved; restarting the same job resumes evidence only, not activity.");
        }
        if (state.bundle.scenarios.every(({ native, defender }) =>
          native.events.length > 0 && defender.alerts.some((alert) => alert.correlated))) break;
        if (now() >= deadline) break;
        await pause(Math.min(30000, deadline - now()));
      } while (now() <= deadline);
      state.bundle.protectionAtEnd = await observeProtection();
      const complete = state.bundle.scenarios.every(({ native }) => native.events.length > 0);
      await publish(state, complete ? "complete" : "partial",
        complete
          ? "All executions and evidence queries are recorded. Defender outcomes may still be empty or unconfirmed; capture completion is not proof of detection or prevention."
          : "The observation window ended with missing native matches. Saved records are actual but incomplete; resume evidence only if forwarding is delayed.");
    } catch (error) {
      const message = error instanceof CaptureJobError
        ? error.message
        : "Operator capture failed. Review SQL, telemetry access and persistent storage before resuming.";
      log(`Pawton operator capture ${id}: ${message}`);
      if (state?.bundle) {
        try { await publish(state, "failed", message); }
        catch { log("Pawton capture failure state could not be saved; no completed capture is claimed."); }
      }
    }
  }
  function queue() {
    const id = environment.WALKTHROUGH_CAPTURE_JOB_ID;
    if (!id || active || attempted.has(id)) return active;
    if (!directory || !jobIdPattern.test(id)) {
      attempted.add(id);
      log("Pawton operator capture requires App Service storage and a valid UUID job ID; no activity was started.");
      return;
    }
    attempted.add(id);
    active = run(id).finally(() => { active = undefined; });
    return active;
  }
  return { queue, read };
}

const operatorCapture = createOperatorCapture();
export const queueOperatorCapture = () => { void operatorCapture.queue(); };
export const readRecordedWalkthroughCapture = () => operatorCapture.read();
