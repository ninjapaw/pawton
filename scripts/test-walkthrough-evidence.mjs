import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { getRunAuditEvidence } from "../apps/pawton-manufacturing/src/lib/auditLog.mjs";
import {
  createWalkthroughCapture,
  formatNativeEvidence,
  formatDefenderEvidence,
  isRecordedSqlRun,
  redactEvidenceText,
  recordedCaptureFor,
} from "../apps/pawton-manufacturing/src/lib/walkthroughEvidence.mjs";
import { captureWalkthrough, validatedCaptureOrigin } from "./capture-walkthrough.mjs";
import { SESSION_COOKIE_NAME } from "../apps/pawton-manufacturing/src/lib/adminAuth.mjs";

const vmId = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/lab/providers/Microsoft.Compute/virtualMachines/sql";
const environment = {
  SQL_VM_RESOURCE_ID: vmId,
  LOG_ANALYTICS_WORKSPACE_ID: "22222222-2222-2222-2222-222222222222",
};
const clock = Date.parse("2026-10-24T12:03:00Z");
function runFixture(scenario = "sql-injection") {
  const runId = randomUUID();
  return {
    runId, scenario, marker: `dojo-attack-test:${scenario}:${runId}`,
    startedAt: "2026-10-24T12:00:00Z", completedAt: "2026-10-24T12:00:05Z",
    state: "executed", sqlProtection: "SQL permitted the fixed test activity.",
    outcome: "The bounded lab query completed.",
    executionEvidence: { source: "SQL Server execution response" },
  };
}
function rowFixture(run, overrides = {}) {
  return {
    TimeGenerated: "2026-10-24T12:00:02Z", EventID: 33205,
    EventLevelName: "Information", Source: "MSSQLSERVER", EventLog: "Application",
    _ResourceId: vmId,
    RenderedDescription: `action_id:LGIS succeeded:true server_principal_name:private-service server_principal_sid:private-sid server_instance_name:private-host client_ip:10.2.3.4 application_name:${run.marker} database_name:FutonManufacturing statement:SELECT 1; /* ${run.marker} */`,
    ...overrides,
  };
}
function logsClient(rows, status = "Success") {
  const columns = Object.keys(rows[0] || rowFixture(runFixture()));
  return {
    calls: [],
    async queryWorkspace(workspace, query, interval, options) {
      this.calls.push({ workspace, query, interval, options });
      const table = { columnDescriptors: columns.map((name) => ({ name })), rows: rows.map((row) => columns.map((name) => row[name])) };
      return status === "PartialFailure"
        ? { status, partialTables: [table], partialError: { message: "upstream private detail" } }
        : { status, tables: [table] };
    },
  };
}

test("native captures require a valid recorded run, configured VM and workspace", async () => {
  const run = runFixture();
  assert.equal(isRecordedSqlRun(run), true);
  const client = logsClient([]);
  for (const invalid of [
    { ...run, runId: "not-a-run" },
    { ...run, marker: `${run.marker}' | take 9999` },
    { ...run, correlationIdentity: "unrelated-real-login" },
    { ...run, completedAt: "2026-10-24T13:00:00Z" },
  ]) {
    assert.equal((await getRunAuditEvidence(invalid, { environment, client, now: () => clock })).state, "unavailable");
  }
  assert.equal((await getRunAuditEvidence(run, { environment: {}, client, now: () => clock })).state, "unavailable");
  assert.equal(client.calls.length, 0);
});

test("native audit queries are bounded and late arrivals retain the original event-time window", async () => {
  const run = runFixture();
  const client = logsClient([
    rowFixture(run),
    rowFixture(run, { _ResourceId: `${vmId}-other` }),
    rowFixture(run, { TimeGenerated: "2026-10-24T11:00:00Z" }),
    rowFixture(run, { RenderedDescription: "action_id:LGIS application_name:unrelated" }),
    rowFixture(run, { Source: "Other" }),
  ]);
  const result = await getRunAuditEvidence(run, { environment, client, now: () => clock });
  assert.equal(result.state, "observed");
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].time, "2026-10-24T12:00:02.000Z");
  assert.match(result.events[0].correlation, /marker or test identity/);
  const { query, interval, options } = client.calls[0];
  assert.ok(query.includes(vmId));
  assert.ok(query.includes(run.marker));
  assert.match(query, /EventID in \(33205, 18453, 18454, 18456\)/);
  assert.match(query, /take 26/);
  assert.doesNotMatch(query, /ingestion_time\(\)/);
  assert.equal(interval.startTime.toISOString(), "2026-10-24T11:58:00.000Z");
  assert.equal(interval.endTime.toISOString(), "2026-10-24T12:02:05.000Z");
  assert.equal(options.serverTimeoutInSeconds, 15);
  const serialized = JSON.stringify(result);
  for (const privateValue of ["private-service", "private-sid", "private-host", "10.2.3.4"])
    assert.ok(!serialized.includes(privateValue), privateValue);
});

test("sqlmap session evidence is explicitly weaker and cannot match another application's session", async () => {
  const run = { ...runFixture("suspicious-app"), sessionId: 67 };
  const description = "action_id:LGIS succeeded:true session_id:67 application_name:sqlmap database_name:FutonManufacturing";
  const client = logsClient([
    rowFixture(run, { RenderedDescription: description }),
    rowFixture(run, { RenderedDescription: description.replace("sqlmap", "another-app") }),
  ]);
  const result = await getRunAuditEvidence(run, { environment, client, now: () => clock });
  assert.equal(result.events.length, 1);
  assert.match(result.events[0].correlation, /session reuse remains possible/);
  assert.match(client.calls[0].query, /ObservedSession == 67/);
});

test("empty, partial, capped and denied native queries remain distinct from a negative verdict", async () => {
  const run = runFixture();
  const empty = await getRunAuditEvidence(run, { environment, client: logsClient([]), now: () => clock });
  assert.equal(empty.state, "none-yet");
  assert.match(formatNativeEvidence(empty), /not proof/);
  const partial = await getRunAuditEvidence(run, { environment, client: logsClient([rowFixture(run)], "PartialFailure"), now: () => clock });
  assert.equal(partial.state, "partial");
  assert.equal(partial.events.length, 1);
  const capped = await getRunAuditEvidence(run, { environment, client: logsClient(Array.from({ length: 26 }, () => rowFixture(run))), now: () => clock });
  assert.equal(capped.events.length, 25);
  assert.equal(capped.truncated, true);
  assert.equal(capped.state, "partial");
  const denied = await getRunAuditEvidence(run, {
    environment, now: () => clock,
    client: { queryWorkspace: async () => { throw new Error("private upstream credential"); } },
  });
  assert.equal(denied.state, "unavailable");
  assert.ok(!JSON.stringify(denied).includes("private upstream credential"));
});

test("capture publication projects actual fields, redacts secrets and retains uncertain Defender attribution", () => {
  const run = runFixture();
  run.dataMode = "synthetic";
  run.executionEvidence = { source: "SQL Server execution response", password: "never-publish", queryResult: { BaselineMatches: 1, SafeMatches: 0, UnsafeMatches: 4, QuoteProbeError: 105, hidden: "never-publish" } };
  const capture = createWalkthroughCapture({
    run,
    nativeEvidence: { state: "observed", checkedAt: new Date(clock).toISOString(), window: null, events: [{ message: "password=N'never-publish' client_ip:10.2.3.4", secret: "never-publish" }] },
    evidence: { state: "possible", checkedAt: new Date(clock).toISOString(), detail: "Time match only.", blocking: "Not confirmed.", alerts: [{ id: "alert-fixture", title: "Candidate", type: "SQL.VM_PotentialSqlInjection", correlated: false, description: "From 10.2.3.4; password='never-publish'", private: "never-publish" }] },
  });
  assert.ok(!JSON.stringify(capture).includes("never-publish"));
  assert.ok(!JSON.stringify(capture).includes("10.2.3.4"));
  assert.equal(capture.defender.alerts[0].correlated, false);
  assert.equal(capture.run.dataMode, "synthetic");
  assert.match(formatDefenderEvidence(capture.defender), /not confirmed run matches/);
  assert.deepEqual(capture.run.executionEvidence.queryResult, { BaselineMatches: 1, SafeMatches: 0, UnsafeMatches: 4, QuoteProbeError: 105 });
  assert.equal(recordedCaptureFor({ schemaVersion: 1, scenarios: [capture] }, run.scenario), capture);
  assert.throws(() => createWalkthroughCapture({ run }), /both actual evidence/);
  assert.throws(() => recordedCaptureFor({ schemaVersion: 2, scenarios: [] }, run.scenario), /Unsupported/);
  assert.match(redactEvidenceText("x".repeat(3000), run), /excerpt truncated/);
});

test("capture credentials are restricted to configured HTTPS origins", () => {
  const config = { environments: { dev: { webAppName: "pawton-test", webAppCustomDomain: "pawton.example" } } };
  assert.equal(validatedCaptureOrigin("https://pawton.example/", config), "https://pawton.example");
  for (const origin of ["http://pawton.example", "https://evil.example", "https://user:password@pawton.example", "https://pawton.example:444", "https://pawton.example/path", "https://pawton.example/?token=value"])
    assert.throws(() => validatedCaptureOrigin(origin, config), /configured Pawton/);
});

function captureTransport() {
  const calls = [];
  const runs = new Map();
  const fetchRequest = async (url, options = {}) => {
    calls.push({ url, options });
    const request = new URL(url);
    if (request.pathname === "/health")
      return Response.json({ status: "healthy", database: "connected" });
    if (request.pathname === "/walkthrough")
      return new Response('<div data-defender-sql-tier="Standard"></div>');
    if (request.pathname === "/api/admin/login")
      return new Response(null, { status: 303, headers: { "Set-Cookie": `${SESSION_COOKIE_NAME}=only-in-test; Secure; HttpOnly` } });
    if (options.method === "POST") {
      const scenario = options.body.get("simulation");
      const run = runFixture(scenario);
      runs.set(run.runId, run);
      return Response.json(run);
    }
    const run = runs.get(request.searchParams.get("runId"));
    return Response.json({
      run,
      nativeEvidence: { state: "observed", checkedAt: new Date(clock).toISOString(), events: [{ time: run.startedAt, message: run.marker }], window: null },
      evidence: { state: "correlated", checkedAt: new Date(clock).toISOString(), detail: "Run marker matched.", alerts: [{ id: "fixture", correlated: true }] },
    });
  };
  return { calls, runs, fetchRequest };
}

test("operator capture executes each fixed scenario once, resumes without re-execution, and never publishes authentication", async () => {
  const transport = captureTransport();
  const checkpoints = [];
  const options = {
    origin: "https://pawton.example", username: "admin-fixture", password: "credential-not-for-publication",
    observeSeconds: 0, fetchRequest: transport.fetchRequest, now: () => clock,
    pause: async () => {}, progress: () => {},
    checkpoint: async (bundle) => checkpoints.push(structuredClone(bundle)),
  };
  const capture = await captureWalkthrough(options);
  assert.equal(capture.scenarios.length, 6);
  assert.equal(new Set(capture.scenarios.map(({ run }) => run.runId)).size, 6);
  assert.equal(capture.protectionAtStart.tier, "Standard");
  assert.equal(capture.protectionAtEnd.tier, "Standard");
  assert.equal(capture.defenderDisabledForComparison, false);
  const activity = transport.calls.filter(({ url, options }) => new URL(url).pathname === "/api/admin/defender-simulation" && options.method === "POST");
  assert.equal(activity.length, 6);
  assert.ok(activity.every(({ options }) => options.body.get("confirm") === "yes" && options.body.get("sourceMode") === "fixed"));
  for (const checkpoint of checkpoints) {
    const text = JSON.stringify(checkpoint);
    assert.ok(!text.includes(options.password));
    assert.ok(!text.includes(`${SESSION_COOKIE_NAME}=only-in-test`));
  }
  transport.calls.length = 0;
  await captureWalkthrough({ ...options, previous: capture });
  assert.equal(transport.calls.filter(({ url, options }) => new URL(url).pathname === "/api/admin/defender-simulation" && options.method === "POST").length, 0);
});

test("operator capture does not retry an uncertain activity POST", async () => {
  const transport = captureTransport();
  let activities = 0;
  await assert.rejects(captureWalkthrough({
    origin: "https://pawton.example", username: "fixture", password: "fixture-secret",
    observeSeconds: 0, pause: async () => {}, progress: () => {}, now: () => clock,
    fetchRequest: async (url, options) => {
      if (new URL(url).pathname === "/api/admin/defender-simulation" && options.method === "POST") {
        activities++;
        throw new Error("uncertain transport failure");
      }
      return transport.fetchRequest(url, options);
    },
  }), /uncertain transport failure/);
  assert.equal(activities, 1);
});

test("walkthrough shows actual recorded/live sources without fabricating an alert on timeout", async () => {
  const root = new URL("../apps/pawton-manufacturing/src/", import.meta.url);
  const page = await readFile(new URL("pages/walkthrough.astro", root), "utf8");
  assert.match(page, /Captured native audit excerpts/);
  assert.match(page, /Captured Defender observations/);
  assert.match(page, /same protected run/);
  assert.match(page, /Defender is not disabled/);
  assert.match(page, /Expected alert reference \(not a captured detection\)/);
  assert.match(page, /if \(latest\) renderEvidence\(box, latest\.evidence, latest\.nativeEvidence, true\)/);
  assert.doesNotMatch(page, /renderEvidence\(box, \{ state: 'none'/);
  assert.match(page, /Refresh evidence only \(do not rerun\)/);
  const saved = JSON.parse(await readFile(new URL("data/walkthrough-capture.json", root), "utf8"));
  assert.equal(saved.schemaVersion, 1);
  assert.equal(saved.defenderDisabledForComparison, false);
  for (const capture of saved.scenarios) assert.equal(isRecordedSqlRun(capture.run), true);
});
