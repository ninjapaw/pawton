const runIdPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

export function isRecordedSqlRun(run) {
  const started = Date.parse(run?.startedAt);
  const completed = Date.parse(run?.completedAt);
  return Boolean(
    runIdPattern.test(run?.runId || "") &&
      /^[a-z][a-z-]{1,39}$/.test(run?.scenario || "") &&
      run.marker === `dojo-attack-test:${run.scenario}:${run.runId}` &&
      (!run.correlationIdentity ||
        [`dojo_invalid_${run.runId.replaceAll("-", "")}`, `dojo_probe_${run.runId.replaceAll("-", "")}`]
          .includes(run.correlationIdentity)) &&
      Number.isFinite(started) &&
      Number.isFinite(completed) &&
      completed >= started &&
      completed - started <= 300000,
  );
}

export function redactEvidenceText(value, run = {}, limit = 2400) {
  if (value === null || value === undefined) return null;
  const testNames = new Set(
    runIdPattern.test(run.runId || "")
      ? [
          `dojo_invalid_${run.runId.replaceAll("-", "")}`,
          `dojo_probe_${run.runId.replaceAll("-", "")}`,
        ]
      : [],
  );
  const text = String(value)
    .replace(
      /((?:^|\s)(?:server_principal_name|session_server_principal_name|target_server_principal_name|database_principal_name|server_principal_sid|session_server_principal_sid|database_principal_sid|server_instance_name|client_hostname|client_ip|address):)([\s\S]*?)(?=\s+[A-Za-z_][A-Za-z0-9_]*:|$)/gi,
      (_, label, field) =>
        `${label}${testNames.has(field.trim()) ? field.trim() : "[redacted]"}`,
    )
    .replace(
      /((?:password|pwd|access_token|secret|authorization|sig)\s*[:=]\s*)(?:Bearer\s+[^\s;]+|N?'(?:''|[^'])*'|"[^"]*"|[^\s;&]+)/gi,
      "$1[redacted]",
    )
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[redacted IP]");
  return text.length > limit
    ? `${text.slice(0, limit)}\n[excerpt truncated at ${limit} characters]`
    : text;
}

function executionFields(run) {
  const source = run.executionEvidence || {};
  const result = {};
  for (const key of [
    "source",
    "testIdentity",
    "authenticationFailures",
    "applicationName",
    "databaseName",
    "sessionId",
    "readRows",
    "shellEnabled",
    "exitCode",
  ]) {
    const value = source[key];
    if (typeof value === "string")
      result[key] = redactEvidenceText(value, run);
    else if (typeof value === "boolean" || Number.isFinite(value))
      result[key] = value;
  }
  if (Array.isArray(source.stdout))
    result.stdout = source.stdout
      .filter((value) => typeof value === "string" && value.includes(run.marker))
      .slice(0, 5)
      .map((value) => redactEvidenceText(value, run));
  if (source.queryResult) {
    result.queryResult = Object.fromEntries(
      ["BaselineMatches", "SafeMatches", "UnsafeMatches", "QuoteProbeError"]
        .filter((key) => Number.isInteger(source.queryResult[key]))
        .map((key) => [key, source.queryResult[key]]),
    );
  }
  return result;
}

export function createWalkthroughCapture(payload, capturedAt = new Date().toISOString()) {
  const { run, nativeEvidence, evidence } = payload || {};
  if (
    !isRecordedSqlRun(run) ||
    !Number.isFinite(Date.parse(capturedAt)) ||
    !nativeEvidence ||
    !Array.isArray(nativeEvidence.events) ||
    !evidence ||
    !Array.isArray(evidence.alerts)
  )
    throw new Error("A recorded run and both actual evidence responses are required.");
  return {
    capturedAt,
    run: {
      runId: run.runId,
      scenario: run.scenario,
      marker: run.marker,
      startedAt: run.startedAt,
      completedAt: run.completedAt,
      state: run.state,
      ...(["synthetic", "lab-table"].includes(run.dataMode) ? { dataMode: run.dataMode } : {}),
      ...(["fixed", "unique"].includes(run.sourceMode) ? { sourceMode: run.sourceMode } : {}),
      ...(typeof run.sourceUrl === "string" ? { sourceUrl: redactEvidenceText(run.sourceUrl, run) } : {}),
      sqlProtection: redactEvidenceText(run.sqlProtection, run),
      outcome: redactEvidenceText(run.outcome, run),
      executionEvidence: executionFields(run),
    },
    native: {
      source: "Log Analytics Event / Application / MSSQLSERVER",
      checkedAt: nativeEvidence.checkedAt,
      state: nativeEvidence.state,
      detail: redactEvidenceText(nativeEvidence.detail, run),
      window: nativeEvidence.window,
      truncated: Boolean(nativeEvidence.truncated),
      events: nativeEvidence.events.slice(0, 25).map((event) => ({
        time: event.time,
        eventId: event.eventId,
        action: event.action,
        operation: event.operation,
        success: event.success,
        application: redactEvidenceText(event.application, run),
        database: redactEvidenceText(event.database, run),
        correlation: event.correlation,
        statement: redactEvidenceText(event.statement, run, 1200),
        message: redactEvidenceText(event.message, run),
      })),
    },
    defender: {
      source: "Microsoft Defender for Cloud alerts API",
      checkedAt: evidence.checkedAt,
      state: evidence.state,
      detail: redactEvidenceText(evidence.detail, run),
      blocking: evidence.blocking,
      alerts: evidence.alerts.slice(0, 10).map((alert) => ({
        id: alert.id,
        title: redactEvidenceText(alert.title, run),
        type: alert.type,
        severity: alert.severity,
        status: alert.status,
        startedAt: alert.startedAt,
        endedAt: alert.endedAt,
        description: redactEvidenceText(alert.description, run),
        correlated: Boolean(alert.correlated),
        correlation: alert.correlation,
      })),
    },
  };
}

/** @returns {ReturnType<typeof createWalkthroughCapture> | null} */
export function recordedCaptureFor(bundle, scenario) {
  if (bundle?.schemaVersion !== 1 || !Array.isArray(bundle.scenarios))
    throw new Error("Unsupported walkthrough capture format.");
  return bundle.scenarios.find((capture) => capture.run.scenario === scenario) || null;
}

export function formatNativeEvidence(native) {
  if (!native) return "No native audit query has been captured for this run.";
  return [
    `Source: ${native.source || "Log Analytics Event / Application / MSSQLSERVER"}`,
    `Checked: ${native.checkedAt || "not queried"}`,
    `State: ${native.state}`,
    native.window
      ? `Event window: ${native.window.start} to ${native.window.end}`
      : "",
    native.detail || "",
    native.events?.length
      ? `${native.events.length} captured record(s); showing the first ${Math.min(5, native.events.length)} redacted excerpts.\n${JSON.stringify(native.events.slice(0, 5), null, 2)}`
      : "No matching native records were returned. This is not proof that no activity occurred.",
  ].filter(Boolean).join("\n");
}

export function formatDefenderEvidence(defender) {
  if (!defender) return "No Defender query has been captured for this run.";
  return [
    "Source: Microsoft Defender for Cloud alerts API",
    `Checked: ${defender.checkedAt || "not queried"}`,
    `State: ${defender.state}`,
    defender.detail || "",
    defender.alerts?.length
      ? JSON.stringify(defender.alerts, null, 2)
      : "No matching alert was returned in this observation window. This does not prove no detection or that Defender was off.",
    "Alert presence is not proof of prevention. Time/family candidates are not confirmed run matches.",
  ].filter(Boolean).join("\n");
}

export function formatExecutionEvidence(run) {
  return JSON.stringify({
    runId: run.runId,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    state: run.state,
    dataMode: run.dataMode,
    sourceMode: run.sourceMode,
    sourceUrl: run.sourceUrl,
    marker: run.marker,
    sqlProtection: run.sqlProtection,
    outcome: run.outcome,
    executionEvidence: run.executionEvidence,
  }, null, 2);
}
