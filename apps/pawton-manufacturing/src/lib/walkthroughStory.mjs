// Content for the guided Defender for SQL walkthrough (/walkthrough).
//
// Alert names, alert types, severities, and MITRE tactics are quoted from Microsoft's published
// reference (alertReference below). The attacker, times, and log excerpts are fictional. Every
// live run reuses the bounded tests in sqlAttackLab.mjs; this module adds no new SQL activity.
//
// Inline text may reference glossary entries with {{key}} or {{key|display text}}; the page turns
// them into accessible tooltips, and scripts/test-walkthrough.mjs rejects unknown keys.

export const alertReference =
  "https://learn.microsoft.com/azure/defender-for-cloud/alerts-sql-database-and-azure-synapse-analytics";
export const pricingReference =
  "https://azure.microsoft.com/pricing/details/defender-for-cloud/";

// Only tests that connect as the least-privileged application login are runnable by the guide
// account. Tests that need the CONTROL SERVER admin-portal login stay admin-only in the Security lab.
export const walkthroughRunnableScenarios = Object.freeze([
  "brute-force",
  "suspicious-app",
  "sql-injection",
]);

export const glossary = {
  defender: {
    term: "Defender for SQL",
    definition:
      "The Microsoft Defender for Cloud plan that watches SQL Server activity for attack patterns (brute force, injection, harmful tools, shell abuse) and raises security alerts with context and remediation steps.",
  },
  sqlvm: {
    term: "Defender for SQL servers on machines",
    definition:
      "The Defender for SQL variant for SQL Server running on a VM or on-premises machine. It is enabled per subscription (the SqlServerVirtualMachines plan) and uses an extension on the VM.",
  },
  audit: {
    term: "SQL Server Audit",
    definition:
      "Built-in SQL Server logging of who did what. It is an evidence trail, not a detector: it records events but never tells you which of them are an attack.",
  },
  event18456: {
    term: "Event 18456",
    definition:
      "The SQL Server 'Login failed for user' error. Internet-facing servers can log thousands a day, which is why a person reading logs rarely spots the one that matters.",
  },
  event33205: {
    term: "Event 33205",
    definition:
      "The Windows Application log event SQL Server Audit writes for each audited action. Pawton forwards it to Log Analytics so it appears on the Auditing page.",
  },
  port1433: {
    term: "TCP 1433",
    definition:
      "SQL Server's default listening port. Internet scanners sweep it continuously; a server reachable on 1433 from the internet sees login attempts within hours.",
  },
  nsg: {
    term: "NSG",
    definition:
      "Network security group: Azure's allow/deny rules for traffic to a subnet or network interface. Closing 1433 to the internet is prevention; Defender for SQL is detection.",
  },
  sa: {
    term: "sa",
    definition:
      "SQL Server's built-in administrator login and the first name every attacker tries. In Pawton it stays disabled for demos, and scripts use a separate Key Vault-backed login instead.",
  },
  keyvault: {
    term: "Key Vault",
    definition:
      "Azure's managed secret store. Pawton keeps every SQL credential there so no script or page embeds a password.",
  },
  sqlmap: {
    term: "sqlmap",
    definition:
      "A widely used open-source SQL injection and database takeover tool. By default it identifies itself in the SQL client application name, which Defender for SQL recognizes.",
  },
  appname: {
    term: "application name",
    definition:
      "A free-text label every SQL client sends when it connects. A useful detection signal, but never an authorization rule, because the caller chooses it.",
  },
  sqli: {
    term: "SQL injection",
    definition:
      "Tricking an application into running attacker-supplied SQL by pasting untrusted input into a query. Parameterized queries prevent it.",
  },
  parameterized: {
    term: "parameterized query",
    definition:
      "A query where user input is sent as a typed parameter instead of being pasted into the SQL text, so input can never change the query's structure.",
  },
  waf: {
    term: "WAF",
    definition:
      "Web application firewall. It inspects HTTP requests that pass through it, but it never sees the SQL session between the application and the database.",
  },
  principal: {
    term: "principal",
    definition:
      "Any identity SQL Server can authenticate or authorize: a login, a database user, or a role.",
  },
  xpcmdshell: {
    term: "xp_cmdshell",
    definition:
      "A SQL Server procedure that runs operating-system commands as the SQL Server service account. Disabled by default; attackers enable it to break out of the database.",
  },
  obfuscation: {
    term: "obfuscation",
    definition:
      "Hiding a command's intent, for example building 'xp_' + 'cmdshell' from fragments or base64-encoding PowerShell, so simple keyword searches of logs miss it.",
  },
  mitre: {
    term: "MITRE tactic",
    definition:
      "The attack stage an alert represents, such as Pre-Attack, Exploitation, or Execution. Defender labels every alert with one, so you can see how far an intruder has progressed.",
  },
  severity: {
    term: "alert severity",
    definition:
      "Defender's triage signal: High, Medium, Low, or Informational. Informational alerts are context; they matter most inside a chain of higher-severity alerts.",
  },
  sentinel: {
    term: "Microsoft Sentinel",
    definition:
      "Microsoft's cloud SIEM. It ingests Defender alerts and correlates them into incidents, so a brute force, a harmful tool, and a shell command become one story instead of three tickets.",
  },
  incident: {
    term: "incident",
    definition:
      "A group of related alerts correlated into a single attack story that an analyst can investigate and close.",
  },
};

export const chapters = [
  {
    id: "briefing",
    kind: "briefing",
    clock: "Friday, 20:55",
    title: "Your shift at Pawton",
    lead: "You are the on-call security analyst for Pawton Manufacturing. Everything the company sells runs through one SQL Server on an Azure VM: customer accounts, negotiated prices, orders, and shipments.",
    story: [
      "Tonight a fictional intruder called Ghostpaw is coming for that database. You'll see each move twice: first as a team without {{defender}} experiences it, then as Defender for SQL reports it.",
      "Three moves are real, bounded activity you can run against this lab's SQL Server from this page. The other two are narrative, because running them needs administrator rights the guide account deliberately does not have.",
      "Hover over or focus any dotted term for a plain-language definition. Use the arrow keys or the Next button to move through the night.",
    ],
    takeaway:
      "The question this story answers: if this happened on your SQL Server tonight, who would know, how soon, and with enough context to act?",
  },
  {
    id: "brute-force",
    kind: "attack",
    scenario: "brute-force",
    clock: "21:04",
    act: "Act 1 · Knocking on the door",
    title: "Password spraying the SQL listener",
    attacker:
      "Ghostpaw's scanner finds {{port1433}} answering on Pawton's public IP. Next come login attempts: {{sa}} first, then common names, then leaked passwords.",
    without: {
      headline: "A few more lines in a very long log",
      detail:
        "Each attempt becomes an {{event18456}} line in the SQL error log and, if audited, an {{event33205}} record. There is no severity, no grouping by source, and nobody reading the error log on a Friday night.",
      evidence:
        "Error: 18456, Severity: 14, State: 5.\nLogin failed for user 'sa'. Reason: Could not find a login matching the name provided. [CLIENT: 203.0.113.47]\nLogin failed for user 'admin'. Reason: Could not find a login matching the name provided. [CLIENT: 203.0.113.47]\n... repeated 4,211 more times since Tuesday",
    },
    with: {
      alert: "Suspected brute force attack",
      alertType: "SQL.VM_BruteForce",
      severity: "High",
      tactic: "Pre-Attack",
      detail:
        "Defender groups the attempts into one alert with the source IP, targeted logins, and attempt count. Two variants escalate it: 'using a valid user' means the attacker found a real account name, and 'successful brute force attack' means they got in.",
    },
    why: "Brute force is noise until it isn't. The value is not seeing failed logins, which your log already has. It's being told, with a High {{severity|alert severity}} and context, when background scanning turns into a targeted attack on a real account.",
    controls: [
      "Close {{port1433}} to the internet with an {{nsg}} or a private endpoint. That's prevention; Defender is detection. You want both.",
      "Keep {{sa}} disabled and use named, least-privileged logins. Pawton's scripts authenticate with a dedicated login fetched from {{keyvault}}, never the built-in administrator.",
      "Route Defender alerts to {{sentinel}} or email so a High alert reaches a person, not just a dashboard.",
    ],
    live: {
      summary:
        "Makes twelve SQL connection attempts with a random, nonexistent login and random passwords. No real account is targeted and nothing can succeed.",
      note: "Twelve failures prove SQL rejected them. They are not guaranteed to cross Defender's brute-force threshold, and the page says so rather than implying an alert.",
    },
    presenter:
      "Ask the room how many failed SQL logins their servers logged last week, and who looked at them. Then point out that the alerts that matter are the valid-user and successful variants.",
  },
  {
    id: "suspicious-app",
    kind: "attack",
    scenario: "suspicious-app",
    clock: "21:19",
    act: "Act 2 · Bringing the tools",
    title: "An attack tool announces itself",
    attacker:
      "Guessing is slow, so Ghostpaw switches to {{sqlmap}}. Out of the box it identifies itself in the SQL {{appname}} while it fingerprints the server and lists tables.",
    without: {
      headline: "A label nobody records",
      detail:
        "The {{appname}} appears in live session views only while the connection is open. Unless you built custom auditing for it, it's gone the moment Ghostpaw disconnects, and the queries themselves look like ordinary metadata reads.",
      evidence:
        "session_id  login_name  program_name  status\n----------  ----------  ------------  --------\n67          futon_app   sqlmap        sleeping\n(row disappears when the session closes)",
    },
    with: {
      alert: "Logon activity from a potentially harmful application",
      alertType: "SQL.VM_HarmfulApplication",
      severity: "High",
      tactic: "Pre-Attack",
      detail:
        "Defender recognizes known attack tools by their client signature and raises a High alert naming the application, login, and source, even when the login attempt fails. This is the same alert family behind the 'Failed logon attempt from a potentially harmful application' notifications Pawton receives from real internet scanners.",
    },
    why: "Attack tools rarely hide the first time. A named tool connecting to your database is one of the clearest, lowest-false-positive signals you can get, and without Defender it is almost never captured.",
    controls: [
      "Allow SQL connections only from approved hosts with network rules; an attack tool on the internet should never reach the listener.",
      "Grant application logins only the permissions they need, so reconnaissance reveals as little as possible.",
      "Never use the {{appname}} as an access control. Treat it as a detection signal only, because the caller chooses it.",
    ],
    live: {
      summary:
        "Connects as the least-privileged application login with the client name sqlmap, reads session metadata, and lists up to five table names. No business rows are read and no tool is installed.",
      note: "The client name is only a signal. Before attributing an alert to this run, check that its time, login, and client match; an older alert of the same type isn't evidence of this run.",
    },
    presenter:
      "If you have seen the 'potentially harmful application' alert on this environment, this is the moment to show it: those came from real scanners on the internet, not from this demo.",
  },
  {
    id: "sql-injection",
    kind: "attack",
    scenario: "sql-injection",
    clock: "21:37",
    act: "Act 3 · Through the front counter",
    title: "One quote mark crosses customer boundaries",
    attacker:
      "Rather than attack the database directly, Ghostpaw uses Pawton's own order lookup. A legacy query pastes the order number into SQL text, so {{sqli|SQL injection}} input like PW-1042' OR 1=1 -- returns every customer's orders.",
    without: {
      headline: "Nothing fails, so nothing looks wrong",
      detail:
        "From the database's point of view this is valid SQL from the trusted application login. It succeeds, returns rows, and raises no error. A {{waf}} may never see it if the lookup is called from an internal service, and it can't see the SQL session at all.",
      evidence:
        "SELECT ... FROM Orders\nWHERE CustomerCode = N'CUS-100'\n  AND OrderNumber = N'PW-1042' OR 1=1 --'\n(4 rows affected)   <- expected 1",
    },
    with: {
      alert: "Potential SQL injection",
      alertType: "SQL.VM_PotentialSqlInjection",
      severity: "High",
      tactic: "Pre-Attack",
      detail:
        "Defender analyzes the statements the database actually runs, so it can flag an injected query even when the web tier saw nothing unusual. The alert identifies the application, login, and statement, which points developers at the vulnerable code path.",
    },
    why: "Injection turns your own application into the attacker's client, carrying all of its permissions. The database layer is the one place that sees the final, injected statement, which is why detection there catches what web-tier controls miss.",
    controls: [
      "Fix the code: use a {{parameterized}} for every user-supplied value. The live test shows it matching zero rows for the same input.",
      "Give the application login only the tables and actions it needs, so a successful injection exposes as little as possible.",
      "Keep a {{waf}} for HTTP-layer filtering, and rely on Defender for SQL for what reaches the database.",
    ],
    live: {
      summary:
        "Runs the vulnerable and the parameterized lookup side by side against a synthetic, in-memory four-order dataset. No business table is read or changed.",
      note: "This demonstrates the query-construction flaw and the fix. It doesn't imply Pawton's real order pages are vulnerable; they use parameterized queries.",
    },
    presenter:
      "Pause on the comparison counts: the same input matches four rows when concatenated and zero when parameterized. That one line of code is the difference.",
  },
  {
    id: "principal-anomaly",
    kind: "attack",
    scenario: "principal-anomaly",
    clock: "22:02",
    act: "Act 4 · Becoming someone else",
    title: "A principal nobody has seen in months",
    attacker:
      "With a foothold, Ghostpaw creates a quiet database {{principal}}, grants it read access, and impersonates it, hoping new activity blends in under an unfamiliar name.",
    without: {
      headline: "A new user, filed under 'probably a developer'",
      detail:
        "If {{audit}} captures principal changes, a CREATE USER and a GRANT are recorded. Nothing flags that the identity has never been used before, or connects it to the brute force an hour earlier.",
      evidence:
        "CREATE USER [svc_reporting2] WITHOUT LOGIN;\nGRANT SELECT ON dbo.Items TO [svc_reporting2];\nEXECUTE AS USER = 'svc_reporting2';",
    },
    with: {
      alert: "Login from a principal user not seen in 60 days",
      alertType: "SQL.VM_PrincipalAnomaly",
      severity: "Informational",
      tactic: "Exploitation",
      detail:
        "Defender learns which principals normally use the database and flags unfamiliar ones. On its own this is Informational. Next to a High brute-force alert from the same night, it's the step where the attacker became an insider.",
    },
    why: "Informational alerts are how Defender tells the rest of the story. Correlated in {{sentinel}}, this is the link between getting in and staying in.",
    controls: [
      "Review and restrict who can create principals and grant permissions.",
      "Correlate Defender alerts by resource in {{sentinel}} so low-severity anomalies surface when they follow high-severity ones.",
    ],
    adminOnly:
      "Creating and impersonating a principal needs the admin-portal SQL login, so this step is narrative for the guide account. An administrator can run it in the Security lab; every change is rolled back.",
    presenter:
      "Point out that this alert's severity is Informational on purpose. Ask whether anyone would have noticed it without the alerts before it.",
  },
  {
    id: "shell",
    kind: "attack",
    scenario: "obfuscated-shell",
    clock: "22:26",
    act: "Act 5 · Breaking out to the operating system",
    title: "From database to Windows shell",
    attacker:
      "Ghostpaw turns on {{xpcmdshell}} and runs PowerShell hidden behind {{obfuscation}}. Then comes the payoff: pulling a payload from an external server to take over the VM itself.",
    without: {
      headline: "The keyword search finds nothing",
      detail:
        "If you alert on the text 'xp_cmdshell', obfuscation defeats it: the procedure name is assembled at run time and the command is base64. The download looks like ordinary outbound HTTPS from a server.",
      evidence:
        "DECLARE @s nvarchar(max) = N'EXEC master.dbo.' + N'xp_' + N'cmdshell @c';\nEXEC sp_executesql @s, N'@c varchar(8000)',\n  @c = 'powershell -EncodedCommand VwByAGkAdABlAC0A...';",
    },
    with: {
      alert:
        "Unusual payload with obfuscated parts has been initiated by SQL Server",
      alertType: "SQL.VM_PotentialSqlInjection",
      severity: "High/Medium",
      tactic: "Execution",
      detail:
        "Defender looks at what SQL Server actually hands to the operating system, so string-building tricks don't hide it. A related alert, 'SQL Server potentially spawned a Windows command shell and accessed an abnormal external source' (SQL.VM_ShellExternalSourceAnomaly), flags the payload download.",
    },
    why: "This is the point where a database breach becomes a server breach. Detection here is the last good chance to contain Ghostpaw before persistence and lateral movement.",
    controls: [
      "Keep {{xpcmdshell}} disabled, and restrict who holds the permissions to re-enable it.",
      "Run SQL Server under a low-privileged service account and limit outbound internet access from the VM.",
      "Pair Defender for SQL with Defender for Servers so host-level process and network activity is covered too.",
    ],
    adminOnly:
      "Shell tests need the admin-portal SQL login and xp_cmdshell enabled, so this step is narrative for the guide account. An administrator can run the marker-only shell test and the hash-verified inert download in the Security lab; downloaded content is never executed.",
    presenter:
      "Show the obfuscated statement and ask what a log search for 'xp_cmdshell' would return. It's the clearest argument for behavioral detection over keyword rules.",
  },
  {
    id: "debrief",
    kind: "debrief",
    clock: "Saturday, 07:30",
    title: "Debrief: what Defender for SQL changed",
    lead: "Same night, same attacker, same logs. The difference is whether anyone was told, and whether the five moves arrived as five unrelated lines or as one {{incident}}.",
  },
];

// Side-by-side comparison rendered in the debrief.
export const valueComparison = [
  {
    question: "Would anyone be told tonight?",
    without: "Only if someone reads SQL error logs and audit tables by hand.",
    with: "Yes. High-severity alerts go to Defender for Cloud, email, and Sentinel.",
  },
  {
    question: "How is the brute force told apart from background scanning?",
    without: "It isn't. Every failed login looks the same.",
    with: "Separate alerts for any brute force, a valid user targeted, and a successful sign-in.",
  },
  {
    question: "Is the attack tool identified?",
    without: "Only while the session is open, and only if someone is looking.",
    with: "Named in a High alert, even when the login fails.",
  },
  {
    question: "Is injection through the app visible?",
    without: "No. It's valid SQL from a trusted login and it succeeds.",
    with: "Flagged from the statement the database actually runs.",
  },
  {
    question: "Does obfuscated shell use get caught?",
    without: "Keyword searches miss it by design.",
    with: "Detected from the payload SQL Server hands to the OS.",
  },
  {
    question: "Do the moves connect into one story?",
    without: "Five unrelated events across two logs.",
    with: "Tagged with MITRE tactics and correlated into one incident in Sentinel.",
  },
];

// Stated plainly so the walkthrough never oversells the product.
export const honestLimits = [
  "Defender for SQL detects and alerts. It doesn't block a query or a login inline; prevention comes from network restrictions, least privilege, and secure code.",
  "Anomaly alerts, such as a principal not seen in 60 days, depend on learned behavior and may not fire on a brand-new server.",
  "A bounded demo may not cross every detection threshold. When an alert doesn't appear, that's an honest result, not a failure of the story.",
];

export function chapterById(id) {
  return chapters.find((chapter) => chapter.id === id) || null;
}

const tokenPattern = /\{\{([a-z0-9]+)(?:\|([^}]+))?\}\}/g;

// Splits text with {{key}} or {{key|label}} tokens into plain-text and glossary segments.
export function segments(text) {
  const parts = [];
  let last = 0;
  for (const match of String(text).matchAll(tokenPattern)) {
    if (match.index > last)
      parts.push({ text: text.slice(last, match.index) });
    const entry = glossary[match[1]];
    parts.push(
      entry
        ? {
            key: match[1],
            text: match[2] || entry.term,
            definition: entry.definition,
          }
        : { text: match[2] || match[1] },
    );
    last = match.index + match[0].length;
  }
  if (last < text.length) parts.push({ text: text.slice(last) });
  return parts;
}

export function glossaryKeysIn(text) {
  return [...String(text).matchAll(tokenPattern)].map((match) => match[1]);
}