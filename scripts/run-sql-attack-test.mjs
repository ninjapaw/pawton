import {
  attackScenarios,
  sqlAttackRunner,
} from "../apps/pawton-manufacturing/src/lib/sqlAttackLab.mjs";
import { labTableInjectionQueries } from "../apps/pawton-manufacturing/src/lib/sqlInjectionProbe.mjs";
import {
  CredentialError,
  applySqlEnvironment,
} from "./lib/sql-credentials.mjs";

// Scenarios that need CONTROL SERVER. They run as dojo_platform_ops_svc (resolved from Key Vault),
// never as the built-in administrator, so a targeted attack run never produces an 'sa' sign-in.
const PRIVILEGED_SCENARIOS = new Set([
  "principal-anomaly",
  "external-source",
  "obfuscated-shell",
]);

const args = process.argv.slice(2);
if (args.length === 1 && ["--list", "--audit"].includes(args[0])) {
  console.log(
    JSON.stringify(
      {
        mode: "audit",
        executesSql: false,
        scenarios: attackScenarios,
        labTableInjection: {
          optIn:
            "--run sql-injection --confirm isolated-lab --data-mode lab-table",
          table: "dbo.Items",
          rowLimit: 5,
          returns: "counts only; IDs remain internal",
          queries: labTableInjectionQueries(
            "dojo-attack-test:sql-injection:11111111-1111-4111-8111-111111111111",
          ),
        },
      },
      null,
      2,
    ),
  );
} else if (
  (args.length === 4 ||
    (args.length === 6 &&
      args[4] === "--source-mode" &&
      args[5] === "unique" &&
      args[1] === "external-source") ||
    (args.length === 6 &&
      args[4] === "--data-mode" &&
      args[5] === "lab-table" &&
      args[1] === "sql-injection")) &&
  args[0] === "--run" &&
  args[2] === "--confirm" &&
  args[3] === "isolated-lab"
) {
  try {
    // Resolve credentials best-effort: scenario preconditions (feature flags, confirmation
    // gates) must still report their own errors rather than being masked by a Key Vault lookup.
    try {
      await applySqlEnvironment({
        privileged: PRIVILEGED_SCENARIOS.has(args[1]),
      });
    } catch (credentialError) {
      if (!(credentialError instanceof CredentialError)) throw credentialError;
      console.error(credentialError.message);
    }
    const result = await sqlAttackRunner.run(args[1], {
      sourceMode: args[4] === "--source-mode" ? args[5] : "fixed",
      dataMode: args[4] === "--data-mode" ? args[5] : "synthetic",
    });
    console.log(JSON.stringify(result, null, 2));
    if (result.state === "blocked") process.exitCode = 2;
  } catch (error) {
    if (error.run) console.error(JSON.stringify(error.run, null, 2));
    console.error(error.message);
    process.exitCode = 1;
  }
} else {
  console.error(
    "Usage: node scripts/run-sql-attack-test.mjs --audit | --list | --run <scenario-id> --confirm isolated-lab [--source-mode unique (external-source only) | --data-mode lab-table (sql-injection only; reads at most five dbo.Items IDs per query)]",
  );
  process.exitCode = 2;
}
