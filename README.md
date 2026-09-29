# Pawton

> **Independent community project.** This repository is not a Microsoft product,
> assessment, endorsement, or official security guidance. Some contributors may be
> Microsoft employees acting in an individual or community capacity. Use at your
> own risk and validate all demo behavior before using it in any environment. See
> [DISCLAIMER.md](DISCLAIMER.md).

**Pawton** is a self-contained, demo-in-a-box Azure security environment: SQL Server 2022 on
an Azure VM, protected end to end by **Microsoft Defender for Servers Plan 2**, **Microsoft
Defender for SQL**, and **Microsoft Sentinel**, with **Pawton Manufacturing** — a real, running
Astro/Node.js dashboard — making the story tangible instead of leaving it as infrastructure
evidence alone. It was split out of [`ninjapaws-cloud-security-dojo`](https://github.com/ninjapaw/ninjapaws-cloud-security-dojo)
into its own repository so this scenario has a single, simple, disposable home.

Use only an isolated, authorized training subscription. This repository intentionally includes
privileged SQL operations and bounded, real attack-test tooling. Azure resources, Defender
plans, and Sentinel can incur charges. Never use real customer data or expose the lab to
untrusted users.

## Deploy to Azure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fninjapaw%2Fpawton%2Fdev%2Fazuredeploy.json)

The button opens the Azure portal's built-in ARM deployment form for `azuredeploy.json` (a
copy of [`infra/sql-defender-scenario/main.json`](infra/sql-defender-scenario/main.json)) so you
can review and deploy the infrastructure directly from the portal. It provisions the VM, SQL
Server, Key Vault, Bastion, Log Analytics workspace, and the Pawton Manufacturing Web App —
but several parameters (VM admin credentials, SQL login passwords, the admin/manager portal
secrets, and the bootstrap script URL) have **no default** and must be filled in the form,
because this repository never invents a persisted password on your behalf outside the wizard.

**For the full guided experience — infrastructure, SQL bootstrap, secrets, and the deployment
report — use the [wizard](#quick-start) instead of the button.** The button is the fastest way
to inspect or fork the template in the portal; the wizard is the supported way to run the demo.

## Contents

- [Quick start](#quick-start)
- [What this deploys](#what-this-deploys)
- [Pawton Manufacturing: the live demo site](#pawton-manufacturing-the-live-demo-site)
- [Admin portal: a deliberate anti-pattern, not a template](#admin-portal-a-deliberate-anti-pattern-not-a-template)
- [Sentinel SQL detection content](#sentinel-sql-detection-content)
- [Portal setup and configuration](#portal-setup-and-configuration)
- [Direct SQL attack tests](#direct-sql-attack-tests)
- [Configuration](#configuration)
- [Workflows](#workflows)
- [Contributing](CONTRIBUTING.md), [security reporting](SECURITY.md), and [disclaimer](DISCLAIMER.md)

## Quick start

Prerequisites: Git, Node.js 24 (see `.node-version`), Bash, and Azure CLI. GitHub OIDC bootstrap
additionally requires GitHub CLI.

```bash
git clone https://github.com/ninjapaw/pawton.git
cd pawton
npm ci
npm ci --prefix apps/pawton-manufacturing
```

The wizard is the recommended way to deploy, repair, or remove the environment. It detects
`dev`/`prod` from the current Git branch and offers only the actions that make sense for the
current state:

```bash
npm run wizard
# or directly:
bash scripts/manage.sh
```

It walks through:

1. **Plan** — offline, shows what would be deployed, no Azure credentials required.
2. **Doctor** — read-only Azure preflight (login, subscription, Bicep what-if).
3. **Deploy** — provisions the VM, SQL Server, Defender plans, Sentinel workspace, Key Vault, and
   the Pawton Manufacturing dashboard, then seeds the Futon Manufacturing sample database.
4. **Repair** — re-runs deploy against an existing environment; the SQL bootstrap and Bicep
   deployment are idempotent, so this repairs missing audit specs, extensions, or secrets
   without re-provisioning what's already correct.
5. **Configure custom domain** — Cloudflare DNS + managed TLS for the dashboard, isolated from
   the rest of the lifecycle so it can be repeated safely.
6. **Deploy Sentinel analytics content** — the SQL detection rules, hunting queries, and parser
   described in [Sentinel SQL detection content](#sentinel-sql-detection-content).
7. **Uninstall** — deletes the environment's resource group after typing its exact name back as
   confirmation.

Direct automation (CI, scripting) uses `scripts/deploy.sh` without the menu:

```bash
bash scripts/deploy.sh plan --environment dev
bash scripts/deploy.sh doctor --environment dev
bash scripts/deploy.sh deploy --environment dev --yes
bash scripts/deploy.sh uninstall --environment dev --yes
```

One-time GitHub Actions / OIDC bootstrap (run once per GitHub Environment):

```bash
az login
gh auth login
bash scripts/setup-azure-github-oidc.sh --environment dev --defaults
bash scripts/setup-azure-github-oidc.sh --environment prod --defaults
```

This creates one Entra federated-credential application per environment (no client secret),
grants it Contributor and Role Based Access Control Administrator on the scenario's resource
group, and grants Security Admin at subscription scope so Defender plan activation works. Store
the printed `AZURE_CLIENT_ID`/`AZURE_TENANT_ID`/`AZURE_SUBSCRIPTION_ID`/`AZURE_LOCATION` values
as GitHub Environment **variables** (not secrets) so [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml)
can run `workflow_dispatch` for `plan`, `doctor`, `deploy`, `domain`, and `uninstall`.

## What this deploys

SQL Server 2022 on a Windows Server 2022 Azure VM (the official
`MicrosoftSQLServer:sql2022-ws2022` marketplace image), seeded with the [Futon Manufacturing
sample database](https://github.com/microsoft/sql-server-samples/tree/master/samples/databases/futon-manufacturing)
from `microsoft/sql-server-samples`, demonstrating full IaaS-workload coverage: **Microsoft
Defender for Servers Plan 2** (automatic Microsoft Defender for Endpoint onboarding,
vulnerability assessment, Just-In-Time VM access, and file integrity monitoring) and **Microsoft
Defender for SQL** (SQL-specific threat detection and vulnerability assessment for the database
engine), with detections and hunting content forwarded to **Microsoft Sentinel**.

Security posture baked into the infrastructure:

- The SQL Server VM has a public endpoint for training clients on TCP 1433, protected by the VM
  NSG; Azure Bastion remains available for browser-based RDP.
- RDP over Bastion is available immediately: a standing NSG rule (`AllowBastionRdp`) permits RDP
  from the Bastion subnet without first approving a Defender for Cloud Just-in-Time access
  request. The JIT policy itself stays configured (Defender for Servers Plan 2 still reports and
  manages it), but its NSG deny rule is overridden by the explicit allow rule. Set
  `autoAllowBastionRdp` to `false` (in `config/deploy.config.json` or as a Bicep parameter) to
  require a JIT request before every RDP session instead.
- The VM is registered with the SQL IaaS Agent extension
  (`Microsoft.SqlVirtualMachine/sqlVirtualMachines`), so Azure manages automated patching and
  best-practice assessment. Automated backups are off by default because they require a storage
  account destination this training scenario doesn't provision.
- Trusted Launch (Secure Boot + vTPM) and encryption-at-host are enabled on the VM.
- The bootstrap script (`scripts/sql/Setup-FutonManufacturing.ps1`) enables Transparent Data
  Encryption (TDE) on the restored database, creates a SQL Server Audit
  (`FutonManufacturingServerAuditSpec`) covering failed logins, successful logins, login password
  changes, server principal changes, server permission changes, server role membership changes,
  and audit configuration changes, and writes those events to the Windows Application log. It
  also enables instance-level [login auditing](https://learn.microsoft.com/ssms/configure-login-auditing-sql-server-management-studio),
  provisions a least-privilege application login (`db_datareader`/`db_datawriter` only) instead
  of using `sa`, disables the `sa` login and the legacy SQL Server Browser service, and forces
  encrypted client connections.
- **Database data auditing is enabled as well.** `FutonManufacturingDbAuditSpec` records
  `SELECT`, `INSERT`, `UPDATE`, and `DELETE` activity across the database. The bootstrap is
  idempotent and repairs missing action groups on redeploy. The exact implementation,
  verification queries, and a copyable SQL pattern are available to authenticated operators at
  `/admin/auditing`; the source of truth is `scripts/sql/Setup-FutonManufacturing.ps1`.
- **SQL logs reach a configurable Sentinel workspace** — `sqlScenario.sentinelMode` defaults to
  `new`, which creates the Log Analytics/Sentinel workspace in this scenario's own resource group
  for easy demo ownership and teardown. Set it to `existing` to point at a workspace you already
  own instead. `infra/sql-defender-scenario/main.bicep` references the resolved workspace, and
  `scripts/deploy.sh` creates it idempotently when needed. The `amaExtension` +
  `dataCollectionRule` pair does the actual forwarding: the `AzureMonitorWindowsAgent` extension
  on the VM collects the Windows `Application`, `System`, and `Security` event logs, and the
  associated Data Collection Rule (`${vmName}-dcr`) forwards them over the `Microsoft-Event`
  stream. Both the SQL Server Audit records (Event ID 33205, `MSSQLSERVER` source) and the
  login-auditing entries (Event ID 18453/18456) land in the Windows Application log:

  ```kql
  Event
  | where Source == "MSSQLSERVER"
  | order by TimeGenerated desc
  ```

This scenario provisions a billable Azure VM, managed disk, App Service plan, and Log Analytics
workspace; use an isolated subscription and tear it down (`bash scripts/deploy.sh uninstall`)
when the exercise ends.

## Pawton Manufacturing: the live demo site

**Pawton Manufacturing** ("paw" + "futon" — the fictional futon manufacturer behind the sample
data) is a small Astro/Node.js dashboard at `apps/pawton-manufacturing/` that reads the restored
Futon Manufacturing data live: item/warehouse/customer counts, inventory valuation, sales by
channel, and production order status. It exists to make this demo tangible with a real, running
application instead of only infrastructure evidence:

- It runs on its own Azure App Service for Linux (Node 24), protected by **Microsoft Defender for
  App Service** once that plan is Standard at subscription scope.
- It reaches SQL Server through **regional VNet integration** into the same VNet as the SQL VM;
  the NSG allows the Web App subnet and the configured public TCP 1433 endpoint.
- It authenticates with the same `futon_app` SQL login the bootstrap script creates. The
  training template stores the password in **Azure Key Vault** and supplies it directly as a
  protected App Service setting, not a Key Vault reference — a deliberate lab configuration, not
  a production secret-delivery recommendation.

The deployment script uploads the portal source after infrastructure provisioning and uses
Azure's remote build service. See [portal setup and configuration](#portal-setup-and-configuration)
for local development and prebuilt deployment requirements.

## Admin portal: a deliberate anti-pattern, not a template

`xp_cmdshell` defaults to enabled for shell attack exercises. Set
`sqlScenario.enableSqlShellAttackTests` to `"false"` in [deployment configuration](config/deploy.config.json)
for a shell-disabled bootstrap. **Admin settings > SQL shell access** provides a confirmed on/off
switch and live SQL status. Admin changes persist until bootstrap runs again with the deployment
default. Disabling shell access blocks new calls but does not stop already-running commands or
turn off Defender.

Event, log, and status timestamps display in Eastern time by default; see
[display timezone](#display-timezone) to change it.

The portal separates `/users` (SQL login management), `/admin` (security lab and live
protection observations), `/admin/schema` (read-only database inspection), and
`/admin/auditing` (audit setup and verification).

- **Privilege risk.** The admin portal's SQL login, `dojo_admin_portal_svc`, holds `CONTROL
SERVER` to manage the built-in administrator. Compromise of the app or its credentials can
  compromise the SQL instance. This is an intentional training anti-pattern. **Do not copy it
  into production.**
- **Credential lifecycle.** The deployment generates the built-in SQL administrator password,
  applies it during VM bootstrap, and stores it in Key Vault as `sql-sa-login-password`. The
  portal detects the built-in administrator by SQL Server's fixed SID (`0x01`) rather than
  assuming its name remains `sa`, so it can display the current name, enable/disable it, rotate
  its password, and rename it.
- **Automation never uses the built-in administrator.** Repository scripts and any out-of-band
  SQL Server administration authenticate as `dojo_platform_ops_svc`, a separate `CONTROL SERVER`
  login created during VM bootstrap. Its password exists only in Key Vault as
  `sql-platform-ops-password` and is deliberately **not** published as a Web App setting, so the
  public dashboard cannot authenticate as it, and `/users` refuses to enable, disable, rotate,
  rename, or clear it. Keeping automation off the built-in administrator matters because that
  login stays disabled between demos: a script that reached for it would generate failed
  sign-ins, which Microsoft Defender for Cloud reports as *"Failed logon attempt from a
  potentially harmful application was detected"*. With automation on its own login, those alerts
  stay attributable to the demo itself or to genuine outside probing of the public SQL endpoint.
  Scripts resolve credentials with `scripts/lib/sql-credentials.mjs`; set `KEY_VAULT_NAME` (and
  `SQL_SERVER_HOST`) and it reads the secrets through the Azure CLI. The connection builders also
  reject the built-in administrator outright, whatever the environment says.
- **What's protected regardless.** Sign-in requires a random, per-deployment
  `ADMIN_PORTAL_USERNAME`/`ADMIN_PORTAL_PASSWORD`, generated fresh by `scripts/deploy.sh` on
  every deploy. The session cookie is HMAC-signed, `HttpOnly`, `Secure`, `SameSite=Strict`, and
  expires after 15 minutes. The Web App uses its system-assigned managed identity and the Key
  Vault Secrets Officer role to update the two built-in-administrator secrets. That role is
  assigned on those two secrets individually, not across the vault, so the portal's identity
  cannot read `sql-platform-ops-password` — the credential reserved for scripts and back-end SQL
  administration.
- **Audit coverage.** `SERVER_PRINCIPAL_CHANGE_GROUP` covers login enable/disable/rename;
  `LOGIN_CHANGE_PASSWORD_GROUP` covers password changes; the database specification covers
  `SELECT`/`INSERT`/`UPDATE`/`DELETE`. A "Windows Event confirmation" section on `/admin` runs a
  live KQL query against the resolved workspace using the Web App's own managed identity, granted
  only **Log Analytics Reader**.
- **Credentials.** After a deploy, the admin portal URL and generated credentials are written to
  `output/<environment>/admin-portal-credentials.txt` (gitignored, `chmod 600`) alongside
  `sql-vm-credentials.txt`. Delete it when you finish the exercise.
- **Turning it off.** The feature is inert without
  `ADMIN_PORTAL_USERNAME`/`ADMIN_PORTAL_PASSWORD`/`ADMIN_SESSION_SECRET`/`SQL_ADMIN_LOGIN_PASSWORD`
  set. Remove those Web App settings to disable sign-in entirely.

Review the generated report at `output/<environment>/sql-deployment-<environment>.html` for the
verification matrix, then connect through **Azure Bastion** or the public SQL endpoint to
explore the restored database and Defender findings, or open the dashboard URL printed at the end
of the run. The generated Windows administrator password is written once to
`output/<environment>/sql-vm-credentials.txt` (gitignored, never printed to the console) and
stored in Key Vault as `vm-admin-password`.

## Sentinel SQL detection content

The repo-owned solution in `infra/sentinel-sql-solution/` adds content on top of the existing
Windows Application log -> AMA -> DCR -> `Event` table pipeline. It does not replace ingestion,
create another workspace, install the Marketplace SQL connector, or change SQL credentials/Key
Vault. This is a deployable custom content package, not a published Microsoft
Marketplace/Content Hub solution.

Prerequisites: an existing SQL VM and a resolved workspace, SQL audit events already reaching
`Event`, and **Microsoft Sentinel already enabled on that workspace**. With `sentinelMode: "new"`
(the default), the wizard's Sentinel step creates and onboards the workspace before deploying
content; with `sentinelMode: "existing"`, use `infra/sentinel-sql-solution/onboard.bicep` first,
**only after approving Sentinel charges**:

```bash
az provider register --subscription <subscription-id> --namespace Microsoft.OperationsManagement --wait
az extension add --name log-analytics --yes --allow-preview true
az deployment group what-if --subscription <subscription-id> --resource-group NP-Sentinel-CentralUS --template-file infra/sentinel-sql-solution/onboard.bicep --mode Incremental
az deployment group create --subscription <subscription-id> --resource-group NP-Sentinel-CentralUS --name pawton-sentinel-onboard --template-file infra/sentinel-sql-solution/onboard.bicep --mode Incremental
```

The package deploys:

| Content                             | Behavior                                                                                                                                                                                |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DojoSqlAudit(VmResourceId)` parser | Scopes to the SQL VM resource ID; parses 33205 and legacy login IDs 18453/18454/18456 into actor, target, action ID, operation, outcome, client, application and audit/ingestion times. |
| Login-change analytics              | Detects enable, disable, rename and password changes for all logins, including the built-in administrator.                                                                              |
| Built-in-admin sign-in analytics    | Detects successful built-in-administrator authentication using SQL Server Audit records, including renamed accounts.                                                                    |
| Failed-login analytics              | Five or more failed SQL Server Audit logins per VM/account/client in 15 minutes.                                                                                                        |
| Audit-change analytics              | Detects audit creation, alteration or removal statements, including disabling an audit.                                                                                                 |
| Saved hunting and health queries    | A 24-hour login-change timeline in Hunting Queries and counts/latest ingestion by event/action.                                                                                         |

```bash
bash scripts/deploy-sentinel-sql.sh plan --environment dev
bash scripts/deploy-sentinel-sql.sh doctor --environment dev
bash scripts/deploy-sentinel-sql.sh what-if --environment dev
bash scripts/deploy-sentinel-sql.sh deploy --environment dev
bash scripts/deploy-sentinel-sql.sh verify --environment dev
```

`plan` is offline. `doctor`, `what-if`, and `verify` do not change resources. `deploy` always
runs an incremental what-if first and asks for confirmation. There is no workspace-delete
operation; removing this scenario does not remove these centrally stored rules — disable them
before teardown if you reused an existing workspace.

Local validation: `npm run test:sentinel`, `bash -n scripts/deploy-sentinel-sql.sh`. After
installing the Pawton app dependencies:

```bash
node scripts/test-sentinel-sql.mjs --workspace <workspace-customer-id>
```

References: [SQL Server audit action groups](https://learn.microsoft.com/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions)
and [Sentinel scheduled rule resource schema](https://learn.microsoft.com/azure/templates/microsoft.securityinsights/2025-09-01/alertrules).

## Portal setup and configuration

From the repository root:

```bash
npm ci --prefix apps/pawton-manufacturing
npm run dev --prefix apps/pawton-manufacturing
```

Without SQL connection settings, pages report the database as unconfigured. Supply credentials
through your process environment or an approved secret provider, not source control.

### Portal environment variables

| Variable                                         | Default or requirement            | Purpose                                                          |
| ------------------------------------------------ | --------------------------------- | ---------------------------------------------------------------- |
| `SQL_SERVER_HOST`                                | Required for database access      | SQL VM host/private IP                                           |
| `SQL_DATABASE`                                   | `FutonManufacturing`              | Application database                                             |
| `SQL_APP_LOGIN`                                  | `futon_app`                       | Application SQL identity                                         |
| `SQL_APP_LOGIN_PASSWORD`                         | Required for database access      | Application password                                             |
| `SQL_ADMIN_LOGIN`                                | Required for admin SQL operations | Privileged identity; deployment supplies `dojo_admin_portal_svc` |
| `SQL_ADMIN_LOGIN_PASSWORD`                       | Required for admin SQL operations | Privileged SQL password                                          |
| `KEY_VAULT_NAME`                                 | Required by scripts only          | Vault that scripts read `sql-platform-ops-password` from         |
| `SQL_PLATFORM_OPS_LOGIN`                         | `dojo_platform_ops_svc`           | Script-only privileged identity; never set on the Web App        |
| `ADMIN_PORTAL_USERNAME`, `ADMIN_PORTAL_PASSWORD` | Required for sign-in              | Operator credentials                                             |
| `ADMIN_SESSION_SECRET`                           | Required for sign-in              | HMAC session-signing secret                                      |
| `LOG_ANALYTICS_WORKSPACE_ID`                     | Optional workspace GUID           | Enables forwarded-event confirmation                             |
| `SQL_VM_RESOURCE_ID`                             | Set by deployment                 | Fixed VM scope for evidence and extension reads                  |
| `AZURE_SUBSCRIPTION_ID`                          | Set by deployment                 | Read-only Defender plan queries                                  |
| `ENABLE_SQL_DEMO_ACTIONS`                        | Enabled unless `false`            | Controls audit samples and direct SQL tests                      |
| `PORTAL_TIME_ZONE`                               | `America/New_York`                | Human-readable event and status timezone                         |

### Custom domain and Cloudflare

The portal supports an optional custom subdomain. `sqlScenario.webAppCustomDomain` / the
`PORTAL_CUSTOM_DOMAIN` variable set the hostname; `sqlScenario.manageCustomDomain` /
`MANAGE_CUSTOM_DOMAIN` enable managed DNS + certificate automation; `sqlScenario.cloudflareZoneId`
/ `CLOUDFLARE_ZONE_ID` selects the Cloudflare zone. Supply `CLOUDFLARE_API_TOKEN` as an
environment secret with **Zone Read** and **DNS Edit** scoped only to that zone — never in JSON,
command arguments, or Bicep parameters.

```bash
bash scripts/deploy-pawton-domain.sh plan --environment dev
bash scripts/deploy-pawton-domain.sh check --environment dev
bash scripts/deploy.sh domain --environment dev
```

This path requires **Cloudflare DNS-only (grey cloud), with CNAME flattening off**. See
[custom-domain.bicep](infra/sql-defender-scenario/custom-domain.bicep) for the Azure
hostname/certificate side of the lifecycle.

### Display timezone

Set `sqlScenario.portalTimeZone` in [deployment configuration](config/deploy.config.json), or
change the running app's `PORTAL_TIME_ZONE` setting and restart.

## Direct SQL attack tests

All tests require a signed admin session, same-origin POST, and explicit confirmation. The CLI
uses the same fixed catalog and environment configuration — no arbitrary SQL, commands,
credentials, or targets.

| Test ID             | Activity and limits                                                                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `brute-force`       | Twelve failed logins for a random nonexistent identity; no real-account guessing                                                  |
| `suspicious-app`    | Client name `sqlmap`, session/database discovery and at most five visible table names                                             |
| `sql-injection`     | Fictional order-desk lookup: legitimate lookup (one match), fixed unsafe input (four matches), parameter binding (zero)           |
| `principal-anomaly` | Temporary user without login, sample SELECT grant, impersonation, and rollback; no committed principal                            |
| `external-source`   | One first-party HTTPS inert-text download: fixed baseline; at most 1 KiB, no redirects, SHA-256 verified, cleanup, never executed |
| `obfuscated-shell`  | Fixed SQL string concatenation constructs the shell procedure call; requires `xp_cmdshell` already enabled                        |

```bash
node scripts/run-sql-attack-test.mjs --audit
node scripts/run-sql-attack-test.mjs --run suspicious-app --confirm isolated-lab
```

`--audit` and `--list` make no connection. Exit codes: 0 for audit/executed, 1 for failure, 2 for
blocked/usage errors. Correlate `dojo-attack-test:<scenario>:<run-id>` with the VM, time window,
and actual Defender/Sentinel evidence. This is real detection experimentation, not a guaranteed
alert generator; for repeatable alert-delivery exercises use Microsoft's
[supported SQL/Shell alert simulation](https://learn.microsoft.com/azure/defender-for-cloud/simulate-alerts-sql-machines).

The optional unique-source canary experiment (`infra/sql-canary/`) is disabled by default; see
[infra/sql-canary/README.md](infra/sql-canary/README.md) before enabling it.

## Configuration

All deployment configuration lives in [`config/deploy.config.json`](config/deploy.config.json).
Override any value with `--environment`-scoped CLI flags, a matching environment variable, or a
GitHub Environment variable when running through Actions. Defender for Servers/SQL tiers can be
overridden with `DEFENDER_SERVERS_TIER`, `DEFENDER_SERVERS_SUBPLAN`, and `DEFENDER_SQL_TIER`; set
a tier to `disabled` to skip it.

Secrets live in Azure Key Vault, generated fresh on every full deployment. The admin portal's
direct password app settings are a deliberate lab anti-pattern (see
[above](#admin-portal-a-deliberate-anti-pattern-not-a-template)) — do not copy that pattern into
production.

### Repository layout

| Path                         | Contents                                                                        |
| ---------------------------- | ------------------------------------------------------------------------------- |
| `apps/pawton-manufacturing/` | The live dashboard and bounded SQL lab actions                                  |
| `config/deploy.config.json`  | Scenario and environment configuration                                          |
| `scripts/`                   | Local lifecycle commands, SQL bootstrap, and validation                         |
| `infra/`                     | Bicep templates, generated ARM templates, and Sentinel content                  |
| `azuredeploy.json`           | Deploy-to-Azure button target (copy of `infra/sql-defender-scenario/main.json`) |

## Workflows

- `.github/workflows/deploy.yml` — `workflow_dispatch` with a `stage` choice of
  `plan`/`doctor`/`deploy`/`domain`/`uninstall`, delegating to the shared
  `scenario-lifecycle.yml` reusable workflow, followed by a subscription-scoped Defender posture
  audit using [Pawprint](https://github.com/ninjapaw/pawprint)'s `kit-defender-posture.yml`.
- `.github/workflows/validate-infrastructure.yml` — installs dependencies, runs repository and
  portal tests, builds the portal, and delegates Bicep compilation/drift checks to Pawprint's
  `kit-bicep-validate.yml`.

Run the shared checks locally:

```bash
npm ci
npm ci --prefix apps/pawton-manufacturing
npm test
npm run test:portal
```

## Security

Do not commit secrets, customer data, production credentials, or private infrastructure
details. Report security issues privately according to [SECURITY.md](SECURITY.md). See
[CONTRIBUTING.md](CONTRIBUTING.md) for review requirements.

## License and Ownership Notice

The source is provided under the [MIT License](LICENSE). The MIT license does not grant rights
to Microsoft trademarks, names, logos, or third-party materials. Microsoft trademarks and
product names remain the property of Microsoft Corporation. This repository is an unapproved,
unofficial community demonstration and should not imply Microsoft sponsorship or authorization.
