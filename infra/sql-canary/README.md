# Dedicated SQL Canary Hosting

This deploys only the inert canary service for UUID hosts under `*.canary.ninjapaws.org`. It does not deploy the privileged Pawton portal, grant Azure roles, create SQL connections, issue certificates, modify Cloudflare, enable the experiment, or run an attack.

## What Is Automated

| Artifact                                                           | Responsibility                                                                                                                                                       |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [main.bicep](main.bicep)                                           | Separate Linux Node 24 App Service on an existing plan; HTTPS/TLS 1.2; FTP, basic publishing credentials and remote debugging disabled; actual DNS values as outputs |
| [tls.bicep](tls.bicep)                                             | Wildcard SNI binding to an existing uploaded certificate; usable again after renewal                                                                                 |
| [package-sql-canary.ps1](../../scripts/package-sql-canary.ps1)     | Two-file deployment zip; no dependencies, portal routes, environment files or secrets; refuses to overwrite archives                                                 |
| [verify-unique-canary.mjs](../../scripts/verify-unique-canary.mjs) | Two fresh UUID-host HTTPS reads, validating trust, hostname, direct HTTP 200, size and exact SHA-256                                                                 |

ARM JSON siblings are generated from Bicep and checked by the repository's existing infrastructure workflow. Change the Bicep sources, then regenerate their JSON siblings.

## Hosting And Cost Boundary

The checked lab plan is `ninjapaws-pawton-dev-plan`, Linux Basic B1, in `NP-ninjapaws-dojo-sql-Dev-CentralUS`, Central US. Reusing it does not create a second plan or request a SKU change, but **shares CPU and memory with Pawton**. Existing hosting and bandwidth charges remain. Use a separate approved paid plan if independent compute capacity is required. No plan is created by these templates.

Use only a new dedicated app name, proposed `ninjapaws-canary-dev`. Do not point these templates or the clean zip deployment at the Pawton app. The app template manages its listed settings and would replace that configuration on a wrongly selected target. Use incremental deployment mode and inspect what-if every time. Stop if changes include the portal, SQL VM, networking, existing plan, or any deletion.

## 1. Provision The App

Run from the repository root in PowerShell with Azure CLI authenticated to the intended lab subscription. Azure deployment permissions for the resource group are required. The commands below are **not executed by opening this document**.

```powershell
$subscription = Read-Host 'Lab Azure subscription ID'
$group = 'NP-ninjapaws-dojo-sql-Dev-CentralUS'
$plan = 'ninjapaws-pawton-dev-plan'
$app = 'ninjapaws-canary-dev'
$location = 'centralus'

az account show --subscription $subscription --query '{name:name,id:id}' -o json
az appservice plan show --subscription $subscription --resource-group $group --name $plan -o json
az webapp list --subscription $subscription --resource-group $group --query "[?name=='$app'].{name:name,tags:tags}" -o json

az deployment group what-if --subscription $subscription --resource-group $group --template-file infra/sql-canary/main.bicep --parameters canaryAppName=$app appServicePlanName=$plan location=$location --mode Incremental
```

For a first deployment the app must not already exist. For a rerun, verify that the existing app is the dedicated canary app (`purpose=dojo-inert-canary`), has no unrelated settings, identities, routes or data, and uses the intended Linux plan. The existing plan must be Basic or higher and in the same resource group and region. Review capacity before approval.

After approving the what-if result:

```powershell
az deployment group create --subscription $subscription --resource-group $group --name sql-canary-app --template-file infra/sql-canary/main.bicep --parameters canaryAppName=$app appServicePlanName=$plan location=$location --mode Incremental
if ($LASTEXITCODE -ne 0) { throw 'Canary provisioning failed' }
az deployment group show --subscription $subscription --resource-group $group --name sql-canary-app --query properties.outputs -o json
```

Keep the returned default hostname and domain verification ID. **Do not infer the hostname from the proposed app name**; use the actual `canaryDefaultHostname` output.

## 2. Deploy Only The Canary Code

```powershell
./scripts/package-sql-canary.ps1 -Audit
$archive = Join-Path $env:TEMP ('sql-canary-' + [guid]::NewGuid().ToString('N') + '.zip')
./scripts/package-sql-canary.ps1 -OutputPath $archive
az webapp deploy --subscription $subscription --resource-group $group --name $app --type zip --src-path $archive --clean true --restart true
if ($LASTEXITCODE -ne 0) { throw 'Canary code deployment failed' }
```

Use a current Azure CLI with Entra-authenticated zip deployment. Do not enable basic publishing authentication to work around an old CLI. The startup command is `node scripts/serve-external-source-canary.mjs`; remote builds are disabled. No npm install or package manifest is required for this `.mjs` service. It imports only Node built-ins and its packaged helper.

The default hostname and `/` deliberately return **404**. Only a UUID-v4 hostname under the dedicated namespace and `/lab/external-source-canary.txt` return the canary. App Service warmup accepts HTTP responses by default; do not configure a 200-only health check against `/` or add portal routes to make it pass. Verify success with the final custom-host HTTPS preflight, not by expecting a default-host home page.

## 3. Configure Cloudflare Manually

In the **ninjapaws.org** zone, add these records using the exact `cloudflareRecords` output from step 1:

| Type  | Name           | Content                                  | Proxy                    |
| ----- | -------------- | ---------------------------------------- | ------------------------ |
| CNAME | `*.canary`     | Actual canary app default hostname       | **DNS only**, grey cloud |
| TXT   | `asuid.canary` | Actual canary app domain verification ID | Not applicable           |

Use Auto TTL. Do not overwrite a conflicting existing record. No `canary` A/CNAME is required: the service intentionally accepts UUID children, not the parent hostname. Do not point the wildcard at the Pawton portal or the SQL VM. A wildcard DNS record does not provide a certificate.

Keep this DNS-only design unless you deliberately arrange Cloudflare edge coverage for `*.canary.ninjapaws.org` and origin TLS. Standard Universal SSL for the parent zone does not cover these second-level names. No zone-wide security exclusions are needed for DNS-only traffic.

## 4. Obtain A Free Wildcard Certificate

Use Let's Encrypt DNS-01 validation with Posh-ACME on a trusted Windows machine. This is an **operator step**, not a Bicep deployment. Review the module and CA terms before installation/issuance. Certificate issuance is free; hosting is not. Do not put private keys, PFX files, passwords, Cloudflare tokens, or ACME account data anywhere inside this repository.

In Cloudflare, create a dedicated API token with **Zone / DNS / Edit**, scoped to **only `ninjapaws.org`** (Zone / Zone / Read may be granted for zone discovery). Do not use a global API key. Token permissions cover the selected zone, not just the challenge record; protect the renewal machine accordingly. Posh-ACME creates/removes `_acme-challenge.canary` TXT values automatically. If an existing CNAME occupies that challenge name, stop and review DNS challenge delegation rather than overwriting it.

Run these commands directly in your own terminal, not through chat. Enter secrets only at the secure prompts. No transcript or verbose secret output:

```powershell
Install-Module Posh-ACME -Scope CurrentUser
$env:POSHACME_HOME = Join-Path $env:LOCALAPPDATA 'PoshAcme-DojoCanary'
Import-Module Posh-ACME
$pluginArgs = @{ CFToken = (Read-Host 'Cloudflare DNS token' -AsSecureString) }
$pfxPassword = Read-Host 'Strong PFX password (retain securely)' -AsSecureString
$contact = Read-Host 'ACME contact email'

Set-PAServer LE_STAGE
$staging = New-PACertificate '*.canary.ninjapaws.org' -Plugin Cloudflare -PluginArgs $pluginArgs -PfxPassSecure $pfxPassword -Contact $contact -AcceptTOS
```

Staging validates DNS automation without consuming production issuance limits. **Never upload the untrusted staging certificate.** If DNS validation fails, fix that before proceeding. If restrictive CAA records exist, verify that they authorize Let's Encrypt wildcard issuance; do not remove unrelated CAA restrictions blindly.

After the staging order succeeds:

```powershell
Set-PAServer LE_PROD
$cert = New-PACertificate '*.canary.ninjapaws.org' -Plugin Cloudflare -PluginArgs $pluginArgs -PfxPassSecure $pfxPassword -Contact $contact -AcceptTOS
$cert | Select-Object Subject, NotAfter, Thumbprint, PfxFullChain
```

Only the production certificate is publicly trusted. Protect the Posh-ACME directory with user-only access and secure backups: it holds private keys and saved DNS credentials. The code does not create an ACME account, accept terms, or request certificates on your behalf.

## 5. Upload And Bind HTTPS

In Azure Portal, open the **dedicated canary App Service**, then **Certificates / Bring your own certificates (.pfx)** and upload the production `fullchain.pfx` using the password entered above. Use the file path reported by `PfxFullChain`. Never upload it into source control or pass its contents/password through Bicep or shell command arguments.

Find the resulting certificate resource name without reading its private key:

```powershell
az webapp config ssl list --subscription $subscription --resource-group $group --query '[].{name:name,thumbprint:thumbprint,hosts:hostNames,expires:expirationDate}' -o json
$certificateName = Read-Host 'Uploaded certificate RESOURCE name (not its thumbprint)'
az deployment group what-if --subscription $subscription --resource-group $group --template-file infra/sql-canary/tls.bicep --parameters canaryAppName=$app certificateName=$certificateName --mode Incremental
```

Confirm that the certificate has a private key, includes `*.canary.ninjapaws.org`, has a trusted complete chain, is unexpired, and is in the same App Service webspace (plan region/resource group/OS) as the canary. Confirm that what-if touches only its wildcard hostname binding. The template reads the existing certificate thumbprint and does not contain or output key material.

```powershell
az deployment group create --subscription $subscription --resource-group $group --name sql-canary-tls --template-file infra/sql-canary/tls.bicep --parameters canaryAppName=$app certificateName=$certificateName --mode Incremental
if ($LASTEXITCODE -ne 0) { throw 'Wildcard TLS binding failed' }
node scripts/verify-unique-canary.mjs --check
if ($LASTEXITCODE -ne 0) { throw 'Do not enable unique-source experiments: HTTPS verification failed' }
```

Do not enable `ENABLE_UNIQUE_SQL_CANARY` until this succeeds. Also verify the approved SQL VM egress path before an explicitly authorized experiment. IaC and DNS setup never automatically run a shell command or attack test. The existing fixed-source baseline remains usable.

## Renewal Is Required

**Certificate issuance alone is not a maintained HTTPS deployment.** App Service will not renew an uploaded Let's Encrypt PFX for you. Assign an owner and monitor the actual bound certificate expiry. Check renewal daily without `-Force`, under the same Windows user/profile and `POSHACME_HOME` that issued it:

```powershell
$env:POSHACME_HOME = Join-Path $env:LOCALAPPDATA 'PoshAcme-DojoCanary'
Import-Module Posh-ACME
Set-PAServer LE_PROD
Set-PAOrder '*.canary.ninjapaws.org'
$renewed = Submit-Renewal
$current = Get-PACertificate
$current | Select-Object NotAfter, Thumbprint, PfxFullChain
```

Posh-ACME uses the saved Cloudflare plugin settings for DNS-01 renewal. Update those securely if the token rotates or expires. A Task Scheduler job can perform this check, but unattended end-to-end rotation is **not installed by this change**.

After renewal, upload the new production PFX in the dedicated app's Certificates page, select its resource name, rerun TLS what-if/deploy, and rerun HTTPS preflight. Retry upload/binding if a previous attempt failed even when `Submit-Renewal` returns no new certificate: the renewed local certificate and the deployed certificate are separate state. Do not delete the previous certificate until the new binding and endpoint are verified, and never delete a shared certificate. For fully unattended operation, separately approve an Azure-authenticated upload/rebinding job with a protected PFX store and failure monitoring; DNS renewal by itself is insufficient.

## Stop Or Remove

Disable unique-source mode on the portal first. To retire hosting, remove the dedicated wildcard CNAME from Cloudflare before deleting the canary app, to avoid dangling DNS. Retain the ownership TXT until the hostname is fully retired. Remove only its unused certificate after checking other bindings. Never delete the shared App Service plan, the portal domain, SQL resources or the resource group as a canary cleanup step.

## References

- [App Service wildcard DNS and ownership validation](https://learn.microsoft.com/azure/app-service/app-service-web-tutorial-custom-domain)
- [App Service certificate requirements](https://learn.microsoft.com/azure/app-service/configure-ssl-certificate)
- [Posh-ACME Cloudflare DNS plugin](https://poshac.me/docs/v4/Plugins/Cloudflare/)
- [Posh-ACME issuance and renewal tutorial](https://poshac.me/docs/v4/Tutorial/)
- [Cloudflare wildcard DNS](https://developers.cloudflare.com/dns/manage-dns-records/reference/wildcard-dns-records/)
