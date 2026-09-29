// Resolves the SQL credentials repository scripts use, from Key Vault.
//
// Scripts must never authenticate as the built-in SQL administrator. That login is disabled
// between demos and is reserved for the portal's enable/disable/rotate/rename walkthrough, so any
// script that reached for it would produce exactly the failed sign-in Microsoft Defender for Cloud
// reports as "Failed logon attempt from a potentially harmful application was detected" -- noise
// that masks the real demo signal and genuine outside probing.
//
// Instead, privileged script work uses dojo_platform_ops_svc, whose password exists only in Key
// Vault (secret 'sql-platform-ops-password'). It is never published to the dashboard Web App, so
// the public GUI cannot authenticate as it, and the portal's login controls refuse to touch it.
//
// Key Vault is read through the Azure CLI rather than the Azure SDK because the repository root
// has no npm dependencies, and every script that needs these credentials is already run alongside
// scripts/deploy.sh, which requires the Azure CLI.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  APP_LOGIN_NAME,
  PLATFORM_OPS_LOGIN_NAME,
  assertNotBuiltInAdminLogin,
} from "../../apps/pawton-manufacturing/src/lib/sqlIdentities.mjs";

const execFileAsync = promisify(execFile);

export const APP_PASSWORD_SECRET = "sql-app-login-password";
export const PLATFORM_OPS_PASSWORD_SECRET = "sql-platform-ops-password";

export class CredentialError extends Error {}

/**
 * Reads one secret value from Key Vault. Returns null when the secret does not exist so callers
 * can raise an error that names the missing secret and how to create it.
 */
export async function readKeyVaultSecret(vaultName, secretName) {
  try {
    const { stdout } = await execFileAsync(
      "az",
      [
        "keyvault",
        "secret",
        "show",
        "--vault-name",
        vaultName,
        "--name",
        secretName,
        "--query",
        "value",
        "-o",
        "tsv",
      ],
      { windowsHide: true },
    );
    const value = stdout.replace(/\r?\n$/, "");
    return value === "" ? null : value;
  } catch (error) {
    if (error.code === "ENOENT")
      throw new CredentialError(
        "The Azure CLI ('az') is required to read SQL credentials from Key Vault. Install it, run 'az login', or set the SQL_* environment variables explicitly.",
      );
    return null;
  }
}

function requireVaultName(environment) {
  const vaultName = environment.KEY_VAULT_NAME;
  if (!vaultName)
    throw new CredentialError(
      "Set KEY_VAULT_NAME to the scenario's Key Vault (deploy.sh reports it), or provide the SQL_* environment variables explicitly.",
    );
  return vaultName;
}

/**
 * Builds the SQL environment variables the attack lab and other scripts read.
 *
 * Explicit environment variables win, so an operator can point a run at a disposable instance
 * without Key Vault. Anything still missing is fetched from Key Vault.
 *
 * @param {object} options
 * @param {boolean} options.privileged Also resolve the platform operations login.
 */
export async function resolveSqlEnvironment({
  privileged = false,
  environment = process.env,
} = {}) {
  const host = environment.SQL_SERVER_HOST;
  if (!host)
    throw new CredentialError(
      "Set SQL_SERVER_HOST to the scenario's SQL Server endpoint before running this script.",
    );

  const resolved = {
    SQL_SERVER_HOST: host,
    SQL_DATABASE: environment.SQL_DATABASE || "FutonManufacturing",
    SQL_APP_LOGIN: environment.SQL_APP_LOGIN || APP_LOGIN_NAME,
    SQL_APP_LOGIN_PASSWORD: environment.SQL_APP_LOGIN_PASSWORD,
  };

  if (!resolved.SQL_APP_LOGIN_PASSWORD) {
    const vaultName = requireVaultName(environment);
    resolved.SQL_APP_LOGIN_PASSWORD = await readKeyVaultSecret(
      vaultName,
      APP_PASSWORD_SECRET,
    );
    if (!resolved.SQL_APP_LOGIN_PASSWORD)
      throw new CredentialError(
        `Could not read secret '${APP_PASSWORD_SECRET}' from Key Vault '${vaultName}'. Confirm the deployment completed and that you have get permission on its secrets.`,
      );
  }

  if (privileged) {
    // Privileged scenarios read the platform operations login, not the portal's service login and
    // never the built-in administrator.
    resolved.SQL_ADMIN_LOGIN =
      environment.SQL_PLATFORM_OPS_LOGIN || PLATFORM_OPS_LOGIN_NAME;
    resolved.SQL_ADMIN_LOGIN_PASSWORD =
      environment.SQL_PLATFORM_OPS_LOGIN_PASSWORD;
    if (!resolved.SQL_ADMIN_LOGIN_PASSWORD) {
      const vaultName = requireVaultName(environment);
      resolved.SQL_ADMIN_LOGIN_PASSWORD = await readKeyVaultSecret(
        vaultName,
        PLATFORM_OPS_PASSWORD_SECRET,
      );
      if (!resolved.SQL_ADMIN_LOGIN_PASSWORD)
        throw new CredentialError(
          `Could not read secret '${PLATFORM_OPS_PASSWORD_SECRET}' from Key Vault '${vaultName}'. Redeploy with scripts/deploy.sh so the ${PLATFORM_OPS_LOGIN_NAME} login and its secret are created.`,
        );
    }
    assertNotBuiltInAdminLogin(resolved.SQL_ADMIN_LOGIN, "This script");
  }

  assertNotBuiltInAdminLogin(resolved.SQL_APP_LOGIN, "This script");
  return resolved;
}

/**
 * Applies resolved credentials to process.env so modules that read the live environment lazily
 * (such as the SQL attack lab's connection builder) pick them up.
 */
export async function applySqlEnvironment(options = {}) {
  const resolved = await resolveSqlEnvironment(options);
  Object.assign(process.env, resolved);
  return resolved;
}
