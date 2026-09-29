// Canonical SQL login names for this scenario, kept dependency-free so repository scripts can
// import it directly without installing the dashboard's npm dependencies.
//
// Three service identities exist, each with a deliberately different blast radius:
//   futon_app             - least-privilege application login (db_datareader/db_datawriter).
//   dojo_admin_portal_svc - CONTROL SERVER login the PUBLIC dashboard holds so it can
//                           enable/disable/rotate/rename the built-in administrator on camera.
//                           Handing a public web app this credential is the anti-pattern the
//                           scenario teaches.
//   dojo_platform_ops_svc - CONTROL SERVER login for repository scripts and out-of-band SQL
//                           Server administration. Its password lives only in Key Vault and is
//                           never published to the web app, so the dashboard cannot use it and
//                           the login cannot be altered from the GUI.
//
// The built-in administrator ('sa') is reserved for the demo itself. Scripts must never
// authenticate as it: it stays disabled between demos, so every automated attempt would be a
// failed sign-in, and those failures are exactly what Defender for Cloud reports as
// "Failed logon attempt from a potentially harmful application was detected". Keeping automation
// off 'sa' keeps that signal attributable to the demo or to genuine outside probing.

export const APP_LOGIN_NAME = "futon_app";
export const ADMIN_PORTAL_LOGIN_NAME = "dojo_admin_portal_svc";
export const PLATFORM_OPS_LOGIN_NAME = "dojo_platform_ops_svc";

// The built-in administrator is authoritatively identified by SID 0x01 (rename-safe). These names
// are the additional string-level guard for configuration values, where no SID is available.
const BUILT_IN_ADMIN_LOGIN_NAMES = new Set(["sa", "system administrator"]);

export function isBuiltInAdminLoginName(name) {
  return (
    typeof name === "string" &&
    BUILT_IN_ADMIN_LOGIN_NAMES.has(name.trim().toLowerCase())
  );
}

/**
 * Names the dashboard GUI must never enable, disable, rotate, rename, or clear. Environment
 * overrides are honoured for the two logins the web app actually knows about; the platform
 * operations login is always reserved because the web app is never told its name or password.
 */
export function reservedServiceLoginNames(environment = process.env) {
  return [
    environment.SQL_APP_LOGIN || APP_LOGIN_NAME,
    environment.SQL_ADMIN_LOGIN || ADMIN_PORTAL_LOGIN_NAME,
    environment.SQL_PLATFORM_OPS_LOGIN || PLATFORM_OPS_LOGIN_NAME,
    PLATFORM_OPS_LOGIN_NAME,
  ];
}

export function isReservedServiceLoginName(name, environment = process.env) {
  if (typeof name !== "string") return false;
  const candidate = name.trim().toLowerCase();
  return reservedServiceLoginNames(environment).some(
    (reserved) => reserved.toLowerCase() === candidate,
  );
}

/**
 * Defence in depth for connection builders: refuse to assemble a connection that authenticates as
 * the built-in administrator, whatever the environment says.
 */
export function assertNotBuiltInAdminLogin(name, context) {
  if (!isBuiltInAdminLoginName(name)) return name;
  throw new Error(
    `${context} must not authenticate as the built-in SQL administrator ('${name}'). ` +
      `Use the ${PLATFORM_OPS_LOGIN_NAME} login (Key Vault secret 'sql-platform-ops-password') instead.`,
  );
}
