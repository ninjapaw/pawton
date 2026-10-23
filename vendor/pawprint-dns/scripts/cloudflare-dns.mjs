import { readFileSync } from "node:fs";
import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const API = "https://api.cloudflare.com/client/v4";
const ID = /^[a-f0-9]{32}$/i;
const SERVICES = {
  "app-service": { suffix: ".azurewebsites.net", prefix: "asuid", maxLength: 64 },
  "static-web-app": { suffix: ".azurestaticapps.net", prefix: "_dnsauth", maxLength: 253 },
  "front-door": { suffix: ".azurefd.net", prefix: "_dnsauth", maxLength: 253 },
};

export function validateDomain(value, maxLength = 253) {
  if (typeof value !== "string") throw new Error("Custom domain must be a DNS hostname.");
  const domain = value.trim().toLowerCase();
  if (domain.length > maxLength
      || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) {
    throw new Error(`Custom domain must be a hostname of at most ${maxLength} characters, without scheme, port, path, or wildcard.`);
  }
  return domain;
}

export function azureDnsRecords({ service, domain, azureHostname, verificationId }) {
  const definition = Object.hasOwn(SERVICES, service) ? SERVICES[service] : undefined;
  if (!definition) throw new Error("DNS service must be app-service, static-web-app, or front-door.");
  domain = validateDomain(domain, definition.maxLength);
  const target = validateDomain(azureHostname);
  if (!target.endsWith(definition.suffix)) {
    throw new Error(`Expected the Azure service's default ${definition.suffix.slice(1)} hostname.`);
  }
  if (typeof verificationId !== "string" || !verificationId.length || verificationId.length > 2048
      || /[\x00-\x1f\x7f]/.test(verificationId)
      || (service === "app-service" && !/^[a-f0-9]{64}$/i.test(verificationId))) {
    throw new Error("Azure custom-domain verification ID or validation token is unavailable.");
  }
  return [
    { type: "TXT", name: `${definition.prefix}.${domain}`, content: verificationId, ttl: 300 },
    { type: "CNAME", name: domain, content: target, ttl: 300, proxied: false, settings: { flatten_cname: false } },
  ];
}

function ownership(owner) {
  const normalized = typeof owner === "string" ? owner.toLowerCase() : "";
  if (!/^[a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9._-]*:(?:dev|prod|shared)(?::[a-z0-9][a-z0-9-]{0,63})?$/.test(normalized)) {
    throw new Error("DNS owner must be an explicit owner/repository:dev, :prod, or :shared identity, optionally followed by :instance.");
  }
  return `pawprint:dns:${normalized}`;
}

function canonicalIpv6(value) {
  return new URL(`http://[${value}]/`).hostname.slice(1, -1);
}

function singlePage(response) {
  const pages = response.result_info?.total_pages;
  return pages === undefined || (Number.isInteger(pages) && pages >= 0 && pages <= 1);
}

function normalizeRecords(records) {
  if (!Array.isArray(records) || records.length > 100) throw new Error("Supply at most 100 explicit DNS records.");
  const names = new Set();
  return records.map((record) => {
    if (!record || typeof record !== "object" || Array.isArray(record)
        || Object.keys(record).some((key) => !["type", "name", "content", "ttl", "proxied", "settings"].includes(key))) {
      throw new Error("DNS records accept only type, name, content, ttl, proxied, and settings.");
    }
    const { type, content } = record;
    const name = typeof record.name === "string" ? record.name.toLowerCase() : "";
    if (name.length > 253 || !/^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/.test(name)
        || names.has(name)) {
      throw new Error("DNS record names must be valid, unique, fully qualified names.");
    }
    names.add(name);
    if (typeof content !== "string" || !content.length || content.length > 2048 || /[\r\n\0]/.test(content)) {
      throw new Error("DNS record content must be nonempty text without control-line separators.");
    }
    if (!["A", "AAAA", "CNAME", "TXT"].includes(type)
        || (type === "A" && isIP(content) !== 4) || (type === "AAAA" && isIP(content) !== 6)) {
      throw new Error("Supported DNS records are valid A, AAAA, CNAME, and TXT records.");
    }
    const ttl = record.ttl ?? 300;
    if (!Number.isInteger(ttl) || (ttl !== 1 && (ttl < 60 || ttl > 86400))) {
      throw new Error("DNS TTL must be 1 (automatic) or an integer from 60 to 86400.");
    }
    if (record.proxied !== undefined && record.proxied !== false) throw new Error("Managed DNS records must remain DNS-only.");
    if (record.settings !== undefined
        && (type !== "CNAME" || !record.settings || typeof record.settings !== "object"
          || Array.isArray(record.settings) || Object.keys(record.settings).length !== 1
          || record.settings.flatten_cname !== false)) {
      throw new Error("Only settings.flatten_cname=false is supported, for CNAME records.");
    }
    if (type === "TXT") {
      if (record.proxied !== undefined) throw new Error("TXT records do not support proxy settings.");
      return { type, name, content, ttl };
    }
    const normalized = type === "CNAME" ? validateDomain(content.replace(/\.$/, ""))
      : type === "AAAA" ? canonicalIpv6(content) : content;
    if (type === "CNAME" && normalized === name) throw new Error("A CNAME must not point to itself.");
    return {
      type, name, content: normalized, ttl, proxied: false,
      ...(type === "CNAME" ? { settings: { flatten_cname: false } } : {}),
    };
  });
}

export function validateRecordManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)
      || Object.keys(manifest).some((key) => !["zoneName", "zoneId", "owner", "records"].includes(key))) {
    throw new Error("DNS manifests accept only zoneName, zoneId, owner, and records; credentials belong in the environment.");
  }
  ownership(manifest.owner);
  const zoneName = validateDomain(manifest.zoneName);
  if (manifest.zoneId !== undefined && !ID.test(manifest.zoneId)) throw new Error("Invalid Cloudflare zone ID.");
  const records = normalizeRecords(manifest.records);
  for (const record of records) {
    if (record.name !== zoneName && !record.name.endsWith(`.${zoneName}`)) {
      throw new Error("Every DNS record must belong to the manifest's exact zone.");
    }
  }
  return { ...manifest, zoneName, records };
}

export function createCloudflareClient({ zoneId, zoneName, token }, { fetcher = fetch } = {}) {
  if (zoneId !== undefined && !ID.test(zoneId)) throw new Error("Set CLOUDFLARE_ZONE_ID to a 32-character hexadecimal zone ID.");
  if (zoneName !== undefined) zoneName = validateDomain(zoneName);
  if (!zoneId && !zoneName) throw new Error("Set CLOUDFLARE_ZONE_ID or CLOUDFLARE_ZONE_NAME.");
  if (typeof token !== "string" || !token.length || token.length > 2048 || /\s/.test(token)) {
    throw new Error("Set CLOUDFLARE_API_TOKEN with Zone Read and DNS Edit permissions for this zone only.");
  }
  async function request(method, path, body) {
    let response;
    try {
      response = await fetcher(`${API}${path}`, {
        method,
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        redirect: "error",
        signal: AbortSignal.timeout(30_000),
      });
    } catch {
      throw new Error("Cloudflare request failed or timed out. Review connectivity and rerun plan; partial changes are not reported as success.");
    }
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new Error("Cloudflare returned an invalid JSON response; its contents were omitted.");
    }
    if (!response.ok || payload?.success !== true) {
      throw new Error(`Cloudflare request rejected (HTTP ${response.status}). Check the scoped token, expiry, and zone permissions.`);
    }
    return payload;
  }
  async function loadZone() {
    let zone;
    if (zoneId) zone = (await request("GET", `/zones/${zoneId}`)).result;
    else {
      const response = await request("GET", `/zones?${new URLSearchParams({ name: zoneName, status: "active", per_page: "50" })}`);
      if (!Array.isArray(response.result) || response.result.length !== 1 || !singlePage(response)) {
        throw new Error("Cloudflare did not return exactly one active zone with the configured name.");
      }
      [zone] = response.result;
    }
    if (!ID.test(zone?.id ?? "") || zone.status !== "active"
        || validateDomain(zone.name) !== zone.name || (zoneId && zone.id !== zoneId)
        || (zoneName && zone.name !== zoneName)) {
      throw new Error("The selected active Cloudflare zone must exactly match the configured zone ID and name.");
    }
    return zone;
  }
  return { request, loadZone };
}

export function assertDomainInZone(domain, zone, { allowApex = false } = {}) {
  domain = validateDomain(domain);
  if (!(domain.endsWith(`.${zone.name}`) || (allowApex && domain === zone.name))) {
    throw new Error("The hostname must be a subdomain of the selected active Cloudflare zone; this service does not support apex domains.");
  }
}

function sameRecord(actual, expected) {
  if (actual.type !== expected.type || typeof actual.content !== "string") return false;
  if (expected.type === "TXT") {
    if (actual.content === expected.content) return true;
    const content = actual.content.startsWith('"') && actual.content.endsWith('"')
      ? actual.content.slice(1, -1) : actual.content;
    return content === expected.content;
  }
  const content = expected.type === "CNAME" ? actual.content.toLowerCase().replace(/\.$/, "")
    : expected.type === "AAAA" && isIP(actual.content) === 6 ? canonicalIpv6(actual.content) : actual.content;
  return content === expected.content && actual.proxied === false
    && (expected.type !== "CNAME" || actual.settings?.flatten_cname !== true);
}

function snapshot(entry) {
  return JSON.stringify(entry && [entry.id, entry.type, entry.name, entry.content, entry.ttl,
    entry.proxied, entry.settings?.flatten_cname, entry.comment]);
}

export async function reconcileRecords(settings, { apply = false, fetcher = fetch } = {}) {
  const records = normalizeRecords(settings.records);
  const comment = ownership(settings.owner);
  if (!records.length) return [];
  const client = createCloudflareClient(settings, { fetcher });
  const zone = await client.loadZone();
  if (settings.domain) assertDomainInZone(settings.domain, zone, { allowApex: settings.service === "static-web-app" });
  for (const record of records) {
    if (record.name !== zone.name && !record.name.endsWith(`.${zone.name}`)) {
      throw new Error("DNS record is outside the selected Cloudflare zone.");
    }
  }
  async function inspect(record) {
    const response = await client.request("GET", `/zones/${zone.id}/dns_records?${new URLSearchParams({ name: record.name, per_page: "100" })}`);
    if (!Array.isArray(response.result) || response.result.length > 1
        || !singlePage(response)
        || response.result.some((entry) => entry.name?.toLowerCase() !== record.name)) {
      throw new Error(`Ambiguous DNS results for ${record.name}; existing records are never replaced by guessing.`);
    }
    const [entry] = response.result;
    if (!entry) return { action: "create", entry };
    if (sameRecord(entry, record) && (entry.comment !== comment || entry.ttl === record.ttl)) {
      return { action: "found", entry };
    }
    if (entry.type !== record.type || entry.comment !== comment || !ID.test(entry.id ?? "")) {
      throw new Error(`Conflicting DNS record at ${record.name}; records owned elsewhere are never overwritten. Review DNS-only routing, flattening, and record ownership.`);
    }
    return { action: "update", entry };
  }
  const plan = [];
  for (const record of records) plan.push(await inspect(record));
  const actions = [];
  for (const [index, record] of records.entries()) {
    let { action, entry } = plan[index];
    if (apply && action !== "found") {
      const current = await inspect(record);
      if (current.action === "found") action = "found";
      else {
        if (snapshot(current.entry) !== snapshot(entry)) throw new Error(`DNS changed during reconciliation at ${record.name}; rerun plan before retrying.`);
        const path = `/zones/${zone.id}/dns_records${entry ? `/${entry.id}` : ""}`;
        const written = (await client.request(entry ? "PATCH" : "POST", path, { ...record, comment })).result;
        const observed = await inspect(record);
        if (!ID.test(written?.id ?? "") || observed.action !== "found"
            || observed.entry?.id !== written.id || observed.entry?.comment !== comment) {
          throw new Error(`DNS record ${record.name} could not be read back with the intended ownership. Rerun plan; no success is asserted.`);
        }
      }
    }
    actions.push({
      type: record.type, name: record.name,
      action: action === "found" ? "found" : apply ? `${action}d` : `would ${action}`,
    });
  }
  return actions;
}

export async function reconcileAzureDns(settings, options) {
  return reconcileRecords({ ...settings, records: azureDnsRecords(settings) }, options);
}

export async function verifyAzureDns(settings, resolver = new Resolver({ timeout: 5000, tries: 2 })) {
  const [txt, cname] = azureDnsRecords(settings);
  let text;
  let aliases;
  const apex = settings.service === "static-web-app" && settings.zoneName === cname.name;
  try {
    text = await resolver.resolveTxt(txt.name);
    aliases = apex ? [] : await resolver.resolveCname(cname.name);
  } catch {
    throw new Error("Public DNS is not ready. Keep DNS-only routing with CNAME flattening off for subdomains, allow propagation, then retry. No TLS readiness is asserted.");
  }
  if (!text.some((chunks) => chunks.join("") === txt.content)
      || (!apex && !aliases.some((alias) => alias.toLowerCase().replace(/\.$/, "") === cname.content))) {
    throw new Error("Public DNS is not ready: the validation TXT or direct Azure CNAME does not match.");
  }
}

export async function main(args = process.argv.slice(2), environment = process.env) {
  const { values, positionals } = parseArgs({
    args, allowPositionals: true,
    options: { records: { type: "string" }, yes: { type: "boolean", default: false } },
  });
  const [mode] = positionals;
  if (positionals.length !== 1 || !["validate", "zone", "plan", "apply", "verify"].includes(mode)) {
    throw new Error("Expected validate, zone, plan, apply --yes, or verify; --records selects a non-secret shared-record manifest.");
  }
  if (mode === "apply" && !values.yes) throw new Error("DNS apply requires --yes after reviewing plan.");
  let settings;
  if (values.records) {
    let manifest;
    try {
      manifest = JSON.parse(readFileSync(resolve(values.records), "utf8"));
    } catch {
      throw new Error("Cannot read a valid DNS manifest; file contents were omitted to protect accidental secrets.");
    }
    settings = { ...validateRecordManifest(manifest), token: environment.CLOUDFLARE_API_TOKEN };
    if (["zone", "verify"].includes(mode)) throw new Error("Shared-record manifests support validate, plan, and apply only.");
  } else {
    settings = {
      service: environment.PAWPRINT_DNS_SERVICE,
      owner: environment.PAWPRINT_DNS_OWNER,
      domain: environment.AZURE_CUSTOM_DOMAIN,
      azureHostname: environment.AZURE_DEFAULT_HOSTNAME,
      verificationId: environment.AZURE_DOMAIN_VALIDATION_TOKEN,
      zoneId: environment.CLOUDFLARE_ZONE_ID || undefined,
      zoneName: environment.CLOUDFLARE_ZONE_NAME || undefined,
      token: environment.CLOUDFLARE_API_TOKEN,
    };
    if (mode === "zone") {
      if (!Object.hasOwn(SERVICES, settings.service)) throw new Error("Set PAWPRINT_DNS_SERVICE to a supported Azure service.");
      ownership(settings.owner);
      const zone = await createCloudflareClient(settings).loadZone();
      assertDomainInZone(settings.domain, zone, { allowApex: settings.service === "static-web-app" });
      console.log(`[found] Active Cloudflare zone ${zone.name}; credentials were not persisted.`);
      return;
    }
    settings.records = azureDnsRecords(settings);
    ownership(settings.owner);
  }
  if (mode === "validate") {
    console.log(`[valid] ${settings.records.length} DNS records; no network calls or writes.`);
    return;
  }
  if (!settings.records.length) {
    console.log("[none] No DNS records declared; no network calls or writes.");
    return;
  }
  if (mode === "verify") {
    await verifyAzureDns(settings);
    console.log("[found] Public validation DNS verified; Azure HTTPS readiness must be checked separately.");
    return;
  }
  for (const action of await reconcileRecords(settings, { apply: mode === "apply" })) {
    console.log(`[${action.action}] ${action.type} ${action.name}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(`ERROR: ${error.message}`);
    process.exitCode = 1;
  });
}
