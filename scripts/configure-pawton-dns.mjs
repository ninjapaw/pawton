import { pathToFileURL } from "node:url";
import {
  azureDnsRecords, reconcileAzureDns, validateDomain as validateSharedDomain, verifyAzureDns,
} from "../vendor/pawprint-dns/scripts/cloudflare-dns.mjs";

export function validateDomain(value) {
  return validateSharedDomain(value, 64);
}

export function desiredRecords(settings) {
  return azureDnsRecords({ ...settings, service: "app-service" });
}

export async function reconcileDns(settings, options) {
  return reconcileAzureDns({ ...settings, service: "app-service" }, options);
}

export async function verifyDns(settings, resolver) {
  return verifyAzureDns({ ...settings, service: "app-service" }, resolver);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const mode = process.argv[2] ?? "plan";
    const settings = {
      domain: process.env.PAWTON_DOMAIN,
      azureHostname: process.env.PAWTON_AZURE_HOSTNAME,
      verificationId: process.env.PAWTON_VERIFICATION_ID,
      zoneId: process.env.CLOUDFLARE_ZONE_ID,
      zoneName: process.env.CLOUDFLARE_ZONE_NAME || undefined,
      token: process.env.CLOUDFLARE_API_TOKEN,
      owner: `ninjapaw/pawton:${process.env.PAWTON_ENVIRONMENT}`,
    };
    if (mode === "validate") validateDomain(settings.domain);
    else if (mode === "verify") {
      await verifyDns(settings);
      console.log("[found] Public CNAME and asuid TXT records verified.");
    } else if (["plan", "apply"].includes(mode)) {
      for (const action of await reconcileDns(settings, { apply: mode === "apply" })) {
        console.log(`[${action.action}] ${action.type} ${action.name}`);
      }
    } else throw new Error("Expected validate, plan, apply, or verify.");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
