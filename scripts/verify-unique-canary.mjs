import { randomUUID, createHash } from "node:crypto";
import { get } from "node:https";
import {
  externalSourceContent,
  externalSourceTarget,
} from "../apps/pawton-manufacturing/src/lib/externalSourceProbe.mjs";

if (
  process.argv.length !== 3 ||
  !["--audit", "--check"].includes(process.argv[2])
) {
  console.error(
    "Usage: node scripts/verify-unique-canary.mjs --audit | --check",
  );
  process.exitCode = 2;
} else {
  const targets = Array.from({ length: 2 }, () =>
    externalSourceTarget(
      `dojo-attack-test:external-source:${randomUUID()}`,
      "unique",
    ),
  );
  if (process.argv[2] === "--audit") {
    console.log(
      JSON.stringify(
        {
          mode: "audit",
          networkRequests: 0,
          targets,
          expectedSha256: createHash("sha256")
            .update(externalSourceContent)
            .digest("hex"),
          note: "Check performs two developer-host HTTPS reads, not SQL activity. No setting is enabled automatically.",
        },
        null,
        2,
      ),
    );
  } else {
    try {
      for (const target of targets) {
        await new Promise((resolve, reject) => {
          const request = get(
            target,
            {
              signal: AbortSignal.timeout(10000),
              maxHeaderSize: 16384,
              agent: false,
            },
            (response) => {
              let length = 0;
              const hash = createHash("sha256");
              response.on("error", reject);
              if (
                response.statusCode !== 200 ||
                Number(response.headers["content-length"]) > 1024
              ) {
                response.destroy(
                  new Error(
                    "Expected direct HTTP 200 and at most 1 KiB; redirects are not followed.",
                  ),
                );
                return;
              }
              response.on("data", (chunk) => {
                length += chunk.length;
                if (length > 1024)
                  response.destroy(new Error("Canary exceeds 1 KiB."));
                else hash.update(chunk);
              });
              response.on("end", () => {
                if (
                  hash.digest("hex") !==
                  createHash("sha256")
                    .update(externalSourceContent)
                    .digest("hex")
                )
                  reject(new Error("Canary SHA-256 mismatch."));
                else resolve();
              });
            },
          );
          request.on("error", reject);
        });
        console.log(
          JSON.stringify({
            target,
            verifiedAt: new Date().toISOString(),
            tls: "trusted certificate and hostname verified",
            canary: "SHA-256 matched",
            redirects: 0,
          }),
        );
      }
      console.log(
        "Preflight passed from this host only. Verify SQL VM egress separately. No Defender alert or experiment enablement is implied.",
      );
    } catch (error) {
      console.error(
        `Unique-source preflight failed: ${error.message}. Leave ENABLE_UNIQUE_SQL_CANARY disabled.`,
      );
      process.exitCode = 1;
    }
  }
}
