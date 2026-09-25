import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import {
  externalSourceContent,
  uniqueSourceDomain,
} from "../apps/pawton-manufacturing/src/lib/externalSourceProbe.mjs";

export function serveCanary(request, response) {
  const host = String(request.headers.host || "").toLowerCase();
  const label = host.slice(0, -(uniqueSourceDomain.length + 1));
  const accepted =
    host.endsWith(`.${uniqueSourceDomain}`) &&
    /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(
      label,
    );
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Content-Type", "text/plain; charset=utf-8");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Strict-Transport-Security", "max-age=31536000");
  if (!accepted || request.url !== "/lab/external-source-canary.txt") {
    response.writeHead(404);
    response.end();
    return;
  }
  if (!["GET", "HEAD"].includes(request.method)) {
    response.writeHead(405, { Allow: "GET, HEAD" });
    response.end();
    return;
  }
  response.writeHead(200, {
    "Content-Length": Buffer.byteLength(externalSourceContent),
  });
  response.end(request.method === "HEAD" ? undefined : externalSourceContent);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const port = Number(process.env.PORT || 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error("Invalid PORT.");
  const server = createServer(
    { requestTimeout: 10000, headersTimeout: 10000, maxHeaderSize: 8192 },
    serveCanary,
  );
  server.listen(port, process.env.HOST || "127.0.0.1", () =>
    console.log(
      `Canary-only service listening on port ${port}; HTTPS must terminate at the approved ingress.`,
    ),
  );
}
