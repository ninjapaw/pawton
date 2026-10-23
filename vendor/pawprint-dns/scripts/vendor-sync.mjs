/**
 * Copies shared files into a consuming repository's vendor/pawprint/ tree, or
 * verifies the copies still match.
 *
 * Bicep has no module registry available here, so sharing means copying, and a
 * copy nobody re-syncs quietly becomes a fork. The CI gate in
 * kit-bicep-validate.yml catches that after the fact; this is how it gets fixed
 * without hand-copying files and hoping.
 *
 * Line endings are normalised before comparing, because the consumer and the
 * kit are separate checkouts and a CRLF difference is not a fork.
 *
 *   node scripts/vendor-sync.mjs --target ../site
 *   node scripts/vendor-sync.mjs --target ../site --check
 *   node scripts/vendor-sync.mjs --target ../site --add modules/naming/main.bicep
 *   node scripts/vendor-sync.mjs --target ../site ../m365profiles --check
 */

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = join(REPO_ROOT, "config", "vendor.manifest.json");

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    target: { type: "string", multiple: true, default: [] },
    add: { type: "string", multiple: true, default: [] },
    check: { type: "boolean", default: false },
    "verify-sources": { type: "boolean", default: false },
    prefix: { type: "string", default: "vendor/pawprint" },
    snapshot: { type: "boolean", default: false },
    "verify-snapshot": { type: "string" },
  },
});

const normalise = (path) => readFileSync(path, "utf8").replace(/\r\n/g, "\n");
const contentHash = (path) => createHash("sha256").update(normalise(path)).digest("hex");
const validPrefix = (prefix) => typeof prefix === "string" && /^vendor\/pawprint(?:-[a-z0-9-]+)?$/.test(prefix);
const vendorPrefix = values.prefix.replaceAll("\\", "/");
if (!validPrefix(vendorPrefix)) throw new Error("--prefix must be vendor/pawprint or a vendor/pawprint-NAME snapshot directory.");

if (values["verify-snapshot"]) {
  const path = resolve(values["verify-snapshot"]);
  let snapshot;
  try {
    snapshot = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("Cannot read a valid Pawprint vendor snapshot; contents omitted.");
  }
  const targetRoot = resolve(dirname(path), "..");
  if (snapshot.version !== 1 || snapshot.source !== "https://github.com/ninjapaw/pawprint"
      || !validPrefix(snapshot.vendorPath)
      || resolve(targetRoot, `${snapshot.vendorPath}.manifest.json`) !== path
      || !Array.isArray(snapshot.files) || !snapshot.files.length || snapshot.files.length > 100) {
    throw new Error("Invalid Pawprint vendor snapshot metadata or location.");
  }
  const seen = new Set();
  for (const entry of snapshot.files) {
    if (typeof entry.path !== "string" || !/^[a-z0-9_.-]+(?:\/[a-z0-9_.-]+)*$/i.test(entry.path)
        || entry.path.split("/").some((part) => [".", ".."].includes(part))
        || seen.has(entry.path) || !/^[a-f0-9]{64}$/.test(entry.sha256 ?? "")) {
      throw new Error("Invalid or duplicate path/hash in Pawprint vendor snapshot.");
    }
    seen.add(entry.path);
    const file = join(targetRoot, ...snapshot.vendorPath.split("/"), ...entry.path.split("/"));
    if (!existsSync(file) || contentHash(file) !== entry.sha256) {
      throw new Error(`Pawprint snapshot drift at ${entry.path}; re-sync from reviewed shared source.`);
    }
    process.stdout.write(`ok    snapshot  ${entry.path}\n`);
  }
  process.stdout.write(`Verified ${seen.size} vendored Pawprint snapshot files.\n`);
  process.exit(0);
}

const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
const known = new Set(manifest.files.map((entry) => entry.path));
const byPath = new Map(manifest.files.map((entry) => [entry.path, entry]));
for (const entry of manifest.files) {
  if (entry.requires !== undefined && !Array.isArray(entry.requires)) throw new Error(`Invalid vendor dependencies for ${entry.path}.`);
  for (const dependency of entry.requires ?? []) {
    if (!known.has(dependency)) throw new Error(`Unknown vendor dependency for ${entry.path}.`);
  }
}

// Runs in this repository's own CI: a shared file renamed without updating the
// manifest would silently stop being vendored anywhere.
if (values["verify-sources"]) {
  let absent = 0;
  for (const entry of manifest.files) {
    if (existsSync(join(REPO_ROOT, entry.path))) {
      process.stdout.write(`ok    ${entry.path}\n`);
    } else {
      process.stderr.write(
        `FAIL  ${entry.path} is in the manifest but missing from this repository.\n`,
      );
      absent += 1;
    }
  }
  if (absent > 0) {
    process.stderr.write(`\n${absent} manifest entr(y/ies) missing.\n`);
    process.exit(1);
  }
  process.stdout.write("\nEvery vendorable file exists.\n");
  process.exit(0);
}

const targets = [...values.target, ...positionals];
if (targets.length === 0) {
  process.stderr.write(
    "Specify at least one --target <path to consuming repository>, or --verify-sources.\n",
  );
  process.exit(1);
}

for (const requested of values.add) {
  if (!known.has(requested.split("\\").join("/"))) {
    process.stderr.write(
      `'${requested}' is not in config/vendor.manifest.json. Add it there first so the drift gate knows about it.\n`,
    );
    process.exit(1);
  }
}

let drifted = 0;
let copied = 0;
let missingSources = 0;

for (const target of targets) {
  const targetRoot = resolve(target);
  if (!existsSync(targetRoot)) {
    process.stderr.write(`FAIL  target '${targetRoot}' does not exist.\n`);
    process.exit(1);
  }

  process.stdout.write(`\n${targetRoot}\n`);

  const selected = new Set();
  function select(path) {
    if (selected.has(path)) return;
    selected.add(path);
    for (const dependency of byPath.get(path).requires ?? []) select(dependency);
  }
  for (const entry of manifest.files) {
    if (existsSync(join(targetRoot, ...vendorPrefix.split("/"), entry.path))
        || values.add.some((candidate) => candidate.replaceAll("\\", "/") === entry.path)) {
      select(entry.path);
    }
  }

  for (const entry of manifest.files) {
    const source = join(REPO_ROOT, entry.path);
    const destination = join(targetRoot, ...vendorPrefix.split("/"), entry.path);

    if (!existsSync(source)) {
      process.stderr.write(
        `  FAIL  ${entry.path} is in the manifest but missing from this repository.\n`,
      );
      missingSources += 1;
      continue;
    }

    const requested = selected.has(entry.path);
    if (!existsSync(destination) && !requested) {
      process.stdout.write(`  skip  ${entry.path} (not vendored here)\n`);
      continue;
    }

    if (
      existsSync(destination) &&
      normalise(source) === normalise(destination)
    ) {
      process.stdout.write(`  ok    ${entry.path}\n`);
      continue;
    }

    if (values.check) {
      process.stderr.write(`  DRIFT ${entry.path}\n`);
      drifted += 1;
      continue;
    }

    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(source, destination);
    copied += 1;
    process.stdout.write(
      `  sync  ${relative(targetRoot, destination).split("\\").join("/")}\n`,
    );
  }
  if (values.snapshot && !values.check) {
    const sourceRevision = execFileSync("git", ["-C", REPO_ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    const files = manifest.files
      .filter((entry) => existsSync(join(targetRoot, ...vendorPrefix.split("/"), entry.path)))
      .map((entry) => ({
        path: entry.path,
        sha256: contentHash(join(targetRoot, ...vendorPrefix.split("/"), entry.path)),
      }));
    if (!files.length) throw new Error("A vendor snapshot requires at least one explicitly selected or existing shared file.");
    writeFileSync(join(targetRoot, `${vendorPrefix}.manifest.json`), `${JSON.stringify({
      version: 1, source: "https://github.com/ninjapaw/pawprint",
      sourceRevision: `working-tree@${sourceRevision}`, vendorPath: vendorPrefix,
      note: "Content hashes identify this reviewed source snapshot; the base commit alone does not. Publish shared-source changes before consumers. Existing core-kit workflow pins remain unchanged.",
      files,
    }, null, 2)}\n`);
  }
}

if (missingSources > 0) {
  process.stderr.write(
    `\n${missingSources} manifest entr(y/ies) missing from this repository.\n`,
  );
  process.exit(1);
}

if (values.check) {
  if (drifted > 0) {
    process.stderr.write(
      `\n${drifted} vendored file(s) drifted. Re-run without --check to re-vendor.\n`,
    );
    process.exit(1);
  }
  process.stdout.write("\nAll vendored files are in sync.\n");
} else {
  process.stdout.write(`\n${copied} file(s) re-vendored.\n`);
}
