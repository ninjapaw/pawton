import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const root = new URL("../", import.meta.url);

test("Git deployments select the portal subdirectory", async () => {
  const configuration = await readFile(new URL(".deployment", root), "utf8");
  assert.match(
    configuration,
    /^\[config\]\r?\nproject = apps\/pawton-manufacturing\r?\n$/,
  );
  const portal = JSON.parse(
    await readFile(new URL("apps/pawton-manufacturing/package.json", root), "utf8"),
  );
  assert.equal(portal.name, "pawton-manufacturing");
});

test("every page links to the Pawton GitHub repository in the shared footer", async () => {
  const layout = await readFile(
    new URL("apps/pawton-manufacturing/src/layouts/Layout.astro", root),
    "utf8",
  );
  const footer = layout.slice(
    layout.indexOf("<footer>"),
    layout.indexOf("</footer>"),
  );
  assert.match(
    footer,
    /<a href="https:\/\/github\.com\/ninjapaw\/pawton" target="_blank" rel="noopener noreferrer">GitHub source<\/a>/,
  );
  assert.doesNotMatch(footer, /adminUsername|staffUsername|guideUsername/);
});

test("CI retains a source-bound Linux website package only after tests and build", async () => {
  const workflow = await readFile(new URL(".github/workflows/validate-infrastructure.yml", root), "utf8");
  const build = workflow.indexOf("npm run build --prefix apps/pawton-manufacturing");
  const packageStep = workflow.indexOf("name: Package verified Linux website");
  assert.ok(build >= 0 && packageStep > build);
  assert.match(workflow, /npm prune --omit=dev --prefix apps\/pawton-manufacturing/);
  assert.ok(workflow.includes("'.env' '.env.*' '.npmrc'"));
  for (const path of ["package.json", "package-lock.json", "dist/server/entry.mjs", "src/layouts/Layout.astro"]) {
    assert.ok(workflow.includes(path), `Package validation must require ${path}`);
  }
  assert.match(workflow, /name: pawton-site-\$\{\{ github\.sha \}\}/);
  assert.match(workflow, /path: \$\{\{ runner\.temp \}\}\/pawton-app\.zip/);
  assert.match(workflow, /if-no-files-found: error/);
  assert.match(workflow, /retention-days: 1/);
});
