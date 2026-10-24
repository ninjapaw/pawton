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
