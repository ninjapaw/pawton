import {
  authorizeWalkthroughMutation,
  getWalkthroughViewer,
} from "../../../lib/walkthroughAuth.mjs";
import { walkthroughRunnableScenarios } from "../../../lib/walkthroughStory.mjs";
import { getRunDefenderEvidence } from "../../../lib/defenderStatus.mjs";
import {
  sqlAttackRunner,
  SimulationError,
} from "../../../lib/sqlAttackLab.mjs";

const headers = { "Cache-Control": "no-store" };

// Starts one of the walkthrough's bounded, unprivileged tests. The allow-list is enforced here
// rather than trusted from the page, so the guide account can never reach a privileged scenario.
export async function POST({ request, cookies }) {
  const denied = authorizeWalkthroughMutation(request, cookies);
  if (denied) return denied;
  let form;
  try {
    form = await request.formData();
  } catch {
    return Response.json(
      { error: "Invalid walkthrough request." },
      { status: 400, headers },
    );
  }
  if (form.get("confirm") !== "yes")
    return Response.json(
      { error: "Confirmation required." },
      { status: 400, headers },
    );
  const scenario = String(form.get("scenario") ?? "");
  if (!walkthroughRunnableScenarios.includes(scenario))
    return Response.json(
      { error: "This step can't be run from the walkthrough." },
      { status: 403, headers },
    );
  try {
    const run = await sqlAttackRunner.run(scenario);
    return Response.json({ run }, { status: 200, headers });
  } catch (error) {
    return Response.json(
      {
        run: error instanceof SimulationError ? error.run : undefined,
        error:
          error instanceof SimulationError
            ? error.message
            : "The live step is unavailable right now.",
      },
      {
        status: error instanceof SimulationError ? error.status : 502,
        headers,
      },
    );
  }
}

// Polls a walkthrough run for correlated Defender alerts. Alerts typically take several minutes.
export async function GET({ request, cookies }) {
  if (!getWalkthroughViewer(cookies))
    return Response.json(
      { error: "Walkthrough sign-in required." },
      { status: 401, headers },
    );
  const runId = new URL(request.url).searchParams.get("runId") || "";
  if (!/^[a-f0-9-]{36}$/i.test(runId))
    return Response.json(
      { error: "Invalid run identifier." },
      { status: 400, headers },
    );
  const run = sqlAttackRunner.getRun(runId);
  if (!run || !walkthroughRunnableScenarios.includes(run.scenario))
    return Response.json(
      {
        error:
          "Run unavailable or expired. Runs are kept for up to 24 hours and reset when the app restarts.",
      },
      { status: 404, headers },
    );
  return Response.json(
    { run, evidence: await getRunDefenderEvidence(run) },
    { headers },
  );
}
