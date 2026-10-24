import { readRecordedWalkthroughCapture } from "../lib/operatorCapture.mjs";

export async function GET() {
  const capture = await readRecordedWalkthroughCapture();
  return Response.json(capture, {
    status: capture.operatorJob?.state === "unavailable" ? 503 : 200,
    headers: {
      "Cache-Control": "no-store",
      "Content-Disposition": 'attachment; filename="pawton-walkthrough-live-capture.json"',
    },
  });
}
