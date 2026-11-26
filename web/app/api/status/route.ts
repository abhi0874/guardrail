import { checkReadiness } from "../../../lib/status";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 15;
export async function GET(request: Request) {
  let expected: URL;
  try {
    const configured =
      process.env.FRONTEND_ORIGIN ??
      (process.env.VERCEL ? "" : "http://127.0.0.1:4183");
    expected = new URL(configured);
    if (
      expected.username ||
      expected.password ||
      expected.search ||
      expected.hash ||
      expected.pathname !== "/" ||
      (expected.protocol !== "https:" &&
        !(
          expected.protocol === "http:" &&
          ["127.0.0.1", "localhost"].includes(expected.hostname)
        ))
    )
      throw Error();
  } catch {
    return Response.json(
      { error: "configuration_unavailable" },
      { status: 503 },
    );
  }
  const url = new URL(request.url);
  if (
    request.headers.get("host") !== expected.host ||
    (request.headers.has("origin") &&
      request.headers.get("origin") !== expected.origin) ||
    url.search ||
    request.headers.has("authorization")
  )
    return Response.json({ error: "request_denied" }, { status: 400 });
  const result = await checkReadiness();
  return Response.json(result, {
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
