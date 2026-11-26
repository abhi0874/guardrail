import { test, expect } from "@playwright/test";
import { GET } from "../app/api/status/route";
import { statusService } from "../lib/status";

test("production configuration fails closed without disclosing values", async () => {
  const previous = process.env.FRONTEND_ORIGIN;
  const vercel = process.env.VERCEL;
  try {
    process.env.VERCEL = "1";
    delete process.env.FRONTEND_ORIGIN;
    expect(
      (
        await GET(
          new Request("https://site.test/api/status/", {
            headers: { host: "site.test" },
          }),
        )
      ).status,
    ).toBe(503);
    for (const origin of [
      "broken",
      "https://user:private@site.test",
      "https://site.test/extra",
      "http://site.test",
    ]) {
      process.env.FRONTEND_ORIGIN = origin;
      const result = await GET(
        new Request("https://site.test/api/status/", {
          headers: { host: "site.test" },
        }),
      );
      expect(result.status).toBe(503);
      expect(await result.text()).not.toContain("private");
    }
    process.env.FRONTEND_ORIGIN = "https://site.test";
    const result = await GET(
      new Request("https://site.test/api/status/", {
        headers: {
          host: "attacker.test",
          forwarded: "host=site.test;proto=https",
        },
      }),
    );
    expect(result.status).toBe(400);
  } finally {
    if (previous === undefined) delete process.env.FRONTEND_ORIGIN;
    else process.env.FRONTEND_ORIGIN = previous;
    if (vercel === undefined) delete process.env.VERCEL;
    else process.env.VERCEL = vercel;
  }
});
test("timeout and network failure are truthfully classified", async () => {
  for (const [name, reason] of [
    ["TimeoutError", "timeout"],
    ["TypeError", "network"],
  ] as const) {
    const result = await statusService(async () => {
      const error = new Error("Private upstream data");
      error.name = name;
      throw error;
    })();
    expect(result.status).toBe("unavailable");
    expect(result.reason).toBe(reason);
    expect(JSON.stringify(result)).not.toContain("Private");
  }
});
test("production headers and honest waiting state", async ({
  page,
  request,
}) => {
  const response = await request.get("/");
  expect(response.headers()["x-frame-options"]).toBe("DENY");
  expect(response.headers()["content-security-policy"]).toContain(
    "frame-ancestors 'none'",
  );
  let release!: () => void;
  const barrier = new Promise<void>((r) => (release = r));
  await page.route("**/api/status/", async (route) => {
    await barrier;
    await route.fulfill({ json: { status: "unavailable", reason: "timeout" } });
  });
  await page.goto("/tools/");
  await page.getByRole("button", { name: "Check backend readiness" }).click();
  await expect(page.getByRole("status")).toContainText("Checking the local readiness endpoint");
  await expect(
    page.getByRole("button", { name: "Check backend readiness" }),
  ).toBeDisabled();
  release();
  await expect(page.getByRole("status")).toContainText("timed out");
});
