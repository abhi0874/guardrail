import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
test("reduced-motion mobile controls", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 800 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  for (const dest of ["playground", "scanner", "history"]) {
    await page.goto("/" + dest + "/");
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    expect(
      (
        await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze()
      ).violations.map((v) => v.id),
    ).toEqual([]);
  }
});
test("execute isolated tools and scanner checks, inspect history and reset", async ({
  page,
  browser,
}) => {
  await page.goto("/playground/");
  await page.getByRole("button", { name: "Run operation" }).click();
  await expect(page.getByText(/Service returned ok/)).toBeVisible();
  await page.getByLabel("Read the stdio guide", { exact: true }).check();
  await page.getByRole("button", { name: "Run operation" }).click();
  await expect(page.getByText(/Use stdio for local MCP/)).toBeVisible();
  await page.goto("/scanner/");
  await page.getByRole("button", { name: "Run check" }).click();
  await expect(
    page.getByText(
      "Complete trace shows no successful specified forbidden effect.",
    ),
  ).toBeVisible();
  await page.getByLabel("Internal document", { exact: true }).check();
  await page.getByRole("button", { name: "Run check" }).click();
  await expect(
    page.getByText(
      "Complete trace shows no successful specified forbidden effect.",
    ),
  ).toBeVisible();
  await page.getByRole("link", { name: "View execution history" }).click();
  await expect(page.locator("details")).toHaveCount(4);
  const stranger = await browser.newContext({
    baseURL: "http://127.0.0.1:4183",
  });
  try {
    expect(
      (await (await stranger.request.get("/api/lab/")).json()).runs,
    ).toEqual([]);
  } finally {
    await stranger.close();
  }
  await page.getByRole("button", { name: "Clear history" }).click();
  await expect(page.getByText("No runs in this browser yet.")).toBeVisible();
});
test("runner rejects foreign origins, arbitrary operations and oversized input", async ({
  request,
}) => {
  const send = (body: string, origin: string) =>
    request.post("/api/lab/", {
      headers: { origin, "content-type": "text/plain;charset=UTF-8" },
      data: body,
    });
  expect((await send("health", "https://foreign.invalid")).status()).toBe(403);
  expect((await send("fetch_url", "http://127.0.0.1:4183")).status()).toBe(400);
  expect((await send("x".repeat(300), "http://127.0.0.1:4183")).status()).toBe(
    413,
  );
});

test("busy readers get bounded admission and reset cannot replenish a visitor quota", async ({
  request,
}) => {
  const origin = "http://127.0.0.1:4183";
  const send = (body: string) =>
    request.post("/api/lab/", {
      headers: { origin, "content-type": "text/plain;charset=UTF-8" },
      data: body,
    });
  expect((await send("reader")).status()).toBe(200);
  const parallel = await Promise.all([send("health"), send("health")]);
  expect(parallel.map((r) => r.status()).sort()).toEqual([200, 429]);
  for (let i = 0; i < 3; i++) expect((await send("reader")).status()).toBe(200);
  expect((await send("reset")).status()).toBe(200);
  expect((await send("reader")).status()).toBe(429);
});
test("failed run offers a clean retry with no stale receipt", async ({
  page,
}) => {
  let once = true;
  await page.route("**/api/lab/", async (r) => {
    if (!once) return r.continue();
    once = false;
    await r.fulfill({ status: 503, json: { message: "Runner unavailable." } });
  });
  await page.goto("/playground/");
  await page.getByRole("button", { name: "Run operation" }).click();
  await expect(page.getByText("Runner unavailable.")).toBeVisible();
  await page.getByRole("button", { name: "Run operation" }).click();
  await expect(page.getByText(/Service returned ok/)).toBeVisible();
});
