import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readEvidence, clean } from "../lib/evidence";
import { statusService } from "../lib/status";
test("relationships and marker suppression", () => {
  const d = readEvidence();
  expect(d.findings).toHaveLength(4);
  expect(d.attacks).toHaveLength(42);
  expect(JSON.stringify(d)).not.toContain("SYNTHETIC_CANARY_");
  expect(clean("S|Y|N|T|H|E|T|I|C|_|C|A|N|A|R|Y")).toContain("withheld");
});
test("filters and return preserve the selected results", async ({ page }) => {
  await page.goto("/findings/");
  await expect(
    page.getByText("4 of 4 findings", { exact: true }),
  ).toBeVisible();
  await page.getByLabel("Severity", { exact: true }).selectOption("High");
  await expect(page.getByText("No results match")).toBeVisible();
  await page.getByRole("button", { name: "Reset filters" }).click();
  await page
    .getByLabel("Category", { exact: true })
    .selectOption("exfiltration");
  await page.locator(".result-list a").first().click();
  await page.getByRole("link", { name: "Back to filtered findings" }).click();
  await expect(page.getByLabel("Category", { exact: true })).toHaveValue(
    "exfiltration",
  );
  await page.getByRole("button", { name: "Reset filters" }).click();
  await page
    .getByLabel("Search", { exact: true })
    .fill("finding-e36908846b7c7681");
  await expect(page.locator(".result-list li")).toHaveCount(1);
  await page.getByRole("button", { name: "Reset filters" }).click();
  await page.getByLabel("Sort", { exact: true }).selectOption("severity");
  await expect(page.locator(".result-list span").first()).toContainText("5.5");
});
test("outcomes, payload and related evidence", async ({ page }) => {
  await page.goto("/tests/");
  await page
    .getByLabel("Outcome", { exact: true })
    .selectOption("INDETERMINATE");
  await expect(page.locator(".result-list li")).toHaveCount(4);
  await page.locator(".result-list a").first().click();
  await expect(
    page.getByRole("heading", { name: "Indeterminate", exact: true }),
  ).toBeVisible();
  await page.getByText("Submitted payload availability").click();
  await expect(page.locator("pre")).toBeVisible();
  await page.getByText("Recorded trace timeline", { exact: true }).click();
  await expect(page.locator("ol li").first()).toBeVisible();
  expect(
    (
      await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze()
    ).violations.map((v) => v.id),
  ).toEqual([]);
  await page.goto("/findings/finding-e36908846b7c7681/");
  await page
    .getByRole("link", { name: "Classification Swap", exact: true })
    .click();
  await expect(page).toHaveURL(
    /attacks\/argument-tampering-classification-swap/,
  );
});
test("probe UI uses safe outcomes", async ({ page }) => {
  await page.route("**/api/status/", (route) =>
    route.fulfill({
      json: { status: "ready", checkedAt: "2026-11-15T00:00:00Z" },
    }),
  );
  await page.goto("/tools/");
  await page.getByRole("button", { name: "Check backend readiness" }).click();
  await expect(page.getByRole("status")).toContainText("Backend ready");
  await page.route("**/api/status/", (route) =>
    route.fulfill({ status: 503, json: { error: "unavailable" } }),
  );
  await page.getByRole("button", { name: "Check backend readiness" }).click();
  await expect(page.getByRole("status")).toContainText(
    "Backend readiness is unavailable",
  );
  await page.getByText("write_note — Protected write", { exact: true }).click();
  await expect(page.getByText(/stable Idempotency-Key/)).toBeVisible();
});
test("server rejects unsupported methods, destinations, origins and credentials", async ({
  request,
}) => {
  for (const path of [
    "/api/status?url=https://example.com",
    "/api/status?tool=write_note",
  ])
    expect((await request.get(path)).status()).toBe(400);
  expect(
    (
      await request.get("/api/status", {
        headers: { origin: "https://attacker.test" },
      })
    ).status(),
  ).toBe(400);
  expect(
    (
      await request.get("/api/status", {
        headers: { authorization: "Bearer test" },
      })
    ).status(),
  ).toBe(400);
  expect((await request.post("/api/status", { data: {} })).status()).toBe(405);
  expect((await request.post("/api/write_note", { data: {} })).status()).toBe(
    404,
  );
  expect((await request.get("/attacks/missing/")).status()).toBe(404);
});
test("fixed probe validates response, bounds work and coalesces callers", async () => {
  let calls = 0;
  let release!: () => void;
  const barrier = new Promise<void>((r) => (release = r));
  let now = 0;
  const fake: typeof fetch = async (input, init) => {
    calls++;
    expect(input).toBe("https://readiness.example.invalid/readyz");
    expect(init?.redirect).toBe("error");
    expect(init?.headers).toBeUndefined();
    await barrier;
    return Response.json({ status: "ok" });
  };
  const check = statusService(fake, () => now);
  const a = check(),
    b = check();
  release();
  expect(await a).toEqual(await b);
  expect(calls).toBe(1);
  await check();
  expect(calls).toBe(1);
  now = 31000;
  await check();
  expect(calls).toBe(2);
  for (const res of [
    new Response("x".repeat(129)),
    new Response("{"),
    Response.json({ status: "ok", secret: "x" }),
    Response.json({ status: "ok" }, { status: 503 }),
  ])
    expect((await statusService(async () => res)()).status).toBe("unavailable");
  expect(
    (
      await statusService(async () => {
        throw Error("private DSN");
      })()
    ).status,
  ).toBe("unavailable");
});
test("malformed evidence fails closed and injected markup remains plain text", async ({
  page,
}) => {
  const { inspectAttack } = await import("../lib/evidence");
  expect(() => inspectAttack({ attack_id: "../../private" })).toThrow();
  expect(() =>
    inspectAttack({
      ...readEvidence().attacks[0],
      response: { events: "missing" },
    }),
  ).toThrow();
  await page.goto("/findings/?q=%3Cscript%3Ewindow.pwned%3D1%3C%2Fscript%3E");
  await expect(page.getByLabel("Search", { exact: true })).toHaveValue(
    "<script>window.pwned=1</script>",
  );
  expect(
    await page.evaluate(() => Reflect.get(window, "pwned")),
  ).toBeUndefined();
});
test("untrusted evidence renders encoded text instead of markup", async () => {
  const { renderToStaticMarkup } = await import("react-dom/server");
  const { createElement } = await import("react");
  const { EvidenceText } = await import("../components/evidence-text");
  const html = renderToStaticMarkup(
    createElement(EvidenceText, {
      text: '<img src=x onerror="alert(1)"><script>alert(1)</script>',
    }),
  );
  expect(html).not.toContain("<script>");
  expect(html).not.toContain("<img");
  expect(html).toContain("&lt;script&gt;");
});
