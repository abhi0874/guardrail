import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { countNames, readCounts } from "../lib/snapshot";
import { scannerSnapshot } from "../lib/export";

test("public snapshot matches the validated export and contains only approved counts", async ({
  request,
}) => {
  const res = await request.get("/data/scanner.json");
  expect(res.ok()).toBeTruthy();
  const json = await res.json();
  expect(Object.keys(json).sort()).toEqual([...countNames].sort());
  expect(json).toEqual(scannerSnapshot());
  for (const value of [-1, 0.2, "31", null, 2]) {
    expect(() =>
      readCounts({ ...json, blocked_or_not_observed: value }),
    ).toThrow();
  }
});

test("overview and references work without outbound traffic or writes", async ({
  page,
}) => {
  const violations: string[] = [];
  await page.route("**/*", async (route) => {
    if (
      new URL(route.request().url()).origin !== "http://127.0.0.1:4183" ||
      !["GET", "HEAD"].includes(route.request().method())
    ) {
      violations.push(
        route.request().method() +
          " " +
          new URL(route.request().url()).protocol +
          " " +
          new URL(route.request().url()).hostname,
      );
      return route.abort();
    }
    await route.continue();
  });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.name));
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  await page.getByRole("link", { name: "View audit evidence" }).click();
  await expect(page.getByText("HTTP 409 / denied")).toBeVisible();
  for (const name of [
    "MCP tools",
    "Security tests",
    "Findings",
    "Performance",
    "Overview",
  ]) {
    const link = page
      .getByRole("navigation")
      .getByRole("link", { name, exact: true });
    await link.click();
    await expect(link).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(
      name === "Overview" ? "Security overview" : name,
    );
    if (name === "MCP tools")
      await expect(page.locator(".tool-list li")).toHaveCount(6);
    if (name === "Security tests")
      await expect(page.getByText("recorded executions")).toBeVisible();
  }
  expect(violations).toEqual([]);
  expect(errors).toEqual([]);
});
test("keyboard skip and a fixed palette with an old preference across reload", async ({
  page,
}) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByText("Skip to content")).toBeFocused();
  await expect(page.getByText("Skip to content")).toHaveCSS("top", "8px");
  await expect(page.getByText("Skip to content")).toHaveCSS("outline-style", "solid");
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();
  await page.emulateMedia({ colorScheme: "dark" });
  await page.context().addCookies([{ name: "guardrail-appearance", value: "dark", url: "http://127.0.0.1:4183" }]);
  await page.evaluate(() => localStorage.setItem("guardrail-theme", "dark"));
  await page.reload();
  expect(await page.locator("html").evaluate((el) => getComputedStyle(el).colorScheme)).toBe("light only");
  await expect(page.getByRole("button", { name: /switch to .* theme/i })).toHaveCount(0);
});
test("mobile menu supports keyboard dismissal and selecting a destination", async ({
  page,
}) => {
  await page.setViewportSize({ width: 320, height: 720 });
  await page.goto("/");
  const trigger = page.getByRole("button", { name: "Open navigation" });
  await trigger.focus();
  await page.keyboard.press("Enter");
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("navigation").getByRole("link", { name: "Overview" }),
  ).toBeFocused();
  await expect(
    page.getByRole("navigation").getByRole("link", { name: "Overview" }),
  ).toHaveCSS("outline-style", "solid");
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
  await trigger.click();
  await page.getByRole("link", { name: "Findings", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Findings", exact: true }),
  ).toBeVisible();
  await expect(trigger).toHaveAttribute("aria-expanded", "false");
});
test("saved report shows loading, recoverable error and empty states", async ({
  page,
}) => {
  let release!: () => void;
  const barrier = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/data/scanner.json", async (route) => {
    await barrier;
    await route.fulfill({ status: 500, body: "failure" });
  });
  await page.goto("/tests/", { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("status")).toHaveText("Loading saved snapshot…");
  release();
  await expect(page.getByRole("main").getByRole("alert")).toContainText(
    "could not be read",
  );
  await page.route("**/data/scanner.json", (route) =>
    route.fulfill({ json: Object.fromEntries(countNames.map((k) => [k, 0])) }),
  );
  await page.getByRole("button", { name: "Reload snapshot" }).click();
  await expect(page.getByRole("status")).toContainText(
    "no recorded executions",
  );
});
for (const width of [1440, 1024, 768, 375, 320]) {
  test(`responsive accessibility at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 950 });
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Scanner outcomes" }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBeTruthy();
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze();
    expect(
      results.violations.map((v) => [v.id, v.nodes.map((n) => n.target)]),
    ).toEqual([]);
  });
}

for (const width of [1440, 320]) {
  test(`reference pages remain accessible at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 960 });
    for (const section of ["tools", "tests", "findings", "audit", "performance"]) {
      await page.goto("/" + section + "/");
      if (section === "tests")
        await expect(page.getByText("recorded executions", { exact: true })).toBeVisible();
      expect(await page.locator("html").evaluate((el) => getComputedStyle(el).colorScheme)).toBe("light only");
      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze();
      expect(results.violations.map((v) => v.id), section).toEqual([]);
    }
  });
}
