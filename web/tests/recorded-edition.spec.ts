import { test, expect } from "@playwright/test";

const recordedOrigin = "http://127.0.0.1:4185";

test("visitors can view each of the four recorded walkthroughs", async ({
  page,
}) => {
  const submitted: string[] = [];
  page.on("request", (req) => {
    if (req.method() !== "GET") submitted.push(req.method());
  });
  for (const section of ["playground", "scanner"]) {
    await page.goto(recordedOrigin + "/" + section + "/");
    await expect(
      page.getByRole("heading", { name: "Recorded result" }),
    ).toBeVisible();
    const options = page.getByRole("radio");
    await expect(options).toHaveCount(2);
    for (const choice of await options.all()) {
      await choice.check();
      await page.getByRole("button", { name: "View recorded trace" }).click();
      await expect(
        page.getByRole("heading", { name: "Execution trace" }),
      ).toBeVisible();
    }
  }
  expect(submitted).toEqual([]);
});

test("legacy account endpoints are absent with account configuration present", async ({
  page,
  request,
}) => {
  const outbound: string[] = [];
  page.on("request", (req) => {
    if (new URL(req.url()).origin !== recordedOrigin) outbound.push(req.url());
  });
  await page.goto(recordedOrigin);
  await expect(page.getByText("Recorded edition", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: /sign in|profile|settings/i })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /sign in|sign out/i })).toHaveCount(0);

  for (const path of ["/account/", "/account/recovery/", "/profile/", "/settings/",
    "/auth/callback/", "/api/account/session/"]) {
    const response = await request.get(recordedOrigin + path, { maxRedirects: 0 });
    expect(response.status(), path).toBe(404);
    expect(response.headers()["set-cookie"], path).toBeUndefined();
  }

  for (const path of ["/api/account/", "/account/recovery/complete/"]) {
    const response = await request.post(recordedOrigin + path, {
      headers: { origin: recordedOrigin },
      data: { action: "reset" },
      maxRedirects: 0,
    });
    expect(response.status(), path).toBe(404);
    expect(response.headers()["set-cookie"], path).toBeUndefined();
  }

  expect(outbound).toEqual([]);
});
