import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  workers: 2,
  retries: 0,
  use: {
    baseURL: "http://127.0.0.1:4183",
    viewport: { width: 1440, height: 960 },
  },
  webServer: [{
    command: "npx next start --hostname 127.0.0.1 --port 4183",
    url: "http://127.0.0.1:4183",
    reuseExistingServer: false,
    stderr: "pipe",
    env: {
      RECRUITER_LOCAL_LAB: "1",
      FRONTEND_ORIGIN: "http://127.0.0.1:4183",
      NEXT_TELEMETRY_DISABLED: "1",
    },
  }, {
    command: "npx next start --hostname 127.0.0.1 --port 4185",
    url: "http://127.0.0.1:4185",
    reuseExistingServer: false,
    stderr: "pipe",
    env: {
      FRONTEND_ORIGIN: "http://127.0.0.1:4185",
      NEXT_TELEMETRY_DISABLED: "1",
      RECRUITER_LOCAL_LAB: "0",
      RECRUITER_AUTH_PROJECT: "disposable-local",
      RECRUITER_AUTH_PUBLISHABLE_KEY: "public-fixture",
      RECRUITER_GOOGLE_ENABLED: "1",
      RECRUITER_CAPTCHA_MODE: "required",
      RECRUITER_TURNSTILE_SITE_KEY: "fixture-only",
    },
  }],
});
