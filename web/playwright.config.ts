import { defineConfig } from '@playwright/test';
import { existsSync } from 'node:fs';

// Chromium may be pre-installed outside the default cache (CI images).
const localChromium = '/opt/pw-browsers/chromium';
const executablePath = process.env.PW_CHROMIUM ?? (existsSync(localChromium) ? localChromium : undefined);

export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 30_000,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    headless: true,
    launchOptions: executablePath ? { executablePath } : {},
  },
  webServer: {
    command: 'npm run preview -- --host 127.0.0.1',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
