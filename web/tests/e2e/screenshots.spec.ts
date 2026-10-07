import { test } from '@playwright/test';
import { installMocks } from './mocks';

// Visual review helper: `SHOTS_DIR=/tmp/shots npx playwright test screenshots`
const dir = process.env.SHOTS_DIR;
test.skip(!dir, 'set SHOTS_DIR to capture screenshots');

const pages = [
  ['live', '/'],
  ['history', '/history.html'],
  ['recent', '/recent.html'],
] as const;

for (const [name, path] of pages) {
  for (const theme of ['dark', 'light'] as const) {
    for (const [vp, size] of [
      ['desktop', { width: 1400, height: 860 }],
      ['mobile', { width: 390, height: 780 }],
    ] as const) {
      test(`${name} ${theme} ${vp}`, async ({ page }) => {
        await page.setViewportSize(size);
        await page.emulateMedia({ colorScheme: theme });
        await installMocks(page, { live: 6 });
        await page.goto(path);
        if (name === 'history') await page.locator('#btn-query').click();
        if (name === 'live') {
          await page.waitForSelector('svg#map path.arc-path');
          await page.waitForTimeout(2500);
          if (vp === 'mobile') await page.locator('.panel-toggle[data-drawer="right"]').click();
        }
        await page.waitForTimeout(300);
        await page.screenshot({ path: `${dir}/${name}-${theme}-${vp}.png`, fullPage: name === 'history' });
      });
    }
  }
}
