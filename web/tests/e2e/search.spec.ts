import { expect, test } from '@playwright/test';
import { installMocks } from './mocks';

test.describe('history search', () => {
  test('sends q, shows chips + badges, and syncs the URL hash', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    const log: string[] = [];
    await installMocks(page, { historyLog: log });
    await page.goto('/history.html');

    const input = page.locator('#sb-input');
    await input.fill('port:22 -cc:US');
    await input.press('Enter');
    await expect(page.locator('#results')).toBeVisible();

    expect(log.at(-1)).toContain('q=port%3A22+-cc%3AUS');
    await expect(page.locator('.sb-chips .chip')).toHaveCount(2);
    await expect(page).toHaveURL(/#.*q=port%3A22\+-cc%3AUS/);
    await expect(page.locator('#scope-note')).toBeVisible();

    // kind / class / scanner badges render with text, not colour alone.
    await expect(page.locator('#result-tbody .badge-scanner').first()).toContainText('Shodan');
    await expect(page.locator('#result-tbody .badge-class[data-value="bruteforce"]').first()).toContainText('bruteforce');
    await expect(page.locator('#result-tbody .badge-kind[data-value="session"]').first()).toContainText('session');

    // Removing a chip re-runs the search without that term.
    await page.getByRole('button', { name: 'Remove filter -cc:US' }).click();
    await expect.poll(() => log.at(-1)).toContain('q=port%3A22');
    expect(log.at(-1)).not.toContain('cc%3AUS');
    expect(errors).toEqual([]);
  });

  test('autocompletes keys with the keyboard', async ({ page }) => {
    await installMocks(page);
    await page.goto('/history.html');
    const input = page.locator('#sb-input');
    await input.focus();
    await input.pressSequentially('cl');
    await expect(page.locator('#sb-list [role=option]')).toHaveText([/class:/]);
    await expect(input).toHaveAttribute('aria-expanded', 'true');
    await input.press('ArrowDown');
    await input.press('Enter');
    await expect(input).toHaveValue('class:');
    await input.pressSequentially('ex');
    await input.press('ArrowDown');
    await input.press('Tab');
    await expect(input).toHaveValue('class:exploit ');
    await expect(input).toHaveAttribute('aria-expanded', 'false');
  });

  test('shows the backend 400 message inline', async ({ page }) => {
    await installMocks(page);
    await page.goto('/history.html');
    await page.locator('#sb-input').fill('explode');
    await page.locator('#sb-input').press('Enter');
    await expect(page.locator('#sb-error')).toBeVisible();
    await expect(page.locator('#sb-error')).toContainText('unexpected token "explode"');
    await expect(page.locator('#sb-input')).toHaveAttribute('aria-invalid', 'true');
    // Editing clears it.
    await page.locator('#sb-input').fill('port:22');
    await expect(page.locator('#sb-error')).toBeHidden();
  });

  test('flags an unterminated quote without calling the server', async ({ page }) => {
    const log: string[] = [];
    await installMocks(page, { historyLog: log });
    await page.goto('/history.html');
    await page.locator('#sb-input').fill('user:"abc');
    await page.locator('#sb-input').press('Enter');
    await expect(page.locator('#sb-error')).toContainText('Unterminated quote');
    expect(log).toHaveLength(0);
  });

  test('quick chips toggle terms; saved views persist and delete', async ({ page }) => {
    const log: string[] = [];
    await installMocks(page, { historyLog: log });
    await page.goto('/history.html');
    await page.getByRole('button', { name: 'exploit', exact: true }).click();
    await expect(page.locator('#sb-input')).toHaveValue('class:exploit');
    await expect.poll(() => log.at(-1)).toContain('q=class%3Aexploit');
    await expect(page.getByRole('button', { name: 'exploit', exact: true })).toHaveAttribute('aria-pressed', 'true');

    await page.locator('.sb-view-name').fill('Exploits');
    await page.getByRole('button', { name: 'Save view' }).click();
    await expect(page.locator('.view-apply')).toHaveText('Exploits');

    await page.reload();
    await expect(page.locator('.view-apply')).toHaveText('Exploits');
    await page.locator('#sb-input').fill('');
    await page.locator('.view-apply').click();
    await expect(page.locator('#sb-input')).toHaveValue('class:exploit');

    await page.getByRole('button', { name: 'Delete saved view Exploits' }).click();
    await expect(page.locator('.view-apply')).toHaveCount(0);
    await page.reload();
    await expect(page.locator('.view-apply')).toHaveCount(0);
  });

  test('a shared link restores the search and runs it', async ({ page }) => {
    const log: string[] = [];
    await installMocks(page, { historyLog: log });
    await page.goto('/history.html#q=cc%3ACN+%22login+failed%22&preset=24');
    await expect(page.locator('#results')).toBeVisible();
    await expect(page.locator('#sb-input')).toHaveValue('cc:CN "login failed"');
    await expect(page.locator('#f-preset')).toHaveValue('24');
    expect(log[0]).toContain('q=cc%3ACN+%22login+failed%22');
  });

  test('time scrubber narrows the table', async ({ page }) => {
    await installMocks(page);
    await page.goto('/history.html');
    await page.locator('#btn-query').click();
    await expect(page.locator('#result-tbody tr')).toHaveCount(30);
    await expect(page.locator('#scrub-count')).toContainText('30 events loaded');
    const lo = page.locator('#scrub-lo');
    await lo.focus();
    for (let i = 0; i < 40; i++) await lo.press('PageUp');
    await expect(page.locator('#scrub-count')).toContainText('in window');
    const rows = await page.locator('#result-tbody tr').count();
    expect(rows).toBeLessThan(30);
    expect(rows).toBeGreaterThan(0);
    await page.locator('#scrub-reset').click();
    await expect(page.locator('#result-tbody tr')).toHaveCount(30);
  });
});

test.describe('top + campaigns', () => {
  test('ranks with bars and trends, and a row becomes a search filter', async ({ page }) => {
    const log: string[] = [];
    await installMocks(page, { historyLog: log });
    await page.goto('/history.html');
    const rows = page.locator('#top-list .top-row');
    await expect(rows).toHaveCount(4);
    await expect(rows.nth(0)).toContainText('AS14061 DigitalOcean');
    await expect(rows.nth(0).locator('.top-trend')).toHaveText('↑ 37%');
    await expect(rows.nth(1).locator('.top-trend')).toHaveText('↓ 20%');
    await expect(rows.nth(2).locator('.top-trend')).toHaveText('new');
    await expect(rows.nth(3).locator('.top-trend')).toHaveText('');
    await expect(rows.nth(0).locator('.top-ips')).toHaveText('57 IPs');

    await page.locator('#top-hours button[data-hours="168"]').click();
    await expect(page.locator('#top-hours button[data-hours="168"]')).toHaveAttribute('aria-pressed', 'true');

    await rows.nth(0).click();
    await expect(page.locator('#sb-input')).toHaveValue('asn:14061');
    await expect(page.locator('#f-preset')).toHaveValue('168');
    await expect.poll(() => log.at(-1)).toContain('q=asn%3A14061');

    await page.locator('#top-by').selectOption('usernames');
    await expect(rows).toHaveCount(1);
    await expect(rows.first().locator('.top-trend')).toHaveText('→ 0%');
  });

  test('campaigns expand and apply their IPs as ip: filters', async ({ page }) => {
    const log: string[] = [];
    await installMocks(page, { historyLog: log });
    await page.goto('/history.html');
    await page.getByRole('tab', { name: 'Campaigns' }).click();
    const head = page.locator('.camp-head').first();
    await expect(head).toContainText('ja4:t13d1516h2_8daaf6152771');
    await expect(head).toContainText('40 IPs');
    await expect(head).toHaveAttribute('aria-expanded', 'false');
    await head.click();
    await expect(head).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('.camp-body').first()).toContainText('CN, US');
    await expect(page.locator('.camp-body').first()).toContainText('37 more not listed');
    await page.getByRole('button', { name: 'Search these 3 IPs' }).click();
    await expect(page.locator('#sb-input')).toHaveValue('ip:198.51.100.4 ip:198.51.100.5 ip:198.51.100.6');
    await expect.poll(() => log.length).toBeGreaterThan(0);
  });

  test('tabs support arrow keys', async ({ page }) => {
    await installMocks(page);
    await page.goto('/history.html');
    await page.locator('#tab-top').focus();
    await page.keyboard.press('ArrowRight');
    await expect(page.locator('#tab-campaigns')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#panel-campaigns')).toBeVisible();
    await expect(page.locator('#panel-top')).toBeHidden();
  });

  test('hides itself when the backend has neither endpoint', async ({ page }) => {
    await installMocks(page, { missing: ['top', 'campaigns'] });
    await page.goto('/history.html');
    await page.locator('#btn-query').click();
    await expect(page.locator('#results')).toBeVisible();
    await expect(page.locator('#insights')).toBeHidden();
  });

  test('hides only the tab whose endpoint is missing', async ({ page }) => {
    await installMocks(page, { missing: ['campaigns'] });
    await page.goto('/history.html');
    await expect(page.locator('#top-list .top-row').first()).toBeVisible();
    await expect(page.locator('#tab-campaigns')).toBeHidden();
    await expect(page.locator('#insights')).toBeVisible();
  });
});

test.describe('recent search + noise filter', () => {
  test('hides XDP-only events by default and the choice persists', async ({ page }) => {
    await installMocks(page);
    await page.goto('/recent.html');
    await page.locator('#filter-data').uncheck();
    await expect(page.locator('#event-list .log-entry')).toHaveCount(12);
    await expect(page.locator('#filter-noise')).toBeChecked();

    await page.locator('#filter-noise').uncheck();
    await expect(page.locator('#event-list .log-entry')).toHaveCount(16);
    await expect(page.locator('#event-list .badge-kind[data-value="observed"]')).toHaveCount(4);

    await page.reload();
    await expect(page.locator('#filter-noise')).not.toBeChecked();
  });

  test('filters the list client-side and shows scanner/class badges', async ({ page }) => {
    await installMocks(page);
    await page.goto('/recent.html');
    await expect(page.locator('#event-list .badge-scanner')).toContainText('Shodan');
    await expect(page.locator('#event-list .badge-class[data-value="exploit"]')).toHaveCount(1);
    await page.locator('#sb-input').fill('scanner:shodan');
    await expect(page.locator('#event-list .log-entry')).toHaveCount(1);
    await page.locator('#sb-input').fill('-scanner:shodan');
    await expect(page.locator('#event-list .log-entry')).toHaveCount(5);
  });
});

test.describe('live toggles', () => {
  test('hide-XDP toggle drops observed events and persists', async ({ page }) => {
    await installMocks(page, { replay: 5, live: 0, observedReplay: 3 });
    await page.goto('/');
    const btn = page.locator('#noise-toggle');
    await expect(btn).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('#conn-count')).toHaveText('5');

    await btn.click();
    await expect(btn).toHaveAttribute('aria-pressed', 'false');
    await expect(page.locator('#conn-count')).toHaveText('8');

    await page.reload();
    await expect(page.locator('#noise-toggle')).toHaveAttribute('aria-pressed', 'false');
    await expect(page.locator('#conn-count')).toHaveText('8');
  });

  test('strict trace toggle persists and tags the trace', async ({ page }) => {
    await installMocks(page, { live: 2 });
    await page.goto('/');
    const btn = page.locator('#trace-mode');
    await expect(btn).toHaveAttribute('aria-pressed', 'false');
    await btn.click();
    await expect(btn).toHaveAttribute('aria-pressed', 'true');
    expect(await page.evaluate(() => localStorage.getItem('wt_trace_mode'))).toBe('strict');

    await page.reload();
    await expect(page.locator('#trace-mode')).toHaveAttribute('aria-pressed', 'true');

    const row = page.locator('#log-panel .log-entry.clickable').first();
    await expect(row).toBeVisible();
    await row.click();
    await expect(page.locator('#trace-indicator')).toContainText('(strict)', { timeout: 8000 });
  });
});
