import { expect, test } from '@playwright/test';
import { installMocks } from './mocks';

test.describe('live map', () => {
  test('renders the world, replays history and updates panels', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await installMocks(page);
    await page.goto('/');

    // Map geography loaded from the bundled topojson.
    await expect(page.locator('svg#map path.land')).toHaveCount(1);
    await expect(page.locator('svg#map path.border')).toHaveCount(1);

    // WebSocket connected and replay counted.
    await expect(page.locator('#ws-status')).toHaveAttribute('data-status', 'open');
    await expect(page.locator('#conn-count')).not.toHaveText('0');
    await expect(page.locator('svg#map circle.src-dot').first()).toBeVisible();

    // Live events produce arcs.
    await expect(page.locator('svg#map path.arc-path').first()).toBeAttached({ timeout: 5000 });

    // Panels populated from /api/* mocks and from the event stream.
    await expect(page.locator('#service-rows .svc-row').first()).toBeVisible({ timeout: 6000 });
    await expect(page.locator('#service-rows')).toContainText('SSH');
    await expect(page.locator('#scanner-rows')).toContainText('198.51.100.99');
    await expect(page.locator('#banned-rows')).toContainText('198.51.100.7');
    await expect(page.locator('#ebpf-rows')).toContainText('Hybrid');
    await expect(page.locator('#log-panel .log-entry').first()).toBeVisible();

    // Theme toggle flips the data-theme attribute.
    await page.locator('[data-theme-toggle]').click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', /light|dark/);

    // Pause control.
    await page.locator('#pause-btn').click();
    await expect(page.locator('#ws-status')).toHaveAttribute('data-status', 'paused');
    await page.locator('#pause-btn').click();
    await expect(page.locator('#ws-status')).toHaveAttribute('data-status', 'open');

    expect(errors).toEqual([]);
  });

  test('clicking a log row starts a traceroute', async ({ page }) => {
    await installMocks(page, { live: 2 });
    await page.goto('/');
    const row = page.locator('#log-panel .log-entry.clickable').first();
    await expect(row).toBeVisible();
    await row.click();
    await expect(page.locator('#trace-indicator')).toHaveClass(/visible/);
    await expect(page.locator('svg#map .layer-trace circle').first()).toBeAttached({ timeout: 8000 });
    await page.keyboard.press('Escape');
    await expect(page.locator('#trace-indicator')).not.toHaveClass(/visible/);
  });
});

test.describe('history', () => {
  test('runs a query and renders charts + table', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await installMocks(page);
    await page.goto('/history.html');
    await page.locator('#btn-query').click();
    await expect(page.locator('#results')).toBeVisible();
    await expect(page.locator('#kpi-tiles .tile')).toHaveCount(4);
    await expect(page.locator('#chart-timeline svg rect')).not.toHaveCount(0);
    await expect(page.locator('#chart-ports svg rect.bar')).toHaveCount(3);
    await expect(page.locator('#card-port-timeline')).toBeVisible();
    await expect(page.locator('#card-ebpf')).toBeVisible();
    await expect(page.locator('#result-tbody tr')).toHaveCount(30);
    expect(errors).toEqual([]);
  });
});

test.describe('recent', () => {
  test('lists events with client data and expands hex dumps', async ({ page }) => {
    await installMocks(page);
    await page.goto('/recent.html');
    await expect(page.locator('#event-list .log-entry')).toHaveCount(6);
    await page.locator('#expand-all-btn').click();
    await expect(page.locator('.log-entry.expanded').first()).toBeVisible();
    await expect(page.locator('.log-client-data').first()).toContainText('GET / HTTP/1.1');
    await page.locator('#filter-data').uncheck();
    await expect(page.locator('#event-list .log-entry')).toHaveCount(12);
  });
});
