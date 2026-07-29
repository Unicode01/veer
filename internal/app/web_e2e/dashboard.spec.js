const { expect, test } = require('@playwright/test');

const pluginPageHTML = `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Firewall fixture</title></head>
<body>
  <main class="veer-page">
    <section class="veer-card">
      <h1 class="veer-title">Firewall fixture</h1>
      <div class="veer-actions">
        <button id="shrink" type="button">Shrink</button>
        <button id="grow" type="button">Grow</button>
        <button id="confirm" type="button">Confirm</button>
      </div>
      <div id="resizable" style="height: 480px"></div>
    </section>
  </main>
  <script>
    document.getElementById('shrink').addEventListener('click', function () {
      document.getElementById('resizable').style.height = '20px';
      if (window.VeerPluginHost) window.VeerPluginHost.requestResize();
    });
    document.getElementById('grow').addEventListener('click', function () {
      document.getElementById('resizable').style.height = '480px';
      if (window.VeerPluginHost) window.VeerPluginHost.requestResize();
    });
    document.getElementById('confirm').addEventListener('click', function () {
      window.fixtureConfirmResult = 'pending';
      window.VeerPluginHost.confirm({
        title: 'Plugin confirmation',
        message: 'Confirm from sandbox',
        confirmText: 'Proceed',
        cancelText: 'Cancel',
        danger: true
      }).then(function (confirmed) {
        window.fixtureConfirmResult = confirmed;
      });
    });
  </script>
</body>
</html>`;

const netfilterDropper = {
  id: 'nf_dropper',
  name: 'Netfilter Dropper',
  kind: 'pipeline',
  stability: 'stable',
  version: '1.0.0',
  status: 'active',
  enabled: true,
  runtime: {
    mode: 'dataplane',
    attachable: true,
    attached: true,
    attachment_count: 1,
    attachments: [{
      hook_id: 'drop',
      engine: 'netfilter',
      family: 'ipv4',
      netfilter_hook: 'forward',
      phase: 'filter',
      namespace: 'host',
      attach: 'forward',
      stage: 'filter',
      interface: 'host',
      priority: 10,
      order: 0,
      program: 'dropper:nf_drop',
      filter_handle: 'bpf_link:priority=4',
      status: 'attached'
    }]
  }
};

const netfilterCounter = {
  id: 'nf_counter',
  name: 'Netfilter Counter',
  description: 'Counts packets at the native Netfilter forward hook.',
  kind: 'pipeline',
  stability: 'stable',
  version: '1.0.0',
  status: 'active',
  enabled: true,
  capabilities: ['netfilter', 'observe'],
  hooks: [{
    id: 'count',
    engine: 'netfilter',
    family: 'inet',
    hook: 'forward',
    phase: 'filter',
    namespace: 'host',
    priority: 20,
    program: 'counter:nf_count'
  }],
  ui: { entry: 'index.html', page: 'firewall', page_title: 'Firewall' },
  asset_base_path: '/api/plugins/nf_counter/assets/',
  runtime: {
    mode: 'dataplane',
    attachable: true,
    attached: true,
    attachment_count: 1,
    attachments: [{
      hook_id: 'count',
      engine: 'netfilter',
      family: 'ipv4',
      netfilter_hook: 'forward',
      phase: 'filter',
      namespace: 'host',
      attach: 'forward',
      stage: 'filter',
      interface: 'host',
      priority: 20,
      order: 1,
      program: 'counter:nf_count',
      filter_handle: 'bpf_link:priority=5',
      status: 'attached'
    }]
  }
};

const pluginCatalog = {
  external_plugins_enabled: true,
  directory: 'plugins',
  runtime: {
    control_enabled: true,
    external_dataplane_attach: true,
    core_priority: 1000
  },
  hot_reload: {
    enabled: true,
    update_available: false,
    last_check_result: 'unchanged',
    updates: []
  },
  plugins: [
    {
      id: 'veer_core',
      name: 'Veer Core',
      kind: 'builtin',
      stability: 'stable',
      version: '1.0.0',
      status: 'builtin',
      builtin: true,
      enabled: true,
      runtime: { mode: 'builtin', attachable: true, attached: true, attachment_count: 0, attachments: [] }
    },
    netfilterDropper,
    netfilterCounter
  ]
};

const apiFixtures = new Map([
  ['/api/tags', []],
  ['/api/interfaces', []],
  ['/api/host-network', { interfaces: [] }],
  ['/api/rules', []],
  ['/api/sites', []],
  ['/api/ranges', []],
  ['/api/managed-networks', []],
  ['/api/managed-networks/runtime-status', {}],
  ['/api/managed-network-reservation-candidates', []],
  ['/api/managed-network-reservations', []],
  ['/api/egress-nats', []],
  ['/api/ipv6-assignments', []],
  ['/api/plugins', pluginCatalog],
  ['/api/workers', { binary_hash: '0123456789abcdef', workers: [] }]
]);

const browserErrors = new WeakMap();

async function installDashboardFixtures(page, locale) {
  const errors = [];
  browserErrors.set(page, errors);
  page.on('pageerror', (error) => errors.push('pageerror: ' + error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push('console: ' + message.text());
  });

  await page.addInitScript((selectedLocale) => {
    if (window !== window.top) return;
    localStorage.setItem('veer_token', 'e2e-token');
    localStorage.setItem('veer_locale', selectedLocale);
    localStorage.setItem('veer_theme', 'light');
  }, locale);

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/plugins/nf_counter/assets/index.html') {
      await route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: pluginPageHTML });
      return;
    }
    if (route.request().method() === 'GET' && apiFixtures.has(url.pathname)) {
      await route.fulfill({ status: 200, contentType: 'application/json; charset=utf-8', body: JSON.stringify(apiFixtures.get(url.pathname)) });
      return;
    }
    await route.fulfill({
      status: 404,
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify({ error: 'missing E2E fixture: ' + route.request().method() + ' ' + url.pathname })
    });
  });
}

async function openDashboard(page, testInfo) {
  const locale = testInfo.project.name.startsWith('mobile') ? 'en-US' : 'zh-CN';
  await installDashboardFixtures(page, locale);
  await page.goto('/');
  await expect(page.locator('#app')).toBeVisible();
  await expect(page.locator('#masterVersion')).toHaveText('01234567');
}

async function expectNoPageOverflow(page) {
  await expect.poll(() => page.evaluate(() => (
    document.documentElement.scrollWidth - document.documentElement.clientWidth
  )), { message: 'page-level horizontal overflow' }).toBeLessThanOrEqual(1);
}

test.afterEach(async ({ page }) => {
  expect(browserErrors.get(page) || [], 'browser console and page errors').toEqual([]);
});

test('dashboard shell localizes cleanly and plugin details stay usable', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.locator('[data-tab="plugins"]').click();
  await expect(page.locator('#pluginsBody tr')).toHaveCount(3);

  const unresolved = await page.evaluate(() => {
    const values = [];
    document.querySelectorAll('[data-i18n]').forEach((node) => {
      const key = node.getAttribute('data-i18n') || '';
      if (node.textContent.trim() === key) values.push(key);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach((node) => {
      const key = node.getAttribute('data-i18n-placeholder') || '';
      if (node.getAttribute('placeholder') === key) values.push(key);
    });
    return values;
  });
  expect(unresolved).toEqual([]);
  const renderedTranslationKeys = await page.evaluate(() => {
    const locale = window.VeerApp.state.locale;
    const dictionary = window.VeerApp.translations[locale] || {};
    const text = document.body.innerText || '';
    return Object.keys(dictionary).filter((key) => text.includes(key));
  });
  expect(renderedTranslationKeys).toEqual([]);
  await expectNoPageOverflow(page);

  const trigger = page.locator('.plugin-detail-trigger[data-plugin-id="nf_counter"]');
  await trigger.scrollIntoViewIfNeeded();
  await trigger.click();
  const popover = page.locator('#pluginRuntimeTooltip');
  await expect(popover).toBeVisible();
  const overlap = await page.evaluate(() => {
    const triggerBox = document.querySelector('.plugin-detail-trigger[data-plugin-id="nf_counter"]').getBoundingClientRect();
    const popoverBox = document.getElementById('pluginRuntimeTooltip').getBoundingClientRect();
    return {
      overlaps: triggerBox.left < popoverBox.right && triggerBox.right > popoverBox.left && triggerBox.top < popoverBox.bottom && triggerBox.bottom > popoverBox.top,
      popover: { left: popoverBox.left, top: popoverBox.top, right: popoverBox.right, bottom: popoverBox.bottom },
      viewport: { width: window.innerWidth, height: window.innerHeight }
    };
  });
  expect(overlap.overlaps).toBe(false);
  expect(overlap.popover.left).toBeGreaterThanOrEqual(0);
  expect(overlap.popover.top).toBeGreaterThanOrEqual(0);
  expect(overlap.popover.right).toBeLessThanOrEqual(overlap.viewport.width);
  expect(overlap.popover.bottom).toBeLessThanOrEqual(overlap.viewport.height);

  const paused = await page.evaluate(() => window.VeerApp.runAutoRefresh() === null);
  expect(paused).toBe(true);
  await expect(popover).toBeVisible();

  await popover.locator('.plugin-detail-close').last().click();
  const resumed = await page.evaluate(async () => {
    const refresh = window.VeerApp.runAutoRefresh();
    if (!refresh) return false;
    await refresh;
    return true;
  });
  expect(resumed).toBe(true);
});

test('background load failures stay visible and recover outside the active tab', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.route('**/api/rules', async (route) => {
    await route.fulfill({
      status: 503,
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify({ error: 'fixture sync failure' })
    });
  });

  await page.evaluate(() => window.VeerApp.loadRules());
  const syncLabel = page.locator('#lastSyncLabel');
  await expect(syncLabel).toHaveClass(/is-error/);
  await expect(syncLabel).toHaveAttribute('title', /\/api\/rules: fixture sync failure/);
  await expect(page.locator('#toastStack')).toContainText('fixture sync failure');

  await page.locator('[data-tab="sites"]').click();
  await page.unroute('**/api/rules');
  await page.evaluate(async () => {
    const app = window.VeerApp;
    Object.values(app.state.requestFailures).forEach((failure) => {
      failure.at = Date.now() - 5000;
    });
    await app.runAutoRefresh();
  });
  await expect(syncLabel).not.toHaveClass(/is-error/);
  await expect(syncLabel).toHaveAttribute('title', '');

  browserErrors.set(page, []);
});

test('in-flight polling waits for an opened floating layer before applying data', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.locator('[data-tab="plugins"]').click();
  await page.evaluate(() => window.VeerApp.stopPolling());
  await expect.poll(() => page.evaluate(() => window.VeerApp.state.pollRefreshInFlight === null)).toBe(true);

  let releaseResponse;
  let markRequestStarted;
  const requestStarted = new Promise((resolve) => { markRequestStarted = resolve; });
  await page.route('**/api/plugins', async (route) => {
    markRequestStarted();
    await new Promise((resolve) => { releaseResponse = resolve; });
    await route.fulfill({
      status: 200,
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify(pluginCatalog)
    });
  });

  await page.evaluate(() => {
    window.__inflightPoll = window.VeerApp.runAutoRefresh();
  });
  await requestStarted;

  const trigger = page.locator('.plugin-detail-trigger[data-plugin-id="nf_counter"]');
  await trigger.click();
  const popover = page.locator('#pluginRuntimeTooltip');
  await expect(popover).toBeVisible();

  releaseResponse();
  await page.waitForTimeout(250);
  await expect.poll(() => page.evaluate(() => window.VeerApp.state.pollRefreshInFlight !== null)).toBe(true);
  await page.evaluate(() => window.dispatchEvent(new Event('resize')));
  await expect(popover).toBeVisible();
  await expect(trigger).toHaveAttribute('aria-expanded', 'true');

  await popover.locator('.plugin-detail-close').last().click();
  await expect(popover).toBeHidden();
  await expect.poll(() => page.evaluate(() => window.VeerApp.state.pollRefreshInFlight === null)).toBe(true);
  await page.unroute('**/api/plugins');
});

test('plugin page renders Netfilter placement and resizes in both directions', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.locator('[data-tab="plugin-firewall"]').click();

  const panel = page.locator('#tab-plugin-firewall');
  await expect(panel).toBeVisible();
  await expect(panel.locator('.plugin-link-card')).toBeVisible();
  await expect(panel.locator('.plugin-link-row')).toContainText('host / ipv4 / forward / filter');
  await expect(panel.locator('.plugin-link-step')).toHaveCount(2);
  await expect(panel.locator('.plugin-link-path')).toContainText('nf_dropper');
  await expect(panel.locator('.plugin-link-path')).toContainText('nf_counter');
  await expectNoPageOverflow(page);

  const frame = panel.locator('.plugin-page-frame');
  const frameBody = page.frameLocator('#tab-plugin-firewall .plugin-page-frame');
  await expect(frameBody.locator('#shrink')).toBeVisible();
  await expect.poll(async () => (await frame.boundingBox()).height).toBeGreaterThan(450);
  const expandedHeight = (await frame.boundingBox()).height;

  await frameBody.locator('#shrink').click();
  await expect.poll(async () => (await frame.boundingBox()).height).toBeLessThan(300);
  const compactHeight = (await frame.boundingBox()).height;
  expect(compactHeight).toBeLessThan(expandedHeight);

  await frameBody.locator('#grow').click();
  await expect.poll(async () => (await frame.boundingBox()).height).toBeGreaterThan(450);
});

test('plugin page confirmation uses the parent overlay and returns the result', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.locator('[data-tab="plugin-firewall"]').click();

  const frame = page.frameLocator('#tab-plugin-firewall .plugin-page-frame');
  await frame.locator('#confirm').click();
  const confirm = page.locator('#confirmModal');
  await expect(confirm).toBeVisible();
  await expect(page.locator('#confirmTitle')).toHaveText('Plugin confirmation');
  await expect(page.locator('#confirmMessage')).toHaveText('Confirm from sandbox');
  await expect(page.locator('#confirmSubmitBtn')).toHaveClass(/is-danger/);

  await page.locator('#confirmCancelBtn').click();
  await expect(confirm).toBeHidden();
  await expect.poll(() => frame.locator('body').evaluate(() => window.fixtureConfirmResult)).toBe(false);
});

test('confirmation dialog stays above plugin management', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.evaluate(() => {
    const manager = document.getElementById('pluginManagerModal');
    manager.classList.add('active');
    manager.setAttribute('aria-hidden', 'false');
    window.VeerApp.confirmAction({ title: 'Confirm fixture', message: 'Layer check', confirmText: 'Confirm', cancelText: 'Cancel' });
  });

  const manager = page.locator('#pluginManagerModal');
  const confirm = page.locator('#confirmModal');
  await expect(manager).toBeVisible();
  await expect(confirm).toBeVisible();
  const layers = await page.evaluate(() => ({
    manager: Number.parseInt(getComputedStyle(document.getElementById('pluginManagerModal')).zIndex, 10),
    confirm: Number.parseInt(getComputedStyle(document.getElementById('confirmModal')).zIndex, 10)
  }));
  expect(layers.confirm).toBeGreaterThan(layers.manager);
  await page.locator('#confirmCancelBtn').click();
  await expect(confirm).toBeHidden();
});
