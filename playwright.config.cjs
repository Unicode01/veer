const { defineConfig } = require('@playwright/test');

const webPort = Number.parseInt(process.env.VEER_WEB_E2E_PORT || '41739', 10);
const webURL = `http://127.0.0.1:${webPort}`;

module.exports = defineConfig({
  testDir: './internal/app/web_e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: 'line',
  outputDir: 'test-results/playwright',
  use: {
    baseURL: webURL,
    browserName: 'chromium',
    channel: process.env.VEER_PLAYWRIGHT_CHANNEL || undefined,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure'
  },
  projects: [
    {
      name: 'desktop-chromium',
      use: {
        locale: 'zh-CN',
        viewport: { width: 1440, height: 1000 }
      }
    },
    {
      name: 'mobile-chromium',
      use: {
        locale: 'en-US',
        viewport: { width: 390, height: 844 },
        isMobile: true,
        hasTouch: true
      }
    }
  ],
  webServer: {
    command: 'node internal/app/web_e2e/server.cjs',
    url: webURL,
    reuseExistingServer: !process.env.CI,
    timeout: 15000
  }
});
