import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';

// This gate renders actual compiled sign-in surfaces with no credentials or API mocks.
const html = await readFile(new URL('../dist/index.html', import.meta.url));
const output = resolve(process.env.RESPIRE_RENDER_OUTPUT || 'render-output');
await mkdir(output, { recursive: true });
const server = createServer((request, response) => {
  if (request.method !== 'GET' || !['/dashboard', '/admin', '/favicon.ico'].includes(request.url)) {
    response.writeHead(404).end();
    return;
  }
  if (request.url === '/favicon.ico') { response.writeHead(204).end(); return; }
  response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(html);
});
await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(process.env.RESPIRE_BROWSER_EXECUTABLE ? { executablePath: process.env.RESPIRE_BROWSER_EXECUTABLE } : {}) });
const rows = [];
try {
  for (const [surface, width, height] of [['dashboard', 1440, 1000], ['admin', 1440, 1000], ['dashboard', 390, 844], ['admin', 390, 844]]) {
    const context = await browser.newContext({ viewport: { width, height } });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', () => errors.push('runtime-error'));
    await page.goto(`${origin}/${surface}`);
    await page.locator('.gate-form h2').waitFor();
    assert.equal(await page.locator('.respire-logo svg path').count(), 2);
    const layout = await page.evaluate(() => ({ width: document.documentElement.scrollWidth, viewport: innerWidth, background: getComputedStyle(document.body).backgroundColor, headline: getComputedStyle(document.querySelector('.gate-story h1')).fontFamily }));
    assert.equal(layout.background, 'rgb(248, 246, 242)');
    assert.match(layout.headline, /Georgia/);
    assert.ok(layout.width <= layout.viewport + 1, 'Sign-in surface overflows its viewport');
    assert.deepEqual(errors, []);
    const name = `${surface}-${width}`;
    // The isolated context has no user input or credential material.
    await page.screenshot({ path: resolve(output, `${name}.png`), fullPage: true });
    rows.push({ surface, viewport: { width, height }, passed: true });
    await context.close();
  }
  await writeFile(resolve(output, 'render-result.json'), JSON.stringify({ compiled_html: true, credentials_used: false, api_calls_mocked: false, surfaces: rows }, null, 2));
  console.log('Compiled console render passed: user/admin desktop/mobile, no credentials.');
} finally {
  await browser.close();
  await new Promise(resolveClose => server.close(resolveClose));
}
