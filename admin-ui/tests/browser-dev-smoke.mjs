import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHmac, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chromium } from 'playwright';
import { authPayload, decryptItem, deriveDataKey, unwrapUrk } from '../src/crypto.js';
import { t } from '../src/i18n.js';

const origin = process.env.RESPIRE_DEV_SERVER_ADDR;
const adminToken = process.env.RESPIRE_DEV_ADMIN_TOKEN;
const expectedSha = process.env.RESPIRE_DEV_SERVER_SHA;
const consoleSha = process.env.RESPIRE_DEV_CONSOLE_SHA;
const siteSha = process.env.RESPIRE_DEV_SITE_SHA;
const mailAddress = process.env.RESPIRE_DEV_MAIL_ADDRESS;
const mailReader = JSON.parse(process.env.RESPIRE_DEV_MAIL_READER || '[]');
if (!mailAddress || !Array.isArray(mailReader) || !mailReader.length || !mailReader.every(value => typeof value === 'string' && value.length)) {
  throw new Error('A development recipient and JSON command array for the mailbox reader are required.');
}
const readMail = promisify(execFile);
if (origin !== 'https://dev.rsrs.rs' || !adminToken || process.env.RESPIRE_DEV_API_ADMIN_APPROVED !== 'true' || ![expectedSha, consoleSha, siteSha].every(value => /^[0-9a-f]{40}$/.test(value || ''))) {
  throw new Error('Approved isolated development URL, admin token and exact API/console/site SHAs are required.');
}
const output = resolve(process.env.RESPIRE_WEB_SMOKE_OUTPUT || 'browser-smoke-output');
await mkdir(output, { recursive: true, mode: 0o700 });
const run = `${Date.now()}-${randomBytes(3).toString('hex')}`;
const user = `web-smoke-${run}`;
const email = mailAddress;
const password = randomBytes(20).toString('hex');
const nextPassword = randomBytes(20).toString('hex');
const owner = `web-owner-${run}`;
const viewer = `web-viewer-${run}`;
const ownerPassword = randomBytes(20).toString('hex');
const viewerPassword = randomBytes(20).toString('hex');
const rows = [];
const created = new Set();
let current = 'launch';
const browser = await chromium.launch({ headless: true, ...(process.env.RESPIRE_BROWSER_EXECUTABLE ? { executablePath: process.env.RESPIRE_BROWSER_EXECUTABLE } : {}) });
const context = await browser.newContext({ baseURL: origin, viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
const page = await context.newPage();
page.setDefaultTimeout(30000);
let userToken;
let ownerToken;
let viewerToken;
let recovery;
let totpSecret;
let fatal = false;

async function step(name, body) {
  current = name;
  await body();
  rows.push({ name, status: 'pass' });
  console.log(`PASS ${name}`);
}
async function call(path, { method = 'GET', token, body, expected = 200 } = {}) {
  const response = await context.request.fetch(`${origin}${path}`, { method, ...(body === undefined ? {} : { data: body }), headers: token ? { Authorization: `Bearer ${token}` } : {} });
  assert.equal(response.status(), expected, 'Development API returned an unexpected status');
  return response.json();
}
async function receivedCode(purpose, requestedAt) {
  const waitSeconds = Number(process.env.RESPIRE_DEV_MAIL_WAIT_SECONDS || 120);
  assert.ok(Number.isFinite(waitSeconds) && waitSeconds >= 30 && waitSeconds <= 600);
  console.log('WAITING_FOR_MAIL ' + purpose);
  const deadline = performance.now() + waitSeconds * 1000;
  while (performance.now() < deadline) {
    let stdout;
    const remaining = Math.max(1, Math.floor(deadline - performance.now()));
    try {
      ({ stdout } = await readMail(mailReader[0], [...mailReader.slice(1), JSON.stringify({ recipient: email, requestedAt, purpose })], { timeout: Math.min(15000, remaining), maxBuffer: 4096 }));
    } catch {
      if (performance.now() >= deadline) break;
      throw new Error('Development mailbox reader failed; credentials and message contents are not logged.');
    }
    let received;
    try { received = JSON.parse(stdout); } catch { throw new Error('Development mailbox reader returned invalid JSON.'); }
    if (typeof received.code === 'string' && /^\d{6}$/.test(received.code)) return received.code;
    const pause = Math.min(2000, deadline - performance.now());
    if (pause > 0) await new Promise(resolve => setTimeout(resolve, pause));
  }
  throw new Error('Verification email was not received before the deadline');
}

async function screenshot(name) {
  await page.screenshot({ path: resolve(output, `${name}.png`), fullPage: true, mask: [page.locator('input'), page.locator('textarea'), page.locator('code'), page.locator('pre'), page.locator('.demo-key'), page.locator('.setup-key'), page.locator('.verification-code'), page.locator('.secret-result')] });
}
async function navigate(id) {
  await page.locator(`.console-sidebar nav a[href="#/${id}"]`).click();
  await page.locator(`.console-main.surface-${id}`).waitFor();
}
async function responseFor(path, action) {
  const reply = page.waitForResponse(r => new URL(r.url()).pathname === path && r.request().method() === 'POST');
  await action();
  assert.equal((await reply).status(), 200, 'Browser operation did not succeed');
}
function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of secret.toUpperCase().replace(/=+$/, '')) {
    const value = alphabet.indexOf(char);
    assert.ok(value >= 0, 'Fixture TOTP secret format invalid');
    bits += value.toString(2).padStart(5, '0');
  }
  const bytes = Buffer.from(bits.match(/.{8}/g).map(b => Number.parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const hash = createHmac('sha1', bytes).update(counter).digest();
  const offset = hash.at(-1) & 15;
  return String((hash.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}

try {
  await step('exact-dev-source-and-readiness', async () => {
    const response = await context.request.get(`${origin}/ready`);
    assert.equal(response.status(), 200);
    assert.equal(response.headers()['x-respire-server-sha'], expectedSha);
    assert.equal((await response.json()).database, 'ready');
  });
  await step('exact-frontend-revisions-and-linked-site-assets', async () => {
    for (const path of ['/dashboard', '/admin']) {
      const response = await context.request.get(`${origin}${path}`);
      assert.equal(response.status(), 200);
      assert.equal(response.headers()['x-respire-console-sha'], consoleSha);
      assert.match(response.headers()['content-type'] || '', /text\/html/);
    }
    const response = await context.request.get(origin);
    assert.equal(response.status(), 200);
    assert.equal(response.headers()['x-respire-site-sha'], siteSha);
    const html = await response.text();
    const assets = [...html.matchAll(/(?:src|href)=["']([^"']+\.(?:js|css|svg|png|webp)(?:\?[^"']*)?)["']/g)].map(match => new URL(match[1], response.url()));
    assert.ok(assets.length > 0, 'Real homepage has no linked build assets');
    for (const url of assets) {
      assert.equal(url.origin, origin, 'Preview asset points outside the isolated dev origin');
      const asset = await context.request.get(url.href);
      assert.equal(asset.status(), 200, 'Linked preview build asset did not load');
    }
  });
  await step('user-login-failure-and-register-form', async () => {
    await page.goto('/dashboard');
    await page.getByLabel(t('username'), { exact: true }).fill(user);
    await page.getByLabel(t('loginPassword'), { exact: true }).fill(password);
    await page.locator('.gate-form form').getByRole('button', { name: t('login'), exact: true }).click();
    await page.getByRole('alert').waitFor();
    await screenshot('user-login');
    await page.locator('.gate-form .tabs').getByRole('button', { name: t('register'), exact: true }).click();
    await page.getByLabel(t('confirmLoginPassword'), { exact: true }).fill('different-fixture-password');
    await page.getByRole('button', { name: t('continue'), exact: true }).click();
    assert.equal(await page.getByRole('alert').textContent(), t('passMismatch'));
    await page.getByLabel(t('confirmLoginPassword'), { exact: true }).fill(password);
    await page.getByRole('button', { name: t('continue'), exact: true }).click();
    await page.getByRole('button', { name: t('generateSuper'), exact: true }).click();
    await page.locator('.demo-key code').waitFor();
    recovery = await page.locator('.demo-key code').textContent();
    created.add(user);
    await page.getByRole('checkbox').check();
    await page.getByRole('button', { name: t('enterMemory'), exact: true }).click();
    await page.locator('.console-main').waitFor();
    userToken = await page.evaluate(() => localStorage.getItem('onememory.userToken'));
    assert.ok(userToken);
  });
  const title = `Synthetic browser memory ${run}`;
  const content = 'Synthetic browser-only content. No personal data.';
  await step('encrypted-memory-create-read-edit', async () => {
    await page.getByRole('button', { name: t('saveMemory'), exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel(t('fieldTitle'), { exact: true }).fill(title);
    await dialog.getByLabel(t('fieldContent'), { exact: true }).fill(content);
    await responseFor('/push', () => dialog.getByRole('button', { name: t('encryptUpload'), exact: true }).click());
    await dialog.waitFor({ state: 'hidden' });
    await page.getByLabel(t('searchMemory'), { exact: true }).fill(title);
    await page.locator('.search-hit').filter({ hasText: title }).click();
    await page.locator('.reading-main').getByText(content, { exact: true }).waitFor();
    await screenshot('memory-read');
    await page.getByRole('button', { name: t('edit'), exact: true }).click();
    await page.getByRole('dialog').getByLabel(t('fieldContent'), { exact: true }).fill(`${content} Edited in the real browser.`);
    await responseFor('/push', () => page.getByRole('dialog').locator('button[type="submit"]').click());
    await page.getByRole('dialog').waitFor({ state: 'hidden' });
    const vault = await call('/api/self/vault', { token: userToken });
    const key = await deriveDataKey(await unwrapUrk(recovery, '', vault));
    const pull = await call('/pull', { token: userToken });
    let found = false;
    for (const blob of pull.blobs || []) {
      if (blob.deleted) continue;
      const memory = JSON.parse(await decryptItem(key, blob.ciphertext, blob.nonce));
      if (memory.title === title) {
        assert.equal(memory.content, `${content} Edited in the real browser.`);
        assert.ok(!blob.ciphertext.includes(content));
        found = true;
      }
    }
    assert.ok(found, 'Edited fixture did not round-trip through encrypted storage');
  });
  await step('all-user-view-layouts-and-mobile-navigation', async () => {
    for (const id of ['memories', 'diary', 'sessions', 'keys', 'security']) {
      await navigate(id);
      await page.locator('.page-heading h1').waitFor();
      await screenshot(`user-${id}`);
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.getByRole('button', { name: t('openNav'), exact: true }).click();
    await navigate('sessions');
    assert.equal(await page.locator('.console-sidebar.open').count(), 0);
    await screenshot('user-mobile');
    await page.setViewportSize({ width: 1440, height: 1000 });
  });
  await step('profile-email-verification-and-mail-fixture', async () => {
    await navigate('security');
    await page.locator('.security-tabs').getByRole('button', { name: t('bindEmail'), exact: true }).click();
    await page.getByLabel(t('emailAddress'), { exact: true }).fill(email);
    const requestedAt = new Date().toISOString();
    await responseFor('/api/self/email', () => page.getByRole('button', { name: t('sendCode'), exact: true }).click());
    const mail = await call('/admin/outbox', { token: adminToken });
    const fixture = mail.items?.find(m => m.to === email);
    assert.ok(fixture, 'Development verification mail row absent');
    assert.equal(fixture.body, undefined, 'Administrator API must not expose verification codes');
    const code = await receivedCode('verify_email', requestedAt);
    await page.getByLabel(t('emailCode'), { exact: true }).fill(code);
    await responseFor('/api/self/email/confirm', () => page.getByRole('button', { name: t('verifyAndBind'), exact: true }).click());
    assert.equal((await call('/api/self/keys', { token: userToken })).email, email);
    await page.getByText(t('currentEmail', { email }), { exact: true }).waitFor();
    await page.locator('.security-tabs').getByRole('button', { name: t('overview'), exact: true }).click();
    await page.getByText(t('verified'), { exact: true }).waitFor();
  });
  await step('user-totp-confirm-login-challenge-and-disable', async () => {
    await page.locator('.security-tabs').getByRole('button', { name: t('twoFactor'), exact: true }).click();
    await page.getByRole('button', { name: t('startBind'), exact: true }).click();
    await page.locator('.setup-key code').waitFor();
    totpSecret = await page.locator('.setup-key code').textContent();
    await page.getByLabel(t('verify'), { exact: true }).fill(totp(totpSecret));
    await responseFor('/api/self/totp/confirm', () => page.getByRole('button', { name: t('confirmOn'), exact: true }).click());
    await page.locator('.security-overview h2').getByText(t('totpOnH2'), { exact: true }).waitFor();
    const auth = await authPayload(user, password);
    const challenge = await call('/login', { method: 'POST', body: { user, pass_hash: auth.pass_hash, device_name: 'browser-smoke-challenge' } });
    assert.equal(challenge.totp_required, true);
    await call('/login/totp', { method: 'POST', body: { ticket: challenge.ticket, code: 'invalid-code' }, expected: 401 });
    const nextChallenge = await call('/login', { method: 'POST', body: { user, pass_hash: auth.pass_hash, device_name: 'browser-smoke-challenge' } });
    const session = await call('/login/totp', { method: 'POST', body: { ticket: nextChallenge.ticket, code: totp(totpSecret), device_name: 'browser-smoke-secondary' } });
    assert.ok(session.token);
    await page.getByLabel(t('verify'), { exact: true }).fill(totp(totpSecret));
    await responseFor('/api/self/totp/disable', () => page.locator('.key-actions').getByRole('button', { name: t('close'), exact: true }).click());
    assert.equal((await call('/api/self/keys', { token: userToken })).totp, false);
    await page.locator('.security-overview h2').getByText(t('totpOffH2'), { exact: true }).waitFor();
  });
  await step('user-password-change-and-session-relogin', async () => {
    await page.locator('.security-tabs').getByRole('button', { name: t('loginPassH3'), exact: true }).click();
    await page.getByLabel(t('newLoginPassword'), { exact: true }).fill(nextPassword);
    await page.getByLabel(t('confirmNewPass'), { exact: true }).fill(nextPassword);
    await responseFor('/api/self/password', () => page.getByRole('button', { name: t('updatePass'), exact: true }).click());
    await page.locator('.sidebar-bottom').getByRole('button', { name: t('signOut'), exact: true }).click();
    await page.getByLabel(t('username'), { exact: true }).fill(user);
    await page.getByLabel(t('loginPassword'), { exact: true }).fill(nextPassword);
    await page.getByLabel(t('superOptional'), { exact: true }).fill(recovery);
    await page.locator('.gate-form form').getByRole('button', { name: t('login'), exact: true }).click();
    await page.locator('.console-main').waitFor();
    userToken = await page.evaluate(() => localStorage.getItem('onememory.userToken'));
    assert.ok(userToken);
  });
  await step('user-email-password-recovery', async () => {
    const previousToken = userToken;
    const vault = await call('/api/self/vault', { token: previousToken });
    const recoveredPassword = randomBytes(20).toString('hex');
    await page.locator('.sidebar-bottom').getByRole('button', { name: t('signOut'), exact: true }).click();
    await page.getByRole('button', { name: t('forgotPassword'), exact: true }).click();
    await page.getByLabel(t('username'), { exact: true }).fill(user);
    const requestedAt = new Date().toISOString();
    await responseFor('/forgot', () => page.getByRole('button', { name: t('sendCode'), exact: true }).click());
    const code = await receivedCode('reset_password', requestedAt);
    await page.getByLabel(t('emailCode'), { exact: true }).fill(code);
    await page.getByLabel(t('newLoginPassword'), { exact: true }).fill(recoveredPassword);
    await page.getByLabel(t('confirmLoginPassword'), { exact: true }).fill(recoveredPassword);
    await responseFor('/reset', () => page.getByRole('button', { name: t('resetPassword'), exact: true }).click());
    await call('/api/self', { token: previousToken, expected: 401 });
    const previous = await authPayload(user, nextPassword);
    await call('/login', { method: 'POST', body: previous, expected: 401 });
    const recovered = await authPayload(user, recoveredPassword);
    await call('/reset', { method: 'POST', body: { ...recovered, code }, expected: 401 });
    await page.getByLabel(t('username'), { exact: true }).fill(user);
    await page.getByLabel(t('loginPassword'), { exact: true }).fill(recoveredPassword);
    await page.getByLabel(t('superOptional'), { exact: true }).fill(recovery);
    await page.locator('.gate-form form').getByRole('button', { name: t('login'), exact: true }).click();
    await page.locator('.console-main').waitFor();
    userToken = await page.evaluate(() => localStorage.getItem('onememory.userToken'));
    assert.deepEqual(await call('/api/self/vault', { token: userToken }), vault);
    assert.equal((await call('/api/self/keys', { token: userToken })).email_verified, true);
    await page.getByText(t('verified'), { exact: true }).waitFor();
    await screenshot('user-password-recovered');
  });
  await step('admin-fixture-owner-and-viewer-permissions', async () => {
    for (const [name, pass, role] of [[owner, ownerPassword, 'owner'], [viewer, viewerPassword, 'viewer']]) {
      const auth = await authPayload(name, pass);
      await call('/admin/admins', { method: 'POST', token: adminToken, body: { ...auth, role, email: `${name}@example.invalid` } });
      created.add(name);
    }
    const auth = await authPayload(viewer, viewerPassword);
    const identity = await call('/admin/login', { method: 'POST', body: { user: viewer, pass_hash: auth.pass_hash } });
    viewerToken = identity.token;
    await call('/admin/users', { token: identity.token });
    await call('/admin/admins', { token: identity.token, expected: 403 });
    await call('/admin/outbox', { token: identity.token, expected: 403 });
    await call('/admin/admins', { method: 'POST', token: identity.token, body: {}, expected: 403 });
  });
  await step('admin-password-login-and-all-real-views', async () => {
    await page.goto('/admin');
    await page.getByLabel(t('username'), { exact: true }).fill(owner);
    await page.getByLabel(t('loginPassword'), { exact: true }).fill(ownerPassword);
    await page.locator('.gate-form form').getByRole('button', { name: t('login'), exact: true }).click();
    await page.locator('.console-main').waitFor();
    ownerToken = await page.evaluate(() => localStorage.getItem('onememory.adminToken'));
    assert.ok(ownerToken);
    for (const id of ['users', 'admins', 'audit', 'mail', 'security']) {
      await navigate(id);
      await page.locator('.page-heading h1').waitFor();
      await screenshot(`admin-${id}`);
    }
    await navigate('users');
    await page.getByLabel(t('searchUser'), { exact: true }).fill(user);
    await page.getByLabel(t('searchUser'), { exact: true }).press('Enter');
    await page.locator('.user-cell').filter({ hasText: user }).click();
    await page.getByRole('dialog', { name: t('userDetail') }).waitFor();
    await screenshot('admin-user-detail');
    await page.getByRole('button', { name: t('close'), exact: true }).click();
  });
  await step('admin-owner-totp-and-auth-boundaries', async () => {
    await navigate('security');
    await page.locator('.security-tabs').getByRole('button', { name: t('twoFactor'), exact: true }).click();
    await page.getByRole('button', { name: t('startBind'), exact: true }).click();
    await page.locator('.setup-key code').waitFor();
    const secret = await page.locator('.setup-key code').textContent();
    await page.getByLabel(t('verify'), { exact: true }).fill(totp(secret));
    await responseFor('/admin/totp/confirm', () => page.getByRole('button', { name: t('confirmOn'), exact: true }).click());
    const auth = await authPayload(owner, ownerPassword);
    const challenge = await call('/admin/login', { method: 'POST', body: { user: owner, pass_hash: auth.pass_hash } });
    assert.equal(challenge.totp_required, true);
    await call('/admin/login/totp', { method: 'POST', body: { ticket: challenge.ticket, code: 'invalid-code' }, expected: 401 });
    const nextChallenge = await call('/admin/login', { method: 'POST', body: { user: owner, pass_hash: auth.pass_hash } });
    const result = await call('/admin/login/totp', { method: 'POST', body: { ticket: nextChallenge.ticket, code: totp(secret) } });
    assert.ok(result.token);
    // Successful challenged login replaces the admin token; use it for fixture teardown.
    ownerToken = result.token;
    await call('/admin/totp/disable', { method: 'POST', token: ownerToken, body: { code: totp(secret) } });
    await call('/api/self', { expected: 401 });
    await call('/admin/me', { expected: 401 });
    await call('/admin/me', { token: userToken, expected: 403 });
    await call('/api/self', { token: adminToken, expected: 401 });
  });
} catch (error) {
  fatal = true;
  const sourceLines = [...String(error.stack || '').matchAll(/browser-dev-smoke\.mjs:(\d+):\d+/g)].slice(0, 3).map(match => Number(match[1]));
  const path = new URL(page.url()).pathname;
  let failureScreenshot = false;
  try {
    await screenshot('failure-masked');
    failureScreenshot = true;
  } catch {
    // Preserve the original failure without dumping credential-bearing browser state.
  }
  rows.push({ name: current, status: 'fail', error_type: error.name, source_lines: sourceLines, path, masked_failure_screenshot: failureScreenshot });
  console.error(`FAIL ${current} (${error.name}); detailed credential-bearing error text omitted.`);
} finally {
  // Cleanup only exact identities created by this run; never list/delete arbitrary dev accounts.
  for (const [name, path] of [[user, 'users'], [viewer, 'admins'], [owner, 'admins']]) {
    if (!created.has(name)) continue;
    try {
      const revoked = await call(`/admin/${path}/${encodeURIComponent(name)}/revoke`, { method: 'POST', token: adminToken, body: {} });
      if (path === 'users') {
        assert.equal(revoked.purged, true, 'Owned user fixture was not purged');
        if (userToken) await call('/api/self', { token: userToken, expected: 401 });
        const remaining = await call(`/admin/users?q=${encodeURIComponent(name)}`, { token: adminToken });
        assert.ok(Array.isArray(remaining.users), 'User-list proof lacks its required collection');
        assert.ok(!remaining.users.some(identity => identity.user === name), 'Purged owned user remains in the user list');
      } else {
        assert.equal(revoked.deleted, true, 'Owned admin fixture was not deleted');
        const priorToken = name === owner ? ownerToken : viewerToken;
        if (priorToken) await call('/admin/me', { token: priorToken, expected: 403 });
        const remaining = await call('/admin/admins', { token: adminToken });
        assert.ok(Array.isArray(remaining.admins), 'Admin-list proof lacks its required collection');
        assert.ok(!remaining.admins.some(identity => identity.user === name), 'Deleted owned admin remains in the admin list');
      }
      rows.push({ name: `cleanup-${path}-fixture`, status: 'pass' });
    } catch {
      fatal = true;
      rows.push({ name: `cleanup-${path}-fixture`, status: 'fail' });
    }
  }
  await context.close();
  await browser.close();
  await writeFile(resolve(output, 'result.json'), JSON.stringify({ server_sha: expectedSha, console_sha: consoleSha, site_sha: siteSha, target: origin, passed: !fatal, checks: rows, screenshot_secrets_masked: true, screenshots_are_synthetic_dev_only: true }, null, 2), { mode: 0o600 });
  if (fatal) process.exitCode = 1;
}
