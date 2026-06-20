#!/usr/bin/env node
// Reproducible Kibana screenshot harness for issue #147 evidence capture.
//
// Logs into Kibana (basic auth provider), opens a dashboard or arbitrary app
// path with the time-picker pinned to a fixed UTC window, lets panels settle,
// then writes a full-page PNG to evidence/screenshots/ and prints its SHA-256
// so the row in evidence/README.md is reproducible by any reviewer.
//
// Usage:
//   node capture_kibana.mjs --dashboard executive-dashboard \
//        --from 2026-06-20T16:00:00.000Z --to 2026-06-20T16:30:00.000Z \
//        --out ../screenshots/executive-dashboard.png
//
//   node capture_kibana.mjs --app-path "/app/discover#/?_a=(index:'logstash-security-home-smith')" \
//        --from now-1h --to now --out ../screenshots/portscan-notice.png
//
// Credentials/URL default to env, falling back to scripts/setup/.env:
//   KIBANA_URL   (default http://localhost:5601)
//   KIBANA_USER  (default elastic)
//   KIBANA_PASS  (default ELASTIC_PASSWORD from scripts/setup/.env)
//
// Exit non-zero on login failure or render timeout so it can gate CI/automation.

import { chromium } from 'playwright';
import { createHash } from 'node:crypto';
import { readFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const a = {};
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if (k.startsWith('--')) a[k.slice(2)] = argv[i + 1]?.startsWith('--') || argv[i + 1] === undefined ? true : argv[++i];
  }
  return a;
}

// Read a key from scripts/setup/.env without sourcing it (no secret echo).
function fromDotEnv(key) {
  try {
    const env = readFileSync(resolve(HERE, '../../scripts/setup/.env'), 'utf8');
    const m = env.match(new RegExp(`^${key}=(.*)$`, 'm'));
    return m ? m[1].trim() : undefined;
  } catch {
    return undefined;
  }
}

const args = parseArgs(process.argv);
const KIBANA_URL = (process.env.KIBANA_URL || 'http://localhost:5601').replace(/\/$/, '');
const USER = process.env.KIBANA_USER || 'elastic';
const PASS = process.env.KIBANA_PASS || fromDotEnv('ELASTIC_PASSWORD');
const FROM = args.from || 'now-24h';
const TO = args.to || 'now';
const WAIT = parseInt(args.wait || '7000', 10);
const OUT = args.out ? resolve(HERE, args.out) : resolve(HERE, '../screenshots/capture.png');

if (!PASS) {
  console.error('[ERROR] no Kibana password (set KIBANA_PASS or ELASTIC_PASSWORD in scripts/setup/.env)');
  process.exit(2);
}
if (!args.dashboard && !args['app-path']) {
  console.error('[ERROR] provide --dashboard <id> or --app-path <kibana app path>');
  process.exit(2);
}

// rison-quote ISO timestamps; relative (now / now-1h) pass through unquoted.
const risonTime = (t) => (/^now([-+].*)?$/.test(t) ? t : `'${t}'`);
const gParam = `_g=(time:(from:${risonTime(FROM)},to:${risonTime(TO)}))`;

let targetUrl;
if (args.dashboard) {
  targetUrl = `${KIBANA_URL}/app/dashboards#/view/${args.dashboard}?${gParam}`;
} else {
  const path = args['app-path'];
  const sep = path.includes('?') ? '&' : (path.includes('#') ? '?' : '#?');
  targetUrl = `${KIBANA_URL}${path}${sep}${gParam}`;
}

const browser = await chromium.launch({ args: ['--no-sandbox'] });
const ctx = await browser.newContext({ viewport: { width: 1680, height: 1050 }, ignoreHTTPSErrors: true });
const page = await ctx.newPage();

try {
  // 1) Go straight to the windowed target. Unauthenticated Kibana redirects to
  //    /login?next=<target>; after we log in it returns us to the target itself.
  await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 45000 });

  // 2) If the login form appears (rendered client-side, so wait for it rather
  //    than probing immediately), authenticate and confirm we leave /login.
  const userField = page.locator('[data-test-subj=loginUsername]');
  const onLogin = await userField.waitFor({ state: 'visible', timeout: 12000 }).then(() => true).catch(() => false);
  if (onLogin) {
    await userField.fill(USER);
    await page.locator('[data-test-subj=loginPassword]').fill(PASS);
    await page.locator('[data-test-subj=loginSubmit]').click();
    await page.waitForURL((u) => !u.toString().includes('/login'), { timeout: 30000 });
  }
  if (page.url().includes('/login')) throw new Error('still on /login after auth — check credentials');

  // 3) Wait for the app chrome + (for dashboards) the panel viewport to mount,
  //    then a fixed settle so panels finish querying ES and painting.
  await page.locator('[data-test-subj=headerGlobalNav]').waitFor({ state: 'visible', timeout: 30000 }).catch(() => {});
  if (args.dashboard) {
    await page.locator('[data-test-subj=dashboardViewport]').waitFor({ state: 'visible', timeout: 30000 }).catch(() => {});
  }
  await page.waitForLoadState('networkidle', { timeout: 30000 }).catch(() => {});
  await page.waitForTimeout(WAIT);

  mkdirSync(dirname(OUT), { recursive: true });
  await page.screenshot({ path: OUT, fullPage: true });

  const sha = createHash('sha256').update(readFileSync(OUT)).digest('hex');
  console.log(JSON.stringify({
    ok: true, out: OUT, sha256: sha,
    window_utc: { from: FROM, to: TO }, url: targetUrl,
  }, null, 2));
} catch (e) {
  console.error(`[ERROR] capture failed: ${e.message}`);
  await page.screenshot({ path: OUT.replace(/\.png$/, '.error.png'), fullPage: true }).catch(() => {});
  process.exitCode = 1;
} finally {
  await browser.close();
}
