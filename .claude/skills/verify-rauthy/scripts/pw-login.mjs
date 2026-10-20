// Browser login through the real Rauthy login page, then capture evidence.
// Usage (via rv):  rv browser pw-login.mjs <feature-id> [start-path] [email] [password] [expect]
//   start-path defaults to /auth/v1/account (redirects to the login page when logged out).
//   expect: "ok" (default) = must leave the login page; "denied" = must stay on it and show
//   "Invalid credentials". Exit code 0 only when the expectation holds.
// Writes <evidence>/<feature-id>/{01-login,02-after}.{png,aria.txt} and browser.log
// (console + /auth/v1 HTTP statuses).
import fs from 'node:fs';
import path from 'node:path';

const { chromium } = await import(process.env.RV_PLAYWRIGHT);

const [feature = 'login', startPath = '/auth/v1/account', email, password, expect = 'ok'] =
  process.argv.slice(2);
const base = process.env.RV_BASE_URL;
const out = path.join(process.env.RV_EVIDENCE, feature);
fs.mkdirSync(out, { recursive: true });
const user = email || process.env.RV_ADMIN_EMAIL;
const pass = password || process.env.RV_ADMIN_PASSWORD;

const browser = await chromium.launch();
const page = await browser.newPage({ locale: 'en-US' });
const log = [];
page.on('console', (m) => log.push(`[console.${m.type()}] ${m.text()}`));
page.on('response', (r) => { if (r.url().includes('/auth/v1/') && !r.url().includes('/_app/')) log.push(`[http ${r.status()}] ${r.request().method()} ${r.url()}`); });

async function proof(name) {
  await page.screenshot({ path: path.join(out, `${name}.png`), fullPage: true });
  fs.writeFileSync(path.join(out, `${name}.aria.txt`), await page.locator('body').ariaSnapshot());
}

let exit = 0;
try {
  await page.goto(base + startPath);
  const emailBox = page.getByRole('textbox', { name: 'E-Mail' });
  await emailBox.waitFor({ timeout: 20000 });
  await emailBox.fill(user);
  // the password field only appears after the email is known to the UI
  await page.locator('form').getByRole('button', { name: 'Login' }).click();
  const pwd = page.getByLabel('Password', { exact: true });
  await pwd.waitFor({ timeout: 10000 });
  await pwd.fill(pass);
  await proof('01-login');
  await page.locator('form').getByRole('button', { name: 'Login' }).click();
  if (expect === 'denied') {
    await page.getByText('Invalid credentials').waitFor({ timeout: 30000 });
    if (!new URL(page.url()).pathname.startsWith('/auth/v1/oidc/authorize')) throw new Error('left login page');
    await proof('02-after');
    console.log(`OK login for ${user} denied as expected; still at ${page.url()}`);
  } else {
    // success = we leave the authorize page (PoW is solved in WASM before the POST).
    // No 'networkidle': the admin UI keeps polling.
    await page.waitForURL((u) => !u.pathname.startsWith('/auth/v1/oidc/authorize'), { timeout: 30000 });
    await page.locator('main').first().waitFor({ timeout: 15000 });
    await page.waitForTimeout(1500);
    await proof('02-after');
    console.log(`OK logged in as ${user}; now at ${page.url()}`);
  }
} catch (e) {
  exit = 1;
  console.error(`FAIL ${e.message}`);
  await proof('99-failure').catch(() => {});
} finally {
  fs.writeFileSync(path.join(out, 'browser.log'), log.join('\n') + '\n');
  console.log(`evidence: ${out}`);
  await browser.close();
  process.exit(exit);
}
