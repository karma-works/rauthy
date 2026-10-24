// End-to-end test of the discoverable passkey login for passkeys whose registration did not
// report `credProps` (iOS Chrome, Android), against a running test backend, not part of CI.
//
// Needs `rauthy serve -c config-test.toml --test` on :8081 (`just test-backend`).
// Run with: node --test tests/passkey-rk.live.mjs
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { chromium } from '@playwright/test';
import { createHash } from 'node:crypto';

const BASE = 'http://localhost:8081';
const ADMIN = { email: 'init_admin@localhost', password: '123SuperSafe' };
const USER = {
    email: `rk-null-${Date.now()}@rtest.io`,
    password: 'RkNull-Test-1234-SuperSafe-PASS!#',
};

let browser;
before(async () => {
    browser = await chromium.launch({
        executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
    });
});
after(async () => browser?.close());

async function addAuthenticator(page) {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
            protocol: 'ctap2',
            transport: 'internal',
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
        },
    });
    return { cdp, authenticatorId };
}

function authorizeUrl() {
    // S256 of a fixed verifier, the token exchange does not matter here
    const challenge = createHash('sha256').update('v'.repeat(64)).digest('base64url');
    return (
        `${BASE}/auth/v1/oidc/authorize?client_id=rauthy&response_type=code` +
        `&redirect_uri=${encodeURIComponent(`${BASE}/auth/v1/oidc/callback`)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256`
    );
}

/** Logs in with a password through the login page of the `rauthy` client. */
async function login(page, { email, password }) {
    await page.goto(authorizeUrl());
    await page.locator('input[name=email]').fill(email);
    await page.getByRole('button', { name: 'Login', exact: true }).first().click();
    await page.locator('input[name=password]').fill(password);
    await page.getByRole('button', { name: 'Login', exact: true }).first().click();
    await page.waitForURL(/\/oidc\/callback/);
}

/** `fetch` inside the page with the session cookie and CSRF token. */
async function api(page, method, path, body) {
    return page.evaluate(
        async ({ method, path, body }) => {
            const info = await fetch('/auth/v1/oidc/sessioninfo/xsrf');
            const csrf = info.ok ? (await info.json()).csrf_token : '';
            const res = await fetch(`/auth/v1${path}`, {
                method,
                headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
                body: body === undefined ? undefined : JSON.stringify(body),
            });
            const text = await res.text();
            let json = null;
            try {
                json = JSON.parse(text);
            } catch {}
            return { status: res.status, json, text };
        },
        { method, path, body },
    );
}

/**
 * Registers a passkey with the backend's options. The `credProps` extension result is dropped,
 * like iOS Chrome and Android do, so the backend stores `resident_key = NULL`.
 */
async function registerWithoutCredProps(page, options) {
    return page.evaluate(async options => {
        const toBuf = s =>
            Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
        const toB64 = buf =>
            btoa(String.fromCharCode(...new Uint8Array(buf)))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, '');
        const pk = options.publicKey;
        pk.challenge = toBuf(pk.challenge);
        pk.user.id = toBuf(pk.user.id);
        for (const c of pk.excludeCredentials || []) c.id = toBuf(c.id);
        const cred = await navigator.credentials.create({ publicKey: pk });
        return {
            id: cred.id,
            rawId: toB64(cred.rawId),
            response: {
                attestationObject: toB64(cred.response.attestationObject),
                clientDataJSON: toB64(cred.response.clientDataJSON),
                transports: cred.response.getTransports(),
            },
            extensions: {},
            type: cred.type,
        };
    }, options);
}

/** A new browser with a copy of the passkey, without any session. */
async function deviceWithPasskey(t, credential) {
    const context = await browser.newContext({ serviceWorkers: 'block', locale: 'en-US' });
    t.after(() => context.close());
    const page = await context.newPage();
    const { cdp, authenticatorId } = await addAuthenticator(page);
    await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
    const finishes = [];
    page.on('response', r => {
        if (r.url().endsWith('/users/webauthn_finish')) finishes.push(r.status());
    });
    if (process.env.DEBUG_LIVE) {
        page.on('console', m => console.log('console:', m.text()));
        page.on('response', r => {
            if (r.request().method() !== 'GET') console.log('resp:', r.status(), r.url());
        });
    }
    await page.goto(authorizeUrl());
    // the button only works after hydration
    await page.waitForLoadState('networkidle');
    return { page, finishes };
}

async function passkeys(admin, uid) {
    const res = await api(admin, 'GET', `/users/${uid}/webauthn`);
    assert.equal(res.status, 200, res.text);
    return res.json;
}

/** Events are written in the background, so this waits a moment for a matching one. */
async function eventsOf(admin, typ, from, filter) {
    for (let i = 0; i < 40; i++) {
        const res = await api(admin, 'POST', '/events', { from, level: 'info', typ });
        assert.equal(res.status, 200, res.text);
        const found = res.json.filter(e => filter(e.text || ''));
        if (found.length > 0) return found;
        await new Promise(r => setTimeout(r, 250));
    }
    return [];
}

test('a passkey stored without resident_key logs in discoverably and is healed', async t => {
    const from = Math.floor(Date.now() / 1000) - 5;

    // --- an admin creates a password user
    const adminCtx = await browser.newContext({ serviceWorkers: 'block' });
    t.after(() => adminCtx.close());
    const admin = await adminCtx.newPage();
    await login(admin, ADMIN);
    const created = await api(admin, 'POST', '/users', {
        email: USER.email,
        given_name: 'Rk',
        family_name: 'Null',
        language: 'en',
        roles: [],
    });
    assert.equal(created.status, 200, created.text);
    const uid = created.json.id;
    const upd = await api(admin, 'PUT', `/users/${uid}`, {
        email: USER.email,
        given_name: 'Rk',
        family_name: 'Null',
        language: 'en',
        password: USER.password,
        roles: [],
        enabled: true,
        email_verified: true,
    });
    assert.equal(upd.status, 200, upd.text);

    // --- the user adds a passkey, the browser reports no `credProps`
    const userCtx = await browser.newContext({ serviceWorkers: 'block' });
    t.after(() => userCtx.close());
    const user = await userCtx.newPage();
    await login(user, USER);
    const { cdp, authenticatorId } = await addAuthenticator(user);
    const pwdToken = await api(user, 'POST', `/users/${uid}/mfa_token`, {
        password: USER.password,
    });
    assert.equal(pwdToken.status, 200, pwdToken.text);
    const regStart = await api(user, 'POST', `/users/${uid}/webauthn/register/start`, {
        passkey_name: 'Phone',
        mfa_mod_token_id: pwdToken.json.id,
        allow_rk: true,
    });
    assert.equal(regStart.status, 200, regStart.text);
    const cred = await registerWithoutCredProps(user, regStart.json);
    const regFinish = await api(user, 'POST', `/users/${uid}/webauthn/register/finish`, {
        passkey_name: 'Phone',
        data: cred,
    });
    assert.equal(regFinish.status, 201, regFinish.text);

    let pks = await passkeys(admin, uid);
    assert.equal(pks.length, 1);
    assert.equal(
        pks[0].resident_key ?? null,
        null,
        'stored without resident_key, as in the incident',
    );

    const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
    assert.equal(credentials.length, 1);
    assert.equal(credentials[0].isResidentCredential, true);

    // --- another device with this passkey uses the "Passkey" button of the login page
    {
        const { page, finishes } = await deviceWithPasskey(t, credentials[0]);
        const loggedIn = page.waitForResponse(
            r =>
                r.url().startsWith(`${BASE}/auth/v1/oidc/authorize`) &&
                r.request().method() === 'POST',
        );
        await page.getByRole('button', { name: 'Login' }).filter({ hasText: 'Passkey' }).click();
        assert.equal((await loggedIn).status(), 202, 'logged in with the resident key token');
        assert.deepEqual(finishes, [202]);
    }

    // self-healing
    pks = await passkeys(admin, uid);
    assert.equal(pks[0].resident_key, true);

    // events without the E-Mail
    const added = await eventsOf(admin, 'PasskeyAdded', from, text => text.includes(uid));
    assert.equal(added.length, 1);
    assert.ok(!added[0].text.includes(USER.email));
    assert.ok(!added[0].text.includes('Phone'), 'no passkey name');

    // --- the passkey is deleted, the browser still offers it
    const del = await api(admin, 'DELETE', `/users/${uid}/webauthn/delete/Phone`, {});
    assert.equal(del.status, 200, del.text);
    const removed = await eventsOf(admin, 'PasskeyRemoved', from, text => text.includes(uid));
    assert.equal(removed.length, 1);
    assert.match(removed[0].text, /by: admin/);
    assert.ok(!removed[0].text.includes(USER.email));

    {
        const { page, finishes } = await deviceWithPasskey(t, credentials[0]);
        await page.evaluate(() => (window.__notReloaded = true));
        await page.getByRole('button', { name: 'Login' }).filter({ hasText: 'Passkey' }).click();
        await page
            .getByText('This passkey is not (or no longer) registered with us.')
            .waitFor({ timeout: 20000 });
        assert.deepEqual(finishes, [404], 'one finish, answered with 404');
        assert.equal(await page.evaluate(() => window.__notReloaded), true, 'no reload');
    }

    const failed = await eventsOf(admin, 'PasskeyAuthFailed', from, text =>
        text.startsWith('unknown_credential - path: discoverable'),
    );
    assert.ok(failed.length >= 1);
});
