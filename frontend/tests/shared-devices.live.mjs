// End-to-end test of shared devices with a PIN login against a running test backend, not part
// of CI.
//
// Needs `rauthy serve -c config-test.toml --test` on :8081 with
// `SHARED_DEVICES_ENABLE=true SHARED_DEVICES_CLIENT_IDS=pin-test`, and mails going to a Mailpit at
// `MAILPIT_URL` (default http://127.0.0.1:18026), e.g.
// `SMTP_URL=127.0.0.1 SMTP_PORT=2525 SMTP_TLS_MODE=danger-insecure`.
// Run with: node --test tests/shared-devices.live.mjs
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { chromium } from '@playwright/test';
import { createHash } from 'node:crypto';

const BASE = 'http://localhost:8081';
const MAILPIT = process.env.MAILPIT_URL || 'http://127.0.0.1:18026';
const ADMIN = { email: 'init_admin@localhost', password: '123SuperSafe' };
const CLIENT_ID = 'pin-test';
const CALLBACK = `${BASE}/auth/v1/oidc/callback`;
const PRACTICE = `praxis-${Date.now()}`;
const PWD = '123SuperSafe123!Aa#$%&/';
const VERIFIER = 'v'.repeat(64);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');

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
            transport: 'usb',
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
        },
    });
    return { cdp, authenticatorId };
}

function authorizeUrl(clientId, extra = '') {
    return (
        `${BASE}/auth/v1/oidc/authorize?client_id=${clientId}&response_type=code` +
        `&redirect_uri=${encodeURIComponent(CALLBACK)}&scope=openid` +
        `&code_challenge=${CHALLENGE}&code_challenge_method=S256${extra}`
    );
}

/** Logs in with a password through the login page of the `rauthy` client. */
async function login(page, { email, password }) {
    await page.goto(authorizeUrl('rauthy'));
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

async function passkeyCeremony(page, kind, options) {
    return page.evaluate(
        async ({ kind, options }) => {
            const toBuf = s =>
                Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c =>
                    c.charCodeAt(0),
                );
            const toB64 = buf =>
                btoa(String.fromCharCode(...new Uint8Array(buf)))
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '');
            const pk = options.publicKey;
            pk.challenge = toBuf(pk.challenge);
            if (kind === 'create') {
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
                    extensions: cred.getClientExtensionResults(),
                    type: cred.type,
                };
            }
            for (const c of pk.allowCredentials || []) c.id = toBuf(c.id);
            const cred = await navigator.credentials.get({ publicKey: pk });
            return {
                id: cred.id,
                rawId: toB64(cred.rawId),
                response: {
                    authenticatorData: toB64(cred.response.authenticatorData),
                    clientDataJSON: toB64(cred.response.clientDataJSON),
                    signature: toB64(cred.response.signature),
                    userHandle: cred.response.userHandle
                        ? toB64(cred.response.userHandle)
                        : undefined,
                },
                extensions: cred.getClientExtensionResults(),
                type: cred.type,
            };
        },
        { kind, options },
    );
}

async function mfaTokenViaPasskey(page, userId) {
    const start = await api(page, 'POST', '/users/webauthn_start', { purpose: 'MfaModToken' });
    assert.equal(start.status, 200, start.text);
    const data = await passkeyCeremony(page, 'get', start.json.rcr);
    const finish = await api(page, 'POST', '/users/webauthn_finish', {
        code: start.json.code,
        data,
    });
    assert.equal(finish.status, 202, finish.text);
    const token = await api(page, 'POST', `/users/${userId}/mfa_token`, {
        mfa_code: finish.json.code,
    });
    assert.equal(token.status, 200, token.text);
    return token.json.id;
}

async function addPasskey(page, uid) {
    const pwdToken = await api(page, 'POST', `/users/${uid}/mfa_token`, { password: PWD });
    assert.equal(pwdToken.status, 200, pwdToken.text);
    const regStart = await api(page, 'POST', `/users/${uid}/webauthn/register/start`, {
        passkey_name: 'Key',
        mfa_mod_token_id: pwdToken.json.id,
        allow_rk: true,
    });
    assert.equal(regStart.status, 200, regStart.text);
    const cred = await passkeyCeremony(page, 'create', regStart.json);
    const regFinish = await api(page, 'POST', `/users/${uid}/webauthn/register/finish`, {
        passkey_name: 'Key',
        data: cred,
    });
    assert.equal(regFinish.status, 201, regFinish.text);
}

async function createUser(admin, email) {
    const created = await api(admin, 'POST', '/users', {
        email,
        given_name: 'Pin',
        family_name: 'Test',
        language: 'en',
        roles: [],
    });
    assert.equal(created.status, 200, created.text);
    const uid = created.json.id;
    const upd = await api(admin, 'PUT', `/users/${uid}`, {
        email,
        given_name: 'Pin',
        family_name: 'Test',
        language: 'en',
        password: PWD,
        roles: [],
        enabled: true,
        email_verified: true,
    });
    assert.equal(upd.status, 200, upd.text);
    return uid;
}

async function mails(to) {
    const res = await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`);
    return (await res.json()).messages || [];
}

async function waitForMail(to, subject) {
    for (let i = 0; i < 40; i++) {
        const found = (await mails(to)).find(m => m.Subject === subject);
        if (found) return found;
        await new Promise(r => setTimeout(r, 250));
    }
    throw new Error(`no mail "${subject}" for ${to}`);
}

/** Screenshots for a visual review, only with `SCREENSHOT_DIR` */
async function shot(page, name) {
    if (process.env.SCREENSHOT_DIR) {
        await page.screenshot({
            path: `${process.env.SCREENSHOT_DIR}/${name}.png`,
            fullPage: true,
        });
    }
}

function jwtPayload(token) {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
}

async function exchangeCode(callbackUrl) {
    const code = new URL(callbackUrl).searchParams.get('code');
    const res = await fetch(`${BASE}/auth/v1/oidc/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: CALLBACK,
            client_id: CLIENT_ID,
            code_verifier: VERIFIER,
        }),
    });
    assert.equal(res.status, 200, await res.clone().text());
    return res.json();
}

async function enterPin(page, pin) {
    const input = page.locator('#shared-device-pin');
    await input.waitFor();
    await input.fill(pin);
}

test('shared devices: register a PC, PIN login, lock and unlock', async t => {
    const adminCtx = await browser.newContext({ serviceWorkers: 'block' });
    t.after(() => adminCtx.close());
    const admin = await adminCtx.newPage();
    await login(admin, ADMIN);

    // --- a PIN client with force_mfa
    let res = await api(admin, 'GET', `/clients/${CLIENT_ID}`);
    if (res.status === 404) {
        res = await api(admin, 'POST', '/clients', {
            id: CLIENT_ID,
            name: 'PIN Test',
            confidential: false,
            redirect_uris: [CALLBACK],
        });
        assert.equal(res.status, 200, res.text);
    }
    res = await api(admin, 'GET', `/clients/${CLIENT_ID}`);
    res = await api(admin, 'PUT', `/clients/${CLIENT_ID}`, {
        ...res.json,
        force_mfa: true,
        flows_enabled: ['authorization_code', 'refresh_token'],
        access_token_lifetime: 300,
    });
    assert.equal(res.status, 200, res.text);

    // --- two people with passkeys, the first one administers the practice
    const emailA = `pin-a-${Date.now()}@ptest.io`;
    const emailB = `pin-b-${Date.now()}@ptest.io`;
    const uidA = await createUser(admin, emailA);
    const uidB = await createUser(admin, emailB);

    res = await api(admin, 'PUT', `/shared_devices/practices/${PRACTICE}`, {
        name: 'Praxis Test',
        idle_timeout: 120,
        notify_user_ids: [uidA],
    });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.idle_timeout, 120);
    for (const uid of [uidA, uidB]) {
        res = await api(admin, 'PUT', `/shared_devices/practices/${PRACTICE}/members/${uid}`);
        assert.equal(res.status, 204, res.text);
    }
    res = await api(admin, 'PUT', `/shared_devices/practices/${PRACTICE}/members/unknown123`);
    assert.equal(res.status, 404, res.text);

    // B sets up a passkey and a PIN in an own browser
    const phoneCtx = await browser.newContext({ serviceWorkers: 'block' });
    t.after(() => phoneCtx.close());
    const phone = await phoneCtx.newPage();
    await login(phone, { email: emailB, password: PWD });
    await addAuthenticator(phone);
    await addPasskey(phone, uidB);
    // a password alone never creates a PIN
    const pwdToken = await api(phone, 'POST', `/users/${uidB}/mfa_token`, { password: PWD });
    assert.equal(pwdToken.status, 400, `password token with a passkey: ${pwdToken.text}`);
    res = await api(phone, 'POST', `/users/${uidB}/shared_device_pins/${PRACTICE}`, {
        mfa_mod_token_id: await mfaTokenViaPasskey(phone, uidB),
    });
    assert.equal(res.status, 200, res.text);
    const pinB = res.json.pin;
    assert.match(pinB, /^[0-9]{4}$/);
    res = await api(phone, 'GET', `/users/${uidB}/shared_device_pins`);
    assert.equal(res.json[0].practice_name, 'Praxis Test');
    assert.ok(res.json[0].pin_created > 0);

    // --- A registers the reception PC in its own session with a fresh passkey
    const pcCtx = await browser.newContext({ serviceWorkers: 'block', locale: 'en-US' });
    t.after(() => pcCtx.close());
    const pc = await pcCtx.newPage();
    await login(pc, { email: emailA, password: PWD });
    await addAuthenticator(pc);
    await addPasskey(pc, uidA);

    res = await api(admin, 'POST', `/shared_devices/practices/${PRACTICE}/registrations`, {
        user_id: uidA,
        label: 'Empfang 1',
        return_uri: 'https://evil.example/',
    });
    assert.equal(res.status, 400, `foreign return_uri: ${res.text}`);
    res = await api(admin, 'POST', `/shared_devices/practices/${PRACTICE}/registrations`, {
        user_id: uidA,
        label: 'Empfang 1',
        return_uri: `${BASE}/auth/v1/account`,
    });
    assert.equal(res.status, 200, res.text);
    const regUrl = res.json.url;
    const regId = res.json.id;

    // the link is useless in another browser, even with a session of someone else
    res = await api(phone, 'GET', `/shared_devices/registrations/${regId}`);
    assert.equal(res.status, 404, res.text);

    await pc.goto(regUrl);
    await pc.getByText('Empfang 1').first().waitFor();
    await pc.getByRole('button', { name: 'Confirm with passkey and register' }).click();
    await pc.getByText('Please confirm the notice.').waitFor();
    await shot(pc, 'register-required');
    await pc.getByRole('checkbox').check();
    await pc.getByRole('button', { name: 'Confirm with passkey and register' }).click();
    await pc.getByText('This PC is now registered as a practice PC.').waitFor();
    // the session of the registering person has been ended
    res = await api(pc, 'GET', `/users/${uidA}/shared_device_pins`);
    assert.equal(res.status, 401, res.text);
    await shot(pc, 'register-done');
    assert.equal(
        await pc.getByRole('link', { name: 'Back to the application' }).getAttribute('href'),
        `${BASE}/auth/v1/account`,
    );
    // the registration is used up
    res = await api(admin, 'GET', `/shared_devices/registrations/${regId}`);
    assert.equal(res.status, 404, res.text);

    res = await api(admin, 'GET', `/shared_devices/practices/${PRACTICE}`);
    assert.equal(res.json.devices.length, 1);
    assert.equal(res.json.risk_ack_by, uidA);
    const deviceId = res.json.devices[0].id;

    // no passkeys on a shared device
    res = await api(pc, 'POST', `/users/${uidA}/webauthn/register/start`, {
        passkey_name: 'Shared',
        mfa_mod_token_id: 'x'.repeat(32),
    });
    assert.equal(res.status, 403, res.text);

    // A signs in on the PC with the passkey for the account page
    await pc.goto(authorizeUrl(CLIENT_ID));
    await pc.getByRole('button', { name: 'Sign in with passkey' }).click();
    await pc.waitForURL(/\/oidc\/callback/);

    // A creates a PIN on the account page of the PC
    await pc.goto(`${BASE}/auth/v1/account`);
    await pc.getByRole('button', { name: 'MFA', exact: true }).first().click();
    await pc.getByRole('heading', { name: 'PIN for practice PCs' }).waitFor();
    await pc.getByRole('button', { name: 'Create PIN' }).click();
    const shown = pc.locator('.shown .pin');
    await shown.waitFor();
    await shot(pc, 'account-pin');
    const pinA = (await shown.textContent()).trim();
    assert.match(pinA, /^[0-9]{4}$/);
    assert.notEqual(pinA, pinB);

    // --- PIN login of B on the PC
    await pc.goto(authorizeUrl(CLIENT_ID));
    await pc.getByText('Empfang 1 · Praxis Test').waitFor();
    const wrong = ['1357', '2468', '1470', '2580', '3690', '1593'].find(
        p => p !== pinA && p !== pinB,
    );
    await enterPin(pc, wrong);
    await pc.getByRole('alert').filter({ hasText: '4 more wrong PINs' }).waitFor();
    await shot(pc, 'pin-wrong');
    await enterPin(pc, pinB);
    await pc.waitForURL(/\/oidc\/callback/);
    const tokens = await exchangeCode(pc.url());
    const access = jwtPayload(tokens.access_token);
    const id = jwtPayload(tokens.id_token);
    assert.equal(access.sub, uidB);
    assert.deepEqual(access.amr, ['pin', 'swk']);
    assert.deepEqual(id.amr, ['pin', 'swk']);
    assert.match(deviceId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.equal(access.aa_shared_device, deviceId);
    assert.equal(id.aa_shared_device, deviceId);
    // a PIN session only serves the login, not the account
    res = await api(pc, 'GET', `/users/${uidB}/shared_device_pins`);
    assert.equal(res.status, 401, res.text);
    // the token chain ends after the idle timeout without a refresh
    const refresh = jwtPayload(tokens.refresh_token);
    assert.ok(refresh.exp - refresh.nbf <= 120, `${refresh.exp - refresh.nbf}`);

    // a PIN login of a client that accepts no PIN is impossible
    await pc.goto(authorizeUrl('rauthy'));
    await pc.locator('input[name=email]').waitFor();
    assert.equal(await pc.locator('#shared-device-pin').count(), 0);

    // never a silent login on the PC
    await pc.goto(authorizeUrl(CLIENT_ID, '&prompt=none'));
    await pc.waitForURL(/error=login_required/);

    // `max_age` asks for a passkey
    await pc.goto(authorizeUrl(CLIENT_ID, '&max_age=0'));
    await pc.locator('input[name=email]').waitFor();
    assert.equal(await pc.locator('#shared-device-pin').count(), 0);

    // --- 5 wrong PINs lock the PC, the practice gets a mail
    await pc.goto(authorizeUrl(CLIENT_ID));
    // the wrong PIN before stays counted, a correct PIN does not reset it
    for (const left of [3, 2, 1]) {
        await enterPin(pc, wrong);
        await pc
            .getByRole('alert')
            .filter({ hasText: `${left} more wrong PINs` })
            .waitFor();
    }
    await enterPin(pc, wrong);
    await pc.getByText('This PC is locked after too many wrong PINs').waitFor();
    await shot(pc, 'pin-locked');
    await waitForMail(emailA, 'Practice PC locked');
    res = await api(admin, 'GET', `/shared_devices/practices/${PRACTICE}`);
    assert.ok(res.json.devices[0].locked_at > 0);

    // A unlocks it with the passkey
    await pc.getByRole('button', { name: 'Unlock with passkey' }).click();
    await pc.waitForURL(/\/oidc\/callback/);
    res = await api(admin, 'GET', `/shared_devices/practices/${PRACTICE}`);
    assert.equal(res.json.devices[0].locked_at, null);
    assert.equal(res.json.devices[0].failed_pins, 0);

    await pc.goto(authorizeUrl(CLIENT_ID));
    await enterPin(pc, pinA);
    await pc.waitForURL(/\/oidc\/callback/);

    res = await api(admin, 'GET', `/shared_devices/practices/${PRACTICE}/events`);
    const kinds = res.json.map(e => e.kind);
    for (const k of ['registered', 'pin_login', 'pin_failed', 'locked', 'unlocked']) {
        assert.ok(kinds.includes(k), `${k} in ${kinds}`);
    }

    // --- IP lock: the test runs from the registered address, so nothing changes
    res = await api(admin, 'PUT', `/shared_devices/devices/${deviceId}`, {
        label: 'Empfang 2',
        ip_lock: true,
    });
    assert.equal(res.status, 204, res.text);
    await pc.goto(authorizeUrl(CLIENT_ID));
    await pc.getByText('Empfang 2 · Praxis Test').waitFor();

    // --- optional practice roles use their own PINs and keep the account's personal PIN
    const roles = `/shared_devices/practices/${PRACTICE}/roles`;
    res = await api(admin, 'PUT', roles, { user_id: uidA });
    assert.equal(res.status, 204, res.text);
    res = await api(admin, 'PUT', roles, { user_id: uidB });
    assert.equal(res.status, 403, res.text);
    res = await api(admin, 'GET', roles);
    assert.equal(res.json.length, 3);
    assert.ok(res.json.every(r => r.enabled && !r.has_pin));
    for (const role of ['administration', 'management', 'staff']) {
        res = await api(admin, 'PUT', `${roles}/${role}/pin`, {
            user_id: uidA,
            password: PWD,
            pin: '7391',
        });
        assert.equal(res.status, 204, res.text);
    }
    await pc.goto(authorizeUrl(CLIENT_ID));
    await pc.getByLabel('Rolle wählen').selectOption('staff');
    // A client cannot omit the role and fall back to a valid old personal PIN.
    await pc.route(
        '**/oidc/authorize/pin',
        async route => {
            const body = route.request().postDataJSON();
            delete body.role;
            await route.continue({ postData: JSON.stringify(body) });
        },
        { times: 1 },
    );
    const bypass = pc.waitForResponse(r => r.url().endsWith('/oidc/authorize/pin'));
    await enterPin(pc, pinA);
    assert.equal((await bypass).status(), 403);
    await enterPin(pc, '7391');
    await pc.waitForURL(/\/oidc\/callback/);
    const roleTokens = await exchangeCode(pc.url());
    const roleClaims = jwtPayload(roleTokens.access_token);
    assert.equal(roleClaims.sub, uidA);
    assert.equal(roleClaims.aa_practice_role, 'staff');
    assert.equal(roleClaims.aa_practice_id, PRACTICE);
    assert.ok(roleClaims.aa_shared_session);
    assert.ok(
        jwtPayload(roleTokens.refresh_token).exp - jwtPayload(roleTokens.refresh_token).nbf > 120,
    );
    const live = `/shared_devices/sessions/${roleClaims.aa_shared_session}`;
    res = await api(admin, 'GET', live);
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.role, 'staff');
    // A role session cannot change a different role, even through the trusted backend API.
    res = await api(admin, 'PUT', `${roles}/administration/pin`, {
        user_id: uidA,
        session_id: roleClaims.aa_shared_session,
        pin: '4826',
    });
    assert.equal(res.status, 403, res.text);
    res = await api(admin, 'PUT', `${roles}/staff/pin`, {
        user_id: uidA,
        session_id: roleClaims.aa_shared_session,
        pin: '4826',
    });
    assert.equal(res.status, 204, res.text);
    res = await api(admin, 'GET', live);
    assert.ok([401, 403, 404].includes(res.status), res.text);
    // The password lock is account-wide and does not prevent a passkey or role PIN login.
    for (let attempt = 0; attempt < 5; attempt++) {
        res = await api(admin, 'PUT', `${roles}/staff/pin`, {
            user_id: uidA,
            password: 'wrong-synthetic-password',
            pin: '4826',
        });
        assert.equal(res.status, 401, res.text);
    }
    res = await api(admin, 'PUT', `${roles}/staff/pin`, {
        user_id: uidA,
        password: PWD,
        pin: '4826',
    });
    assert.equal(res.status, 401, res.text);
    await pc.goto(authorizeUrl(CLIENT_ID));
    await pc.getByRole('button', { name: 'Sign in with passkey' }).click();
    await pc.waitForURL(/\/oidc\/callback/);
    // Five wrong PINs lock only this role/device; another role still works.
    await pc.goto(authorizeUrl(CLIENT_ID));
    await pc.getByLabel('Rolle wählen').selectOption('staff');
    for (let attempt = 0; attempt < 5; attempt++) {
        const denied = pc.waitForResponse(r => r.url().endsWith('/oidc/authorize/pin'));
        await enterPin(pc, '0000');
        assert.ok([401, 423].includes((await denied).status()));
    }
    const locked = pc.waitForResponse(r => r.url().endsWith('/oidc/authorize/pin'));
    await enterPin(pc, '4826');
    assert.equal((await locked).status(), 423);
    await pc.getByLabel('Rolle wählen').selectOption('management');
    await enterPin(pc, '7391');
    await pc.waitForURL(/\/oidc\/callback/);
    const manager = jwtPayload((await exchangeCode(pc.url())).access_token);
    assert.equal(manager.aa_practice_role, 'management');
    res = await api(admin, 'DELETE', roles);
    assert.equal(res.status, 204, res.text);
    res = await api(admin, 'GET', `/shared_devices/sessions/${manager.aa_shared_session}`);
    assert.ok([401, 403, 404].includes(res.status), res.text);
    res = await api(admin, 'GET', roles);
    assert.ok(res.json.every(r => !r.enabled && r.has_pin));

    // --- a sign-in reset deletes the passkeys, and with the last one the PIN
    res = await api(admin, 'DELETE', `/users/${uidB}/webauthn/delete/Key`, {});
    assert.ok(res.status < 300, res.text);
    res = await api(admin, 'GET', `/shared_devices/practices/${PRACTICE}`);
    assert.equal(res.json.members.find(m => m.user_id === uidB).has_pin, false);

    // --- revoked: back to the normal login
    res = await api(admin, 'DELETE', `/shared_devices/devices/${deviceId}`);
    assert.equal(res.status, 204, res.text);
    await pc.goto(authorizeUrl(CLIENT_ID));
    await pc.locator('input[name=email]').waitFor();
    assert.equal(await pc.locator('#shared-device-pin').count(), 0);

    res = await api(admin, 'DELETE', `/shared_devices/practices/${PRACTICE}`);
    assert.equal(res.status, 204, res.text);
    for (const uid of [uidA, uidB]) {
        res = await api(admin, 'DELETE', `/users/${uid}`);
        assert.ok(res.status < 300, res.text);
    }
});
