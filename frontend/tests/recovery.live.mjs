// End-to-end test of recovery codes against a running test backend, not part of CI.
//
// Needs `rauthy serve -c config-test.toml --test` on :8081 with `WEBAUTHN_RECOVERY_CODES=true`,
// and mails going to a Mailpit at `MAILPIT_URL` (default http://127.0.0.1:18026), e.g.
// `SMTP_URL=127.0.0.1 SMTP_PORT=2525 SMTP_TLS_MODE=danger-insecure`.
// Run with: node --test tests/recovery.live.mjs
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { chromium } from '@playwright/test';
import { createHash } from 'node:crypto';

const BASE = 'http://localhost:8081';
const MAILPIT = process.env.MAILPIT_URL || 'http://127.0.0.1:18026';
const ADMIN = { email: 'init_admin@localhost', password: '123SuperSafe' };
const USER = { email: `recovery-${Date.now()}@rtest.io`, password: '123SuperSafe123!' };

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
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
            protocol: 'ctap2',
            transport: 'internal',
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
        },
    });
}

/** Logs in with a password through the login page of the `rauthy` client. */
async function login(page, { email, password }) {
    // S256 of a fixed verifier, the token exchange does not matter here
    const challenge = createHash('sha256').update('v'.repeat(64)).digest('base64url');
    await page.goto(
        `${BASE}/auth/v1/oidc/authorize?client_id=rauthy&response_type=code` +
            `&redirect_uri=${encodeURIComponent(`${BASE}/auth/v1/oidc/callback`)}` +
            `&code_challenge=${challenge}&code_challenge_method=S256`,
    );
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

/** Runs a WebAuthn ceremony in the page with the backend's options. */
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
                    attachment: cred.authenticatorAttachment,
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

async function mails(to) {
    const res = await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`);
    const body = await res.json();
    return body.messages || [];
}

async function mailText(id) {
    const res = await fetch(`${MAILPIT}/api/v1/message/${id}`);
    return (await res.json()).Text;
}

async function waitForMail(to, count) {
    for (let i = 0; i < 40; i++) {
        const list = await mails(to);
        if (list.length >= count) return list;
        await new Promise(r => setTimeout(r, 250));
    }
    throw new Error(`no mail #${count} for ${to}`);
}

/** Uses the public recover page in a fresh browser. Returns the page after "Continue". */
async function redeem(code, email = USER.email) {
    const context = await browser.newContext({ serviceWorkers: 'block', locale: 'en-US' });
    const page = await context.newPage();
    await page.goto(`${BASE}/auth/v1/users/recover`);
    await page.locator('#recover-email').fill(email);
    await page.locator('#recover-code').fill(code);
    const started = Date.now();
    const response = page.waitForResponse(r => r.url().endsWith('/users/recover/start'));
    await page.getByRole('button', { name: 'Continue' }).click();
    const challengeId = (await (await response).json()).challenge_id;
    await page.getByText('If the email address and the code are correct').waitFor();
    return { page, context, took: Date.now() - started, challengeId };
}

test('recovery codes: create, redeem, register a new passkey', async t => {
    // --- an admin creates a password user
    const adminCtx = await browser.newContext({ serviceWorkers: 'block' });
    t.after(() => adminCtx.close());
    const admin = await adminCtx.newPage();
    await login(admin, ADMIN);
    const created = await api(admin, 'POST', '/users', {
        email: USER.email,
        given_name: 'Rec',
        family_name: 'Overy',
        language: 'en',
        roles: [],
    });
    assert.equal(created.status, 200, created.text);
    const uid = created.json.id;
    const upd = await api(admin, 'PUT', `/users/${uid}`, {
        email: USER.email,
        given_name: 'Rec',
        family_name: 'Overy',
        language: 'en',
        password: USER.password,
        roles: [],
        enabled: true,
        email_verified: true,
    });
    assert.equal(upd.status, 200, upd.text);

    // --- the user adds a passkey
    const userCtx = await browser.newContext({ serviceWorkers: 'block' });
    t.after(() => userCtx.close());
    const user = await userCtx.newPage();
    await login(user, USER);
    await addAuthenticator(user);
    const pwdToken = await api(user, 'POST', `/users/${uid}/mfa_token`, {
        password: USER.password,
    });
    assert.equal(pwdToken.status, 200, pwdToken.text);
    // a password alone must not create codes
    let res = await api(user, 'POST', `/users/${uid}/recovery_codes`, {
        mfa_mod_token_id: pwdToken.json.id,
    });
    assert.equal(res.status, 400, res.text);

    const regStart = await api(user, 'POST', `/users/${uid}/webauthn/register/start`, {
        passkey_name: 'Laptop',
        mfa_mod_token_id: pwdToken.json.id,
        allow_rk: true,
    });
    assert.equal(regStart.status, 200, regStart.text);
    const cred = await passkeyCeremony(user, 'create', regStart.json);
    const regFinish = await api(user, 'POST', `/users/${uid}/webauthn/register/finish`, {
        passkey_name: 'Laptop',
        data: { ...cred, attachment: undefined },
        authenticator_attachment: cred.attachment,
    });
    assert.equal(regFinish.status, 201, regFinish.text);

    // --- codes need a passkey ceremony, the token is consumed
    const token = await mfaTokenViaPasskey(user, uid);
    res = await api(user, 'POST', `/users/${uid}/recovery_codes`, { mfa_mod_token_id: token });
    assert.equal(res.status, 200, res.text);
    const codes = res.json.recovery_codes;
    assert.equal(codes.length, 10);
    assert.match(codes[0], /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
    res = await api(user, 'POST', `/users/${uid}/recovery_codes`, { mfa_mod_token_id: token });
    assert.equal(res.status, 401, `a used token must fail: ${res.text}`);
    res = await api(user, 'GET', `/users/${uid}/recovery_codes`);
    assert.deepEqual([res.status, res.json.remaining], [200, 10]);
    // "new codes" mail
    await waitForMail(USER.email, 1);

    // --- an unknown account and a wrong code look exactly like a valid code
    const mailsBefore = (await mails(USER.email)).length;
    for (const [code, email] of [
        ['AAAA-BBBB-CCCC', 'nobody-here@rtest.io'],
        ['AAAA-BBBB-CCCC', USER.email],
    ]) {
        const r = await redeem(code, email);
        assert.ok(r.took >= 1400, `took ${r.took} ms`);
        await r.context.close();
    }
    assert.equal((await mails(USER.email)).length, mailsBefore, 'no mail for a wrong code');

    // --- redeem a valid code (lowercase, without dashes)
    const { page, context, took } = await redeem(codes[0].replaceAll('-', '').toLowerCase());
    t.after(() => context.close());
    assert.ok(took >= 1400, `took ${took} ms`);
    const list = await waitForMail(USER.email, mailsBefore + 1);
    const text = await mailText(list[0].ID);
    const mailCode = text.match(/confirmation code is (\d{8})/)[1];

    // a wrong mail code first
    await page.locator('#recover-mail-code').fill('00000000');
    await page.getByRole('button', { name: 'Confirm' }).click();
    await page.getByRole('alert').filter({ hasText: 'invalid or has expired' }).waitFor();
    await page.locator('#recover-mail-code').fill(mailCode);
    await page.getByRole('button', { name: 'Confirm' }).click();

    // register a new passkey in this browser
    await addAuthenticator(page);
    await page.locator('#recover-passkey-name').fill('Phone');
    await page.getByRole('button', { name: 'Register', exact: true }).click();
    await page.getByText('Your new passkey is set up').waitFor();

    // the old session is gone, the code is used up
    res = await api(user, 'GET', `/users/${uid}/recovery_codes`);
    assert.equal(res.status, 401, 'the user session must have been ended');
    res = await api(admin, 'GET', `/users/${uid}/recovery_codes`);
    assert.deepEqual([res.status, res.json.remaining], [200, 9]);
    res = await api(admin, 'GET', `/users/${uid}/webauthn`);
    assert.deepEqual(res.json.map(p => p.name).sort(), ['Laptop', 'Phone']);

    // the same code again: same response, no mail
    const mailsAfter = (await mails(USER.email)).length;
    const again = await redeem(codes[0]);
    await again.context.close();
    await new Promise(r => setTimeout(r, 1000));
    // only the "new passkey" mail may have arrived meanwhile
    const fresh = (await mails(USER.email)).length;
    assert.ok(fresh <= mailsAfter + 1, `${fresh} vs ${mailsAfter}`);

    // --- 5 failures send one warning, but never block a valid code of the owner
    for (let i = 0; i < 5; i++) {
        const r = await redeem('ZZZZ-ZZZZ-ZZZZ');
        await r.context.close();
    }
    const warned = await waitForMail(USER.email, fresh + 1);
    assert.match(await mailText(warned[0].ID), /Invalid recovery codes have been entered/);
    const warnedCount = (await mails(USER.email)).length;
    const second = await redeem(codes[1]);
    t.after(() => second.context.close());
    const withCode = await waitForMail(USER.email, warnedCount + 1);
    const secondCode = (await mailText(withCode[0].ID)).match(/confirmation code is (\d{8})/)[1];

    // parallel guesses of the mail code use up its 3 attempts, the right code is too late then
    const challengeId = second.challengeId;
    {
        const statuses = await second.page.evaluate(
            id =>
                Promise.all(
                    Array.from({ length: 6 }, (_, i) =>
                        fetch('/auth/v1/users/recover/verify', {
                            method: 'POST',
                            headers: { 'content-type': 'application/json' },
                            body: JSON.stringify({ challenge_id: id, mail_code: `1234567${i}` }),
                        }).then(async r => [r.status, (await r.json()).message]),
                    ),
                ),
            challengeId,
        );
        assert.ok(
            statuses.every(([status, msg]) => status === 400 && /invalid or has expired/.test(msg)),
            JSON.stringify(statuses),
        );
        await second.page.locator('#recover-mail-code').fill(secondCode);
        await second.page.getByRole('button', { name: 'Confirm' }).click();
        await second.page
            .getByRole('alert')
            .filter({ hasText: 'invalid or has expired' })
            .waitFor();
    }

    // --- an admin deletes the codes
    res = await api(admin, 'DELETE', `/users/${uid}/recovery_codes`);
    assert.equal(res.status, 200, res.text);
    res = await api(admin, 'GET', `/users/${uid}/recovery_codes`);
    assert.equal(res.json.remaining, 0);

    res = await api(admin, 'DELETE', `/users/${uid}`);
    assert.ok(res.status < 300, res.text);
});
