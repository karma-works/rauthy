// Built-UI contract tests for the "shared computer" question (`webauthn.ask_shared_device`)
// before a passkey registration on the account setup page. All requests are intercepted; the
// passkey comes from a CDP virtual authenticator.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { after, before, test } from 'node:test';
import { chromium } from '@playwright/test';

const b64url = bytes => Buffer.from(bytes).toString('base64url');

let browser;
let html;
before(async () => {
    html = await readFile(
        new URL('../../templates/html/users/{id}/reset/reset.html', import.meta.url),
        'utf8',
    );
    browser = await chromium.launch({
        executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
    });
});
after(async () => browser?.close());

/**
 * `answer`: the radio to pick (or `undefined`), `useThisDevice`: tick the override.
 * Returns the start and finish payloads.
 */
async function register(t, { ask, answer, useThisDevice = false, expectRegistration = true }) {
    const context = await browser.newContext({ serviceWorkers: 'block', locale: 'de-DE' });
    t.after(() => context.close());
    const page = await context.newPage();
    const tpl = {
        user_id: 'new-user',
        magic_link_id: crypto.randomUUID(),
        csrf_token: crypto.randomUUID(),
        needs_mfa: false,
        passkey_only: true,
        password_policy: {
            length_min: 12,
            length_max: 128,
            include_lower_case: 1,
            include_upper_case: 1,
            include_digits: 1,
            include_special: 1,
        },
    };
    const payloads = {};
    const documentPath = '/auth/v1/users/new-user/reset/reset';
    await context.route('**/*', async route => {
        const request = route.request();
        const url = new URL(request.url());
        if (url.origin !== 'http://localhost') return route.abort();
        if (request.method() === 'GET' && url.pathname === documentPath) {
            return route.fulfill({
                contentType: 'text/html',
                body: html
                    .replace('{{lang}}', 'de')
                    .replace(
                        /\{%- for tpl in templates -%\}[\s\S]*?\{%- endfor %\}/,
                        `<template id="tpl_password_reset">${JSON.stringify(tpl)}</template>` +
                            `<template id="tpl_ask_shared_device">${ask}</template>`,
                    ),
            });
        }
        if (
            /^\/auth\/v1\/_app\/immutable\/(entry|chunks|nodes|assets)\/[\w.-]+\.(js|css|woff2)$/.test(
                url.pathname,
            )
        ) {
            return route.fulfill({
                path: fileURLToPath(
                    new URL(`../../static/v1/${url.pathname.slice(9)}`, import.meta.url),
                ),
            });
        }
        if (request.method() === 'GET') return route.fulfill({ status: 404 });
        const body = request.postDataJSON();
        if (url.pathname === '/auth/v1/users/new-user/webauthn/register/start') {
            payloads.start = body;
            return route.fulfill({
                json: {
                    publicKey: {
                        challenge: b64url(crypto.getRandomValues(new Uint8Array(32))),
                        rp: { name: 'Setup test', id: 'localhost' },
                        user: {
                            id: b64url(crypto.getRandomValues(new Uint8Array(16))),
                            name: 'new-user',
                            displayName: 'New user',
                        },
                        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
                        authenticatorSelection: { userVerification: 'required' },
                        timeout: 30000,
                        hints: body.hints,
                    },
                },
            });
        }
        if (url.pathname === '/auth/v1/users/new-user/webauthn/register/finish') {
            payloads.finish = body;
            return route.fulfill({ status: 201 });
        }
        return route.fulfill({ status: 400, json: { message: 'Unexpected endpoint' } });
    });

    await page.goto(`http://localhost${documentPath}?type=new_user`);
    await page.getByLabel('Passkey Name').waitFor();
    const cdp = await context.newCDPSession(page);
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

    const question = page.getByRole('group', { name: 'Wird dieser Computer' });
    if (ask) {
        await question.waitFor();
    } else {
        assert.equal(await question.count(), 0);
    }
    const labels = {
        yes: 'Ja, mehrere Personen nutzen dieses Benutzerkonto',
        no: 'Nein, das Benutzerkonto oder Gerät gehört nur mir',
        unknown: 'Weiß ich nicht',
    };
    const warning = page.getByText('Ein Passkey auf diesem Computer ist nicht persönlich', {
        exact: false,
    });
    if (answer) {
        await question.getByLabel(labels[answer]).check();
        assert.equal(await warning.isVisible(), answer !== 'no');
    }
    if (useThisDevice) {
        await page.getByLabel('Trotzdem diesen Computer verwenden').check();
    }

    await page.getByLabel('Passkey Name').fill('Laptop');
    await page.getByRole('button', { name: 'Registrieren', exact: true }).click();
    if (expectRegistration) {
        await page.getByText('Der neue Passkey wurde erfolgreich registriert.').waitFor();
    }
    return { page, payloads };
}

test('no question when the switch is off', async t => {
    const { payloads } = await register(t, { ask: false });
    assert.equal(payloads.start.hints, undefined);
    assert.equal(payloads.finish.shared_device, undefined);
    // the browser's attachment and transports go along to derive the kind
    assert.equal(payloads.finish.authenticator_attachment, 'platform');
    assert.deepEqual(payloads.finish.data.response.transports, ['internal']);
});

test('the question must be answered', async t => {
    const { page, payloads } = await register(t, { ask: true, expectRegistration: false });
    await page.getByRole('alert').filter({ hasText: 'Bitte beantworten Sie die Frage.' }).waitFor();
    assert.deepEqual(payloads, {});
});

test('"no" registers normally', async t => {
    const { payloads } = await register(t, { ask: true, answer: 'no' });
    assert.equal(payloads.start.hints, undefined);
    assert.equal(payloads.finish.shared_device, 'no');
});

for (const answer of ['yes', 'unknown']) {
    test(`"${answer}" warns and asks for a smartphone or security key first`, async t => {
        const { payloads } = await register(t, { ask: true, answer });
        assert.deepEqual(payloads.start.hints, ['hybrid', 'security-key']);
        assert.equal(payloads.finish.shared_device, answer);
    });
}

test('"yes" with "use this computer anyway" drops the hints', async t => {
    const { payloads } = await register(t, { ask: true, answer: 'yes', useThisDevice: true });
    assert.equal(payloads.start.hints, undefined);
    assert.equal(payloads.finish.shared_device, 'yes');
});
