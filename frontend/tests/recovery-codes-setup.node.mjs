// Built-UI contract test: after the first passkey of an account setup, the recovery codes from
// the `register/finish` response are shown once (`webauthn.recovery_codes`). All requests are
// intercepted; the passkey comes from a CDP virtual authenticator.
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

const CODES = Array.from({ length: 10 }, (_, i) => `K7QF-3MXA-9PD${'0123456789'[i]}`);

test('the setup shows the recovery codes once before finishing', async t => {
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
                        `<template id="tpl_password_reset">${JSON.stringify(tpl)}</template>`,
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
        if (url.pathname === '/auth/v1/users/new-user/webauthn/register/start') {
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
                    },
                },
            });
        }
        if (url.pathname === '/auth/v1/users/new-user/webauthn/register/finish') {
            return route.fulfill({ status: 201, json: { recovery_codes: CODES } });
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
    await page.getByLabel('Passkey Name').fill('Laptop');
    await page.getByRole('button', { name: 'Registrieren', exact: true }).click();

    const section = page.getByRole('region', { name: 'Ihre Wiederherstellungscodes' });
    await section.waitFor();
    for (const code of CODES) {
        await section.getByText(code, { exact: true }).waitFor();
    }
    // no redirect and no success text while the codes are shown
    assert.equal(
        await page.getByText('Der neue Passkey wurde erfolgreich registriert.').count(),
        0,
    );
    const done = section.getByRole('button', { name: 'Fertig' });
    assert.equal(await done.isDisabled(), true);
    await section.getByLabel('Ich habe die Codes sicher aufbewahrt').check();
    await done.click();
    await page.getByText('Der neue Passkey wurde erfolgreich registriert.').waitFor();
    assert.equal(await section.count(), 0);
});
