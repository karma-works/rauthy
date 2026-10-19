// Built-UI contract tests for the account setup from a "new account" link with a passkey.
// All requests are intercepted; the passkey comes from a CDP virtual authenticator.
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

for (const passkeyOnly of [true, false]) {
    test(`new account setup with a passkey, passkey_only=${passkeyOnly}`, async t => {
        const context = await browser.newContext({ serviceWorkers: 'block', locale: 'en-US' });
        t.after(() => context.close());
        const page = await context.newPage();
        const tpl = {
            user_id: 'new-user',
            magic_link_id: crypto.randomUUID(),
            csrf_token: crypto.randomUUID(),
            needs_mfa: false,
            passkey_only: passkeyOnly,
            password_policy: {
                length_min: 12,
                length_max: 128,
                include_lower_case: 1,
                include_upper_case: 1,
                include_digits: 1,
                include_special: 1,
            },
        };
        const requests = [];
        const documentPath = '/auth/v1/users/new-user/reset/reset';
        await context.route('**/*', async route => {
            const request = route.request();
            const url = new URL(request.url());
            if (url.origin !== 'http://localhost') return route.abort();
            if (request.method() === 'GET' && url.pathname === documentPath) {
                return route.fulfill({
                    contentType: 'text/html',
                    body: html.replace(
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
            requests.push(`${request.method()} ${url.pathname}`);
            const body = request.postDataJSON();
            assert.equal(request.headers()['x-pwd-csrf-token'], tpl.csrf_token);
            assert.equal(body.magic_link_id, tpl.magic_link_id);
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
                assert.equal(body.passkey_name, 'Laptop');
                return route.fulfill({ status: 201 });
            }
            return route.fulfill({ status: 400, json: { message: 'Unexpected endpoint' } });
        });

        await page.goto(`http://localhost${documentPath}?type=new_user`);
        await page.getByRole('heading', { name: 'New Account' }).waitFor();
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

        const passkeyOnlyIntro = page.getByText('Your account uses a passkey.', { exact: false });
        const passwordChoice = page.getByRole('button', { name: 'Password', exact: true });
        if (passkeyOnly) {
            await passkeyOnlyIntro.waitFor();
            assert.equal(await passwordChoice.count(), 0);
        } else {
            assert.equal(await passkeyOnlyIntro.count(), 0);
            await page.getByRole('button', { name: 'Passkey', exact: true }).click();
        }

        await page.getByLabel('Passkey Name').fill('Laptop');
        await page.getByRole('button', { name: 'Register', exact: true }).click();

        // a passkey setup must never claim that a password was changed
        await page.getByText('Your new passkey has been registered successfully.').waitFor();
        assert.equal(
            await page.getByText('The password has been updated successfully.').count(),
            0,
        );
        assert.deepEqual(requests, [
            'POST /auth/v1/users/new-user/webauthn/register/start',
            'POST /auth/v1/users/new-user/webauthn/register/finish',
        ]);
    });
}
