// Built-UI contract tests for `access.login_layout = 'split'` on the login page.
// All requests are intercepted; passkeys come from a CDP virtual authenticator.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { after, before, test } from 'node:test';
import { chromium } from '@playwright/test';

const b64url = bytes => Buffer.from(bytes).toString('base64url');
const documentPath = '/auth/v1/oidc/authorize';
const redirectUri = 'http://localhost/app/callback';
const query = new URLSearchParams({
    client_id: 'aa-practice-web',
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid',
    state: 'state-1',
    code_challenge: 'x'.repeat(43),
    code_challenge_method: 'S256',
});
// ArztAgent-like colors, as the theme API would deliver them
const themeCss = `:root {
    --text: 160 5% 19%; --text-high: 160 5% 15%; --bg: 45 22% 96%; --bg-high: 43 13% 85%;
    --action: 172 31% 28%; --accent: 30 85% 31%; --error: 0 70% 40%; --btn-text: white;
    --border-radius: 8px;
}`;

let browser;
let html;
before(async () => {
    html = await readFile(
        new URL('../../templates/html/oidc/authorize.html', import.meta.url),
        'utf8',
    );
    browser = await chromium.launch({
        executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
    });
});
after(async () => browser?.close());

/**
 * Opens the login page with mocked backend responses. `authorize` answers the final
 * `POST /oidc/authorize` and receives its JSON body.
 */
async function openLogin(t, { layout, width = 1280, height = 800, authorize, recovery = false }) {
    const context = await browser.newContext({
        serviceWorkers: 'block',
        locale: 'de-DE',
        viewport: { width, height },
    });
    t.after(() => context.close());
    // records the `hints` the page passes to `navigator.credentials.get()`
    const hints = [];
    await context.exposeBinding('__recordHints', (_source, value) => hints.push(value));
    await context.addInitScript(() => {
        const get = navigator.credentials.get.bind(navigator.credentials);
        navigator.credentials.get = async options => {
            await window.__recordHints(options?.publicKey?.hints ?? null);
            return get(options);
        };
    });
    const page = await context.newPage();
    const requests = [];
    const templates = {
        tpl_client_name: 'ArztAgent',
        tpl_csrf_token: 'csrf-1',
        tpl_login_action: 'None',
        tpl_passkey_reg_type: 'resident_key default',
        tpl_legal_links: JSON.stringify({
            imprint_url: 'https://example.com/impressum',
            privacy_url: 'https://example.com/datenschutz',
            help_url: 'https://example.com/hilfe',
        }),
        tpl_login_layout: layout,
        tpl_recovery_codes: String(recovery),
    };
    await context.route('**/*', async route => {
        const request = route.request();
        const url = new URL(request.url());
        if (url.origin !== 'http://localhost') return route.abort();
        if (request.method() === 'GET' && url.pathname === documentPath) {
            const tpls = Object.entries(templates)
                .map(([id, value]) => `<template id="${id}">${value}</template>`)
                .join('');
            return route.fulfill({
                contentType: 'text/html',
                body: html
                    .replace('{{lang}}', 'de')
                    .replace(/\{%- for tpl in templates -%\}[\s\S]*?\{%- endfor %\}/, tpls),
            });
        }
        if (request.method() === 'GET' && url.pathname.startsWith('/auth/v1/theme/')) {
            return route.fulfill({ contentType: 'text/css', body: themeCss });
        }
        if (request.method() === 'GET' && url.pathname === '/app/callback') {
            return route.fulfill({ contentType: 'text/html', body: '<p>App</p>' });
        }
        if (
            /^\/auth\/v1\/_app\/immutable\/(entry|chunks|nodes|assets|workers)\/[\w.-]+\.(js|css|woff2|wasm)$/.test(
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
        if (url.pathname === '/auth/v1/pow') {
            // no PoW in these tests: the login request is sent with an empty one
            return route.fulfill({ status: 400, json: { message: 'no pow' } });
        }
        if (url.pathname === '/auth/v1/users/webauthn_start') {
            assert.deepEqual(request.postDataJSON(), { purpose: 'Discover' });
            return route.fulfill({
                json: {
                    code: 'discover-1',
                    exp: 5,
                    rcr: {
                        publicKey: {
                            challenge: b64url(crypto.getRandomValues(new Uint8Array(32))),
                            rpId: 'localhost',
                            userVerification: 'required',
                            timeout: 4000,
                        },
                    },
                },
            });
        }
        if (url.pathname === '/auth/v1/users/webauthn_finish') {
            assert.equal(request.postDataJSON().code, 'discover-1');
            return route.fulfill({ status: 202, json: { resident_key_token: 'rk-token-1' } });
        }
        if (url.pathname === documentPath) {
            return authorize(route, request.postDataJSON());
        }
        return route.fulfill({ status: 400, json: { message: 'Unexpected endpoint' } });
    });
    await page.goto(`http://localhost${documentPath}?${query}`);
    return { page, requests, hints };
}

async function addPasskey(page) {
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
    await page.evaluate(() =>
        navigator.credentials.create({
            publicKey: {
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                rp: { name: 'Split login test', id: 'localhost' },
                user: {
                    id: crypto.getRandomValues(new Uint8Array(16)),
                    name: 'anna@praxis.de',
                    displayName: 'Anna',
                },
                pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
                authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
            },
        }),
    );
}

const loginAccepted = (route, body, seen) => {
    seen.push(body);
    return route.fulfill({ status: 202, headers: { location: redirectUri } });
};

test('split layout: known device signs in with a discoverable passkey', async t => {
    const seen = [];
    const { page, requests, hints } = await openLogin(t, {
        layout: 'split',
        authorize: (route, body) => loginAccepted(route, body, seen),
    });
    await page.getByRole('heading', { name: 'Anmelden bei ArztAgent' }).waitFor();
    await addPasskey(page);

    await page.getByRole('button', { name: 'Mit Passkey anmelden' }).click();
    await page.waitForURL(redirectUri);

    assert.equal(seen.length, 1);
    assert.equal(seen[0].resident_key_token, 'rk-token-1');
    // the known-device card never sends an E-Mail with the passkey
    assert.equal(seen[0].email, undefined);
    assert.equal(seen[0].client_id, 'aa-practice-web');
    assert.deepEqual(hints, [['client-device']]);
    assert.deepEqual(requests.slice(-3), [
        'POST /auth/v1/users/webauthn_finish',
        'POST /auth/v1/pow',
        `POST ${documentPath}`,
    ]);
});

test('split layout: new device sends the E-Mail and asks for phone or security key', async t => {
    const seen = [];
    const { page, hints } = await openLogin(t, {
        layout: 'split',
        authorize: (route, body) => loginAccepted(route, body, seen),
    });
    await page.getByRole('heading', { name: 'Anmelden bei ArztAgent' }).waitFor();
    await addPasskey(page);

    const card = page.getByRole('region', { name: 'Erstes Mal hier oder anderes Gerät' });
    await card.getByLabel('E-Mail').fill('Anna@Praxis.de');
    await card.getByRole('button', { name: 'Weiter' }).click();
    await page.waitForURL(redirectUri);

    assert.equal(seen[0].resident_key_token, 'rk-token-1');
    assert.equal(seen[0].email, 'Anna@Praxis.de');
    assert.deepEqual(hints, [['hybrid', 'security-key']]);
});

test('split layout: a passkey of another account shows the error in the new-device card', async t => {
    const { page } = await openLogin(t, {
        layout: 'split',
        authorize: route =>
            route.fulfill({
                status: 401,
                json: { error: 'Unauthorized', message: 'Invalid user credentials' },
            }),
    });
    await page.getByRole('heading', { name: 'Anmelden bei ArztAgent' }).waitFor();
    await addPasskey(page);

    const newCard = page.getByRole('region', { name: 'Erstes Mal hier oder anderes Gerät' });
    await newCard.getByLabel('E-Mail').fill('ben@praxis.de');
    await newCard.getByRole('button', { name: 'Weiter' }).click();

    await newCard.getByRole('alert').filter({ hasText: 'Anmeldung nicht möglich.' }).waitFor();
    const existingCard = page.getByRole('region', { name: 'Ich habe mich hier schon angemeldet' });
    assert.equal(await existingCard.getByRole('alert').count(), 0);
    // no password field appears in the split layout
    assert.equal(await page.locator('input[type=password]:visible').count(), 0);
});

test('split layout: an invalid E-Mail sends nothing', async t => {
    const { page, requests } = await openLogin(t, {
        layout: 'split',
        authorize: () => assert.fail('must not log in'),
    });
    const card = page.getByRole('region', { name: 'Erstes Mal hier oder anderes Gerät' });
    await card.getByLabel('E-Mail').fill('keine-adresse');
    await card.getByRole('button', { name: 'Weiter' }).click();
    await card.getByText('Gültige E-Mail Adresse angeben').waitFor();
    assert.deepEqual(requests, []);
});

test('split layout: no passkey on this device points to the new-device card', async t => {
    const { page } = await openLogin(t, {
        layout: 'split',
        authorize: () => assert.fail('must not log in'),
    });
    await page.getByRole('heading', { name: 'Anmelden bei ArztAgent' }).waitFor();
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

    await page.getByRole('button', { name: 'Mit Passkey anmelden' }).click();
    const existingCard = page.getByRole('region', { name: 'Ich habe mich hier schon angemeldet' });
    await existingCard
        .getByRole('alert')
        .filter({ hasText: 'Auf diesem Gerät wurde kein Passkey gefunden' })
        .waitFor({ timeout: 20000 });
});

test('split layout: cards stack on a phone, with the legal links below', async t => {
    const { page } = await openLogin(t, {
        layout: 'split',
        width: 390,
        height: 844,
        authorize: () => assert.fail('must not log in'),
    });
    const existing = page.getByRole('region', { name: 'Ich habe mich hier schon angemeldet' });
    const newCard = page.getByRole('region', { name: 'Erstes Mal hier oder anderes Gerät' });
    await existing.waitFor();
    const a = await existing.boundingBox();
    const b = await newCard.boundingBox();
    assert.ok(b.y > a.y + a.height, 'the new-device card is below the known-device card');
    assert.ok(a.x >= 16 && a.x + a.width <= 390 - 16, 'the card keeps a 16px gutter');
    assert.equal(
        await page.evaluate(() => document.documentElement.scrollWidth),
        390,
        'no horizontal scrolling',
    );
    await page.getByText('oder', { exact: true }).waitFor();
    await page.getByRole('link', { name: 'Datenschutz' }).waitFor();
    if (process.env.SPLIT_LOGIN_SCREENSHOTS) {
        await page.screenshot({
            path: `${process.env.SPLIT_LOGIN_SCREENSHOTS}/split-phone.png`,
            fullPage: true,
        });
    }
});

test('split layout: two cards side by side on a desktop', async t => {
    const { page } = await openLogin(t, {
        layout: 'split',
        authorize: () => assert.fail('must not log in'),
    });
    const existing = page.getByRole('region', { name: 'Ich habe mich hier schon angemeldet' });
    const newCard = page.getByRole('region', { name: 'Erstes Mal hier oder anderes Gerät' });
    await existing.waitFor();
    const a = await existing.boundingBox();
    const b = await newCard.boundingBox();
    assert.equal(Math.round(a.y), Math.round(b.y));
    assert.equal(Math.round(a.width), Math.round(b.width));
    assert.equal(Math.round(b.x - (a.x + a.width)), 32);
    assert.equal(await page.getByText('oder', { exact: true }).isVisible(), false);
    if (process.env.SPLIT_LOGIN_SCREENSHOTS) {
        await page.screenshot({
            path: `${process.env.SPLIT_LOGIN_SCREENSHOTS}/split-desktop.png`,
            fullPage: true,
        });
    }
    // keyboard order: known device first, then E-Mail and "Weiter"
    await page.keyboard.press('Tab');
    const order = [];
    for (let i = 0; i < 6; i++) {
        order.push(
            await page.evaluate(
                () =>
                    document.activeElement?.textContent?.trim() ||
                    document.activeElement?.getAttribute('name'),
            ),
        );
        await page.keyboard.press('Tab');
    }
    const passkeyIdx = order.indexOf('Mit Passkey anmelden');
    assert.ok(passkeyIdx >= 0);
    assert.ok(order.indexOf('email') > passkeyIdx);
    assert.ok(order.indexOf('Weiter') > order.indexOf('email'));
});

test('default layout keeps the upstream login form', async t => {
    const { page } = await openLogin(t, {
        layout: 'default',
        authorize: () => assert.fail('must not log in'),
    });
    await page.getByRole('heading', { name: 'ArztAgent' }).waitFor();
    await page.getByRole('textbox', { name: 'E-Mail' }).waitFor();
    assert.equal(await page.getByRole('heading', { name: 'Anmelden bei ArztAgent' }).count(), 0);
    assert.equal(await page.getByRole('button', { name: 'Mit Passkey anmelden' }).count(), 0);
});

test('split layout: the recovery link only shows with recovery codes', async t => {
    for (const recovery of [false, true]) {
        const { page } = await openLogin(t, {
            layout: 'split',
            recovery,
            authorize: () => assert.fail('must not log in'),
        });
        await page.getByRole('heading', { name: 'Anmelden bei ArztAgent' }).waitFor();
        const link = page.getByRole('link', { name: 'Mit Wiederherstellungscode fortfahren' });
        if (recovery) {
            await link.waitFor();
            assert.equal(await link.getAttribute('href'), '/auth/v1/users/recover');
        } else {
            await page
                .getByText('Passkey verloren? Wenden Sie sich an Ihre Administration.')
                .waitFor();
            assert.equal(await link.count(), 0);
        }
    }
});
