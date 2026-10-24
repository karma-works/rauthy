// Run with: npm run test:webauthn
// Frontend contract tests only: no backend, accounts, or network access.
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { after, before, test } from 'node:test';
import { createServer } from 'vite';
import { svelteConfig } from '../vite.config.js';

let server;
let webauthnAuth;
const storageDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');

before(async () => {
    Object.defineProperty(globalThis, 'localStorage', {
        configurable: true,
        value: { getItem: () => null },
    });
    server = await createServer({
        configFile: false,
        server: { middlewareMode: true, watch: null },
        resolve: {
            alias: Object.fromEntries(
                Object.entries(svelteConfig.alias).map(([key, path]) => [key, resolve(path)]),
            ),
        },
    });
    ({ webauthnAuth } = await server.ssrLoadModule('/src/mfa/webauthn/authentication.ts'));
});

after(async () => {
    await server?.close();
    if (storageDescriptor) {
        Object.defineProperty(globalThis, 'localStorage', storageDescriptor);
    } else {
        delete globalThis.localStorage;
    }
});

test('password reset starts verification for the reset user', async t => {
    const fetch = t.mock.method(globalThis, 'fetch', async (path, options) => {
        assert.equal(path, '/auth/v1/users/reset-user/webauthn/auth/start');
        assert.equal(options.method, 'POST');
        assert.deepEqual(JSON.parse(options.body), { purpose: 'PasswordReset' });
        return Response.json({ message: 'binding rejected' }, { status: 400 });
    });
    t.mock.method(console, 'error', () => {});
    const result = await webauthnAuth('PasswordReset', 'invalid key', 'timeout', 'reset-user');
    assert.equal(result.error, 'binding rejected');
    assert.equal(fetch.mock.callCount(), 1);
});

test('missing reset user fails before any request', async t => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => {
        throw new Error('must not send a reset request without its user');
    });
    for (const userId of [undefined, '']) {
        const result = await webauthnAuth('PasswordReset', 'invalid key', 'timeout', userId);
        assert.ok(result.error);
    }
    assert.equal(fetch.mock.callCount(), 0);
});

test('the reset user is encoded as one path segment', async t => {
    t.mock.method(globalThis, 'fetch', async path => {
        assert.equal(
            path,
            '/auth/v1/users/user%2Fwith%3Freserved%23characters/webauthn/auth/start',
        );
        return Response.json({ message: 'invalid user' }, { status: 400 });
    });
    t.mock.method(console, 'error', () => {});
    await webauthnAuth('PasswordReset', 'invalid key', 'timeout', 'user/with?reserved#characters');
});

test('login and authenticated service purposes keep the generic endpoint', async t => {
    // Generate login context at runtime; never persist it in a fixture or assertion output.
    const login = { Login: crypto.randomUUID() };
    for (const purpose of [login, 'Discover', 'PasswordNew', 'MfaModToken', 'Test']) {
        const fetch = t.mock.method(globalThis, 'fetch', async (path, options) => {
            assert.equal(path, '/auth/v1/users/webauthn_start');
            assert.equal(options.method, 'POST');
            assert.ok(JSON.stringify(JSON.parse(options.body).purpose) === JSON.stringify(purpose));
            return Response.json({ message: 'verification rejected' }, { status: 403 });
        });
        t.mock.method(console, 'error', () => {});
        const result = await webauthnAuth(purpose, 'invalid key', 'timeout', 'ignored-user');
        assert.equal(result.error, 'verification rejected');
        assert.equal(fetch.mock.callCount(), 1);
        t.mock.restoreAll();
    }
});

/**
 * A discoverable login up to `/webauthn_finish`, which answers with `finish`. Returns what the
 * page sent and signalled.
 */
async function discoverWithFinish(t, finish, code = crypto.randomUUID()) {
    const bytes = n => new Uint8Array(n).fill(7).buffer;
    const credential = {
        id: 'cred-id-b64url',
        rawId: bytes(16),
        type: 'public-key',
        response: {
            authenticatorData: bytes(37),
            clientDataJSON: bytes(64),
            signature: bytes(70),
            userHandle: bytes(16),
        },
        getClientExtensionResults: () => ({}),
    };
    Object.defineProperty(globalThis.navigator, 'credentials', {
        configurable: true,
        value: { get: async () => credential },
    });
    const signals = [];
    Object.defineProperty(globalThis, 'PublicKeyCredential', {
        configurable: true,
        value: {
            signalUnknownCredential: async opts => {
                signals.push(opts);
            },
        },
    });
    t.after(() => {
        delete globalThis.navigator.credentials;
        delete globalThis.PublicKeyCredential;
    });

    const calls = [];
    t.mock.method(globalThis, 'fetch', async (path, options) => {
        calls.push(path);
        if (path === '/auth/v1/users/webauthn_start') {
            return Response.json({
                code,
                exp: 30,
                rcr: {
                    publicKey: {
                        challenge: 'AAAA',
                        rpId: 'login.example.org',
                        userVerification: 'required',
                    },
                },
            });
        }
        assert.equal(path, '/auth/v1/users/webauthn_finish');
        assert.equal(JSON.parse(options.body).code, code);
        return finish();
    });
    t.mock.method(console, 'error', () => {});
    const result = await webauthnAuth('Discover', 'invalid key', 'timeout');
    return { result, calls, signals };
}

test('an unknown credential is reported and signalled to the browser', async t => {
    const { result, calls, signals } = await discoverWithFinish(t, () =>
        Response.json({ error: 'NotFound', message: 'Unknown Credential' }, { status: 404 }),
    );
    assert.equal(result.unknownCredential, true);
    assert.equal(result.error, 'invalid key');
    assert.deepEqual(signals, [{ rpId: 'login.example.org', credentialId: 'cred-id-b64url' }]);
    assert.equal(calls.filter(c => c.endsWith('/webauthn_finish')).length, 1);
});

test('any other 404 never makes the browser hide the passkey', async t => {
    const { result, signals } = await discoverWithFinish(t, () =>
        Response.json({ error: 'NotFound', message: 'Not Found' }, { status: 404 }),
    );
    assert.equal(result.unknownCredential, undefined);
    assert.deepEqual(signals, []);
});

test('a database error is no unknown credential', async t => {
    const { result, signals } = await discoverWithFinish(t, () =>
        Response.json(
            { error: 'ServiceUnavailable', message: 'Database error during the passkey lookup' },
            { status: 503 },
        ),
    );
    assert.equal(result.unknownCredential, undefined);
    assert.equal(result.error, 'Database error during the passkey lookup');
    assert.deepEqual(signals, []);
});

test('a 401 from finish shows an error instead of reloading the page', async t => {
    // `window` does not exist here: a `window.location.reload()` would throw
    const { result } = await discoverWithFinish(t, () =>
        Response.json({ error: 'Unauthorized', message: 'x' }, { status: 401 }),
    );
    assert.equal(result.error, 'invalid key');
    assert.equal(result.unknownCredential, undefined);
});

test('the same ceremony code is finished only once', async t => {
    const code = crypto.randomUUID();
    const finish = () => Response.json({ resident_key_token: 'rk' }, { status: 202 });
    const first = await discoverWithFinish(t, finish, code);
    assert.deepEqual(first.result.data, { resident_key_token: 'rk' });
    t.mock.restoreAll();

    const second = await discoverWithFinish(t, finish, code);
    assert.ok(second.result.error);
    assert.deepEqual(second.calls, ['/auth/v1/users/webauthn_start']);
});
