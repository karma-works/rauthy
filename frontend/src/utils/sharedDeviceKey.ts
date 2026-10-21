import { arrBufToBase64UrlSafe } from '$mfa/webauthn/utils';

/**
 * The key of a registered shared device: a non-extractable ECDSA P-256 key pair in IndexedDB,
 * see `rauthy_data::entity::shared_devices`. Only the public key ever leaves the browser.
 */
const DB_NAME = 'rauthy-shared-device';
const STORE = 'keys';
const KEY_DEVICE = 'device';
const KEY_PENDING = 'pending';

const ALG_SIGN: EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };

function openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => req.result.createObjectStore(STORE);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function withStore<T>(
    mode: IDBTransactionMode,
    fn: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
    const db = await openDb();
    try {
        return await new Promise<T>((resolve, reject) => {
            const tx = db.transaction(STORE, mode);
            const req = fn(tx.objectStore(STORE));
            tx.oncomplete = () => resolve(req.result);
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error);
        });
    } finally {
        db.close();
    }
}

export function isDeviceKeySupported(): boolean {
    return typeof indexedDB !== 'undefined' && !!globalThis.crypto?.subtle;
}

async function sign(key: CryptoKey, msg: string): Promise<string> {
    const sig = await crypto.subtle.sign(ALG_SIGN, key, new TextEncoder().encode(msg));
    return arrBufToBase64UrlSafe(sig);
}

/**
 * Creates a new key pair, kept as pending until `activateDeviceKey()`, so that a failed
 * registration never replaces the key of an already registered device. Returns the public key
 * as an uncompressed point and the signature of `registrationId`, both base64url.
 */
export async function createPendingDeviceKey(
    registrationId: string,
): Promise<{ publicKey: string; signature: string }> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
        'sign',
        'verify',
    ]);
    await withStore('readwrite', s => s.put(pair, KEY_PENDING));
    const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
    return {
        publicKey: arrBufToBase64UrlSafe(raw),
        signature: await sign(pair.privateKey, registrationId),
    };
}

/** After a successful registration, the pending key becomes the device key. */
export async function activateDeviceKey(): Promise<void> {
    const pair = await withStore<CryptoKeyPair | undefined>('readonly', s => s.get(KEY_PENDING));
    if (!pair) {
        throw new Error('no pending device key');
    }
    await withStore('readwrite', s => s.put(pair, KEY_DEVICE));
    await withStore('readwrite', s => s.delete(KEY_PENDING));
}

/** Signs a login challenge. `undefined` if this browser has no device key. */
export async function signWithDeviceKey(challenge: string): Promise<string | undefined> {
    const pair = await withStore<CryptoKeyPair | undefined>('readonly', s => s.get(KEY_DEVICE));
    if (!pair) {
        return undefined;
    }
    return sign(pair.privateKey, challenge);
}
