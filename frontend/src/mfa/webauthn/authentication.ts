import { arrBufToBase64UrlSafe, promiseTimeout } from '$utils/helpers';
import { fetchPost } from '$api/fetch';
import type {
    WebauthnAdditionalData,
    WebauthnAuthFinishRequest,
    WebauthnAuthStartRequest,
    WebauthnAuthStartResponse,
} from '$mfa/webauthn/types.ts';
import { base64UrlSafeToArrBuf } from './utils';
import type { MfaPurpose } from '$api/types/mfa.js';

/** WebAuthn L3 `hints`: which authenticator the browser should offer first. Ignored if unknown. */
export type PasskeyHint = 'client-device' | 'hybrid' | 'security-key';

export interface WebauthnAuthResult {
    error?: string;
    data?: WebauthnAdditionalData;
    /**
     * The backend does not know the credential the browser offered in a discoverable login:
     * it was deleted, or the account is gone. The login page explains this and offers the
     * recovery instead of a generic error.
     */
    unknownCredential?: boolean;
}

/**
 * Tells the browser / password manager that a credential is unknown, so it can hide or remove
 * it (WebAuthn L3). Feature-detected, errors are ignored.
 */
export function signalUnknownCredential(rpId: string | undefined, credentialId: string) {
    const pkc = globalThis.PublicKeyCredential as unknown as
        | {
              signalUnknownCredential?: (opts: {
                  rpId: string;
                  credentialId: string;
              }) => Promise<void>;
          }
        | undefined;
    if (typeof pkc?.signalUnknownCredential !== 'function') {
        return;
    }
    try {
        pkc.signalUnknownCredential({
            rpId: rpId || window.location.hostname,
            credentialId,
        }).catch(() => {});
    } catch (_e) {
        // not supported in this form, nothing to do
    }
}

/**
 * The `code` of each ceremony this page has already sent to `/webauthn_finish`. The backend
 * consumes the code with the first request, so a second one could only fail with "Webauthn Data
 * not found" and hide the first error.
 */
const finishedCodes = new Set<string>();

/** Must match `rauthy_data::entity::webauthn::passkey::UNKNOWN_CREDENTIAL`. */
const UNKNOWN_CREDENTIAL_MSG = 'Unknown Credential';

export async function webauthnAuth(
    purpose: MfaPurpose,
    errorI18nInvalidKey: string,
    errorI18nTimeout: string,
    resetUserId?: string,
    hints?: PasskeyHint[],
): Promise<WebauthnAuthResult> {
    let startUri = '/auth/v1/users/webauthn_start';
    if (purpose === 'PasswordReset') {
        if (!resetUserId) {
            return { error: 'Missing user context for password reset' };
        }
        startUri = `/auth/v1/users/${encodeURIComponent(resetUserId)}/webauthn/auth/start`;
    }

    let payloadStart: WebauthnAuthStartRequest = {
        purpose,
    };
    let res = await fetchPost<WebauthnAuthStartResponse>(startUri, payloadStart);
    if (res.error) {
        console.error(res.error);
        return {
            error: res.error.message || 'Error starting the Authentication',
        };
    }
    if (!res.body) {
        let error = 'Did not receive a valid webauthn body';
        console.error(error);
        return { error };
    }

    let resp = res.body;
    // We need to apply a small hack to make TS happy.
    // The browser expects ArrayBuffers in some places, but the backend sends them as base64 encoded data,
    // which we will decode properly in the following lines.
    let challenge = resp.rcr as unknown as CredentialRequestOptions;
    if (!challenge.publicKey) {
        let error = 'no publicKey in challenge from the backend';
        console.error(error);
        return {
            error,
        };
    }

    // convert base64 into ArrayBuffers
    challenge.publicKey.challenge = base64UrlSafeToArrBuf(challenge.publicKey.challenge);
    if (challenge.publicKey.allowCredentials) {
        for (let cred of challenge.publicKey.allowCredentials) {
            cred.id = base64UrlSafeToArrBuf(cred.id);
        }
    }

    if (hints && hints.length > 0) {
        // not yet part of the TS DOM types
        (
            challenge.publicKey as PublicKeyCredentialRequestOptions & { hints?: PasskeyHint[] }
        ).hints = hints;
    }

    // prompt for the passkey and get its public key
    const exp = (resp.exp - 1) * 1000;
    const expTime = new Date().getTime() + exp;
    let credential: Credential;
    try {
        const cred = await promiseTimeout(navigator.credentials.get(challenge), exp);
        if (cred) {
            credential = cred;
        } else {
            return {
                error: errorI18nInvalidKey,
            };
        }
    } catch (e) {
        const timeout = new Date().getTime() >= expTime;
        return {
            error: timeout ? errorI18nTimeout : errorI18nInvalidKey,
        };
    }

    // The backend expects base64 url safe strings instead of array buffers.
    // The values we need to modify are not publicly exported in the TS type though, but they exist.
    let payloadFinish: WebauthnAuthFinishRequest = {
        code: resp.code,
        data: {
            id: credential.id,
            // @ts-ignore the `response.rawId` actually exists
            rawId: arrBufToBase64UrlSafe(credential.rawId),
            response: {
                // @ts-ignore the `response.authenticatorData` actually exists
                authenticatorData: arrBufToBase64UrlSafe(credential.response.authenticatorData),
                // @ts-ignore the `response.clientDataJSON` actually exists
                clientDataJSON: arrBufToBase64UrlSafe(credential.response.clientDataJSON),
                // @ts-ignore the `response.signature` actually exists
                signature: arrBufToBase64UrlSafe(credential.response.signature),
                // @ts-ignore the `response.userHandle` actually exists
                userHandle: credential.response.userHandle
                    ? // @ts-ignore the `response.userHandle` actually exists
                      arrBufToBase64UrlSafe(credential.response.userHandle)
                    : undefined,
            },
            // @ts-ignore the `response.getClientExtensionResults()` actually exists
            extensions: credential.getClientExtensionResults(),
            type: credential.type,
        },
    };

    // finish the ceremony, exactly once per code
    if (finishedCodes.has(resp.code)) {
        console.error('webauthn_finish for this code has already been sent');
        return { error: errorI18nInvalidKey };
    }
    finishedCodes.add(resp.code);
    // A 401 here is a failed ceremony, not an expired session. Reloading the page would hide
    // the error, so it is shown like any other.
    let resFinish = await fetchPost<WebauthnAdditionalData>(
        `/auth/v1/users/webauthn_finish`,
        payloadFinish,
        'json',
        'noRedirect',
    );
    // 202 -> normal success
    // 205 -> Webauthn success during login, but needs user values updates
    // 206 -> Webauthn success during login, but needs additional ToS update accept
    // 404 -> Only for a discoverable login, when the credential is not (or no longer) registered
    if (resFinish.status === 202 || resFinish.status === 206) {
        return {
            data: resFinish.body,
        };
    } else if (resFinish.status === 205) {
        return {};
    } else if (resFinish.status === 404 && resFinish.error?.message === UNKNOWN_CREDENTIAL_MSG) {
        // Only for the exact backend answer: any other 404 (a proxy, for instance) must never
        // make the browser hide a passkey that still works.
        signalUnknownCredential(challenge.publicKey.rpId, credential.id);
        return {
            error: errorI18nInvalidKey,
            unknownCredential: true,
        };
    } else if (resFinish.status === 401) {
        console.error(resFinish.error);
        return {
            error: errorI18nInvalidKey,
        };
    } else {
        console.error(resFinish);
        return {
            error: resFinish.error?.message || 'Authentication Error',
        };
    }
}
