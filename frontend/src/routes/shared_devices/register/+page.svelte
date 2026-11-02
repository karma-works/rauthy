<script lang="ts">
    import Main from '$lib5/Main.svelte';
    import LangSelector from '$lib5/LangSelector.svelte';
    import ThemeSwitch from '$lib5/ThemeSwitch.svelte';
    import LegalLinks from '$lib5/LegalLinks.svelte';
    import WebauthnRequest from '$lib5/WebauthnRequest.svelte';
    import IconKey from '$icons/IconKey.svelte';
    import { useI18n } from '$state/i18n.svelte';
    import { useParam } from '$state/param.svelte';
    import { fetchGet, fetchPost } from '$api/fetch';
    import { saveCsrfToken } from '$utils/helpers';
    import { onMount } from 'svelte';
    import {
        activateDeviceKey,
        createPendingDeviceKey,
        isDeviceKeySupported,
    } from '$utils/sharedDeviceKey';
    import type { MfaPurpose } from '$api/types/mfa';
    import type { MfaModTokenResponse } from '$api/types/mfa_mod_token';
    import type { SessionInfoResponse } from '$api/types/session';
    import type { WebauthnAdditionalData, WebauthnServiceReq } from '$mfa/webauthn/types';
    import type {
        SharedDeviceRegisterRequest,
        SharedDeviceRegisterResponse,
        SharedDeviceRegistrationInfoResponse,
    } from '$api/types/shared_devices';

    /**
     * Registers this browser as a shared practice PC. Needs the session of the user who started
     * the registration and a fresh passkey, see `rauthy_data::entity::shared_devices`.
     */
    let t = useI18n();

    let regId = useParam('id').get() || '';

    type Step = 'loading' | 'confirm' | 'done' | 'noSession' | 'notFound' | 'unsupported';
    let step: Step = $state('loading');
    let info: undefined | SharedDeviceRegistrationInfoResponse = $state();
    let userId = '';
    let riskAck = $state(false);
    let showRiskRequired = $state(false);
    let isLoading = $state(false);
    let err = $state('');
    let password = $state('');
    let usePassword = $state(false);
    let mfaPurpose: undefined | MfaPurpose = $state();
    let returnUri: undefined | string = $state();

    onMount(async () => {
        if (!isDeviceKeySupported()) {
            step = 'unsupported';
            return;
        }
        if (!/^[a-zA-Z0-9]{48}$/.test(regId)) {
            step = 'notFound';
            return;
        }
        const session = await fetchGet<SessionInfoResponse>(
            '/auth/v1/oidc/sessioninfo/xsrf',
            'json',
            'noRedirect',
        );
        if (!session.body?.csrf_token || !session.body.user_id) {
            step = 'noSession';
            return;
        }
        saveCsrfToken(session.body.csrf_token);
        userId = session.body.user_id;

        const res = await fetchGet<SharedDeviceRegistrationInfoResponse>(
            `/auth/v1/shared_devices/registrations/${regId}`,
            'json',
            'noRedirect',
        );
        if (res.body) {
            info = res.body;
            step = 'confirm';
        } else if (res.status === 401) {
            step = 'noSession';
        } else {
            step = 'notFound';
        }
    });

    function onConfirm(ev: SubmitEvent) {
        ev.preventDefault();
        err = '';
        if (info?.needs_risk_ack && !riskAck) {
            showRiskRequired = true;
            return;
        }
        isLoading = true;
        if (usePassword && info?.password_allowed) {
            finishRegistration();
        } else {
            mfaPurpose = 'MfaModToken';
        }
    }

    function onMfaError(error: string) {
        mfaPurpose = undefined;
        isLoading = false;
        err = error;
    }

    async function onMfaSuccess(data?: WebauthnAdditionalData) {
        mfaPurpose = undefined;
        const svc = data as undefined | WebauthnServiceReq;
        if (!svc?.code) {
            isLoading = false;
            err = t.sharedDevice.registerErr;
            return;
        }

        const token = await fetchPost<MfaModTokenResponse>(
            `/auth/v1/users/${userId}/mfa_token`,
            { mfa_code: svc.code },
            'json',
            'noRedirect',
        );
        if (!token.body) {
            isLoading = false;
            err = t.sharedDevice.registerErr;
            return;
        }

        await finishRegistration(token.body.id);
    }

    async function finishRegistration(mfaToken?: string) {
        try {
            const key = await createPendingDeviceKey(regId);
            const payload: SharedDeviceRegisterRequest = {
                mfa_mod_token_id: mfaToken,
                password: usePassword ? password : undefined,
                public_key: key.publicKey,
                signature: key.signature,
                risk_ack: riskAck,
            };
            const res = await fetchPost<SharedDeviceRegisterResponse>(
                `/auth/v1/shared_devices/registrations/${regId}`,
                payload,
                'json',
                'noRedirect',
            );
            if (res.body) {
                await activateDeviceKey();
                returnUri = res.body.return_uri;
                step = 'done';
            } else if (res.status === 404) {
                step = 'notFound';
            } else {
                err = `${t.sharedDevice.registerErr} ${res.error?.message || ''}`.trim();
            }
        } catch (e) {
            console.error(e);
            err = t.sharedDevice.registerErr;
        }
        password = '';
        isLoading = false;
    }
</script>

<svelte:head>
    <title>{t.sharedDevice.registerTitle}</title>
</svelte:head>

<Main>
    <div class="page">
        <section class="card" aria-labelledby="register-title">
            <h1 id="register-title">{t.sharedDevice.registerTitle}</h1>

            {#if step === 'loading'}
                <p class="desc" aria-busy="true">…</p>
            {:else if step === 'unsupported'}
                <p class="desc" role="alert">{t.sharedDevice.registerUnsupported}</p>
            {:else if step === 'noSession'}
                <p class="desc" role="alert">{t.sharedDevice.registerNoSession}</p>
            {:else if step === 'notFound'}
                <p class="desc" role="alert">{t.sharedDevice.registerNotFound}</p>
            {:else if step === 'confirm' && info}
                <p class="desc">
                    {t.sharedDevice.registerDesc
                        .replace('{label}', info.label)
                        .replace('{practice}', info.practice_name)}
                </p>
                {#if info.password_allowed}
                    <label
                        ><input type="checkbox" bind:checked={usePassword} /> Mit Kontopasswort bestätigen</label
                    >
                    {#if usePassword}
                        <label for="coupling-password">Passwort des Praxiskontos</label>
                        <input
                            id="coupling-password"
                            type="password"
                            autocomplete="current-password"
                            bind:value={password}
                        />
                    {/if}
                {/if}
                <form novalidate onsubmit={onConfirm}>
                    {#if info.needs_risk_ack}
                        <div class="risk" role="note">
                            <h2>{t.sharedDevice.riskTitle}</h2>
                            <p>{t.sharedDevice.riskText}</p>
                            <label class="check">
                                <input
                                    type="checkbox"
                                    name="risk_ack"
                                    bind:checked={riskAck}
                                    onchange={() => (showRiskRequired = false)}
                                />
                                {t.sharedDevice.riskAck}
                            </label>
                            {#if showRiskRequired}
                                <p class="err" role="alert">{t.sharedDevice.riskRequired}</p>
                            {/if}
                        </div>
                    {/if}
                    <button
                        type="submit"
                        class="primary"
                        disabled={isLoading}
                        aria-busy={isLoading}
                    >
                        <IconKey width="1.2rem" />
                        {usePassword
                            ? 'Mit Passwort bestätigen und koppeln'
                            : t.sharedDevice.registerSubmit}
                    </button>
                </form>
                {#if err}
                    <p class="err" role="alert">{err}</p>
                {/if}
            {:else if step === 'done'}
                <p class="desc" role="status">{t.sharedDevice.registerDone}</p>
                {#if returnUri}
                    <a class="button primary" href={returnUri}>{t.sharedDevice.backToApp}</a>
                {/if}
            {/if}
        </section>

        {#if mfaPurpose}
            <WebauthnRequest purpose={mfaPurpose} onSuccess={onMfaSuccess} onError={onMfaError} />
        {/if}

        <div class="footer">
            <LegalLinks />
        </div>
        <ThemeSwitch absolute />
        <LangSelector absolute borderless />
    </div>
</Main>

<style>
    .page {
        width: 100%;
        min-height: 100dvh;
        padding: 48px 16px 24px;
        box-sizing: border-box;
        display: flex;
        flex-direction: column;
        align-items: center;
        background: hsla(var(--bg-high) / 0.25);
    }

    .card {
        width: 100%;
        max-width: 480px;
        padding: 32px;
        box-sizing: border-box;
        border: 1px solid hsl(var(--bg-high));
        border-radius: 12px;
        background: hsl(var(--bg));
    }

    h1 {
        margin: 0 0 12px;
        font-size: 24px;
        color: hsl(var(--text-high));
    }

    h2 {
        margin: 0 0 8px;
        font-size: 17px;
        color: hsl(var(--text-high));
    }

    .desc {
        max-width: none;
        margin: 0 0 20px;
        line-height: 1.5;
        color: hsla(var(--text) / 0.85);
    }

    form {
        display: flex;
        flex-direction: column;
    }

    .risk {
        padding: 14px 16px;
        border-left: 3px solid hsl(var(--action));
        background: hsla(var(--action) / 0.06);
    }

    .risk p {
        max-width: none;
        margin: 0 0 12px;
        line-height: 1.5;
    }

    .check {
        display: flex;
        align-items: flex-start;
        gap: 8px;
        font-weight: 500;
        cursor: pointer;
    }

    .check input {
        flex: none;
        width: 1.1rem;
        height: 1.1rem;
        margin: 3px 0 0;
    }

    button,
    .button {
        height: 48px;
        margin-top: 20px;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        border-radius: 8px;
        font: inherit;
        font-weight: 600;
        cursor: pointer;
        text-decoration: none;
    }

    .primary {
        border: 1px solid hsl(var(--action));
        background: hsl(var(--action));
        color: var(--btn-text);
    }

    .primary:disabled {
        opacity: 0.7;
        cursor: progress;
    }

    button:focus-visible,
    input:focus-visible,
    .button:focus-visible {
        outline: 2px solid hsl(var(--accent));
        outline-offset: 2px;
    }

    .err {
        max-width: none;
        margin: 12px 0 0;
        color: hsl(var(--error));
    }

    .footer {
        margin-top: auto;
        padding-top: 24px;
    }

    @media (max-width: 499px) {
        .card {
            padding: 20px;
        }
    }
</style>
