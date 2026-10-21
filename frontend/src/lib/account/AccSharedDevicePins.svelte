<script lang="ts">
    import WebauthnRequest from '$lib5/WebauthnRequest.svelte';
    import { useI18n } from '$state/i18n.svelte';
    import { fetchGet, fetchPost } from '$api/fetch';
    import { formatDateFromTs } from '$utils/helpers';
    import { onMount } from 'svelte';
    import type { UserResponse } from '$api/types/user';
    import type { MfaPurpose } from '$api/types/mfa';
    import type { MfaModTokenResponse } from '$api/types/mfa_mod_token';
    import type { WebauthnAdditionalData, WebauthnServiceReq } from '$mfa/webauthn/types';
    import type {
        SharedDevicePinInfoResponse,
        SharedDevicePinResponse,
    } from '$api/types/shared_devices';

    /**
     * The PINs for the registered practice PCs of the user's practices. A new PIN needs a
     * passkey and is shown exactly once, see `rauthy_data::entity::shared_devices`.
     */
    let { user }: { user: UserResponse } = $props();

    let t = useI18n();

    let practices: SharedDevicePinInfoResponse[] = $state([]);
    let pendingPractice: undefined | string = $state();
    let mfaPurpose: undefined | MfaPurpose = $state();
    let shownPin: undefined | { practice: string; pin: string } = $state();
    let err = $state('');

    onMount(fetchPins);

    async function fetchPins() {
        const res = await fetchGet<SharedDevicePinInfoResponse[]>(
            `/auth/v1/users/${user.id}/shared_device_pins`,
            'json',
            'noRedirect',
        );
        // `404` without `shared_devices.enable`
        practices = res.body || [];
    }

    function onNewPin(practiceId: string) {
        err = '';
        shownPin = undefined;
        pendingPractice = practiceId;
        mfaPurpose = 'MfaModToken';
    }

    function onMfaError(error: string) {
        mfaPurpose = undefined;
        pendingPractice = undefined;
        err = error;
    }

    async function onMfaSuccess(data?: WebauthnAdditionalData) {
        mfaPurpose = undefined;
        const practiceId = pendingPractice;
        pendingPractice = undefined;
        const svc = data as undefined | WebauthnServiceReq;
        if (!svc?.code || !practiceId) {
            err = t.sharedDevice.pinErr;
            return;
        }

        const token = await fetchPost<MfaModTokenResponse>(
            `/auth/v1/users/${user.id}/mfa_token`,
            { mfa_code: svc.code },
            'json',
            'noRedirect',
        );
        if (!token.body) {
            err = t.sharedDevice.pinErr;
            return;
        }

        const res = await fetchPost<SharedDevicePinResponse>(
            `/auth/v1/users/${user.id}/shared_device_pins/${practiceId}`,
            { mfa_mod_token_id: token.body.id },
            'json',
            'noRedirect',
        );
        if (res.body) {
            const name = practices.find(p => p.practice_id === practiceId)?.practice_name || '';
            shownPin = { practice: name, pin: res.body.pin };
            await fetchPins();
        } else if (res.status === 429) {
            err = t.sharedDevice.pinTooMany;
        } else {
            err = t.sharedDevice.pinErr;
        }
    }
</script>

{#if practices.length > 0}
    <section class="pins" aria-labelledby="acc-pins-title">
        <h3 id="acc-pins-title">{t.sharedDevice.pinsTitle}</h3>
        <p class="desc">{t.sharedDevice.pinsDesc}</p>

        {#each practices as p (p.practice_id)}
            <div class="row">
                <div class="info">
                    <b>{p.practice_name}</b>
                    <span class="state">
                        {#if p.pin_created}
                            {t.sharedDevice.pinCreated.replace(
                                '{date}',
                                formatDateFromTs(p.pin_created),
                            )}
                        {:else}
                            {t.sharedDevice.pinNone}
                        {/if}
                    </span>
                </div>
                <button
                    type="button"
                    class="btn"
                    disabled={!!pendingPractice}
                    aria-busy={pendingPractice === p.practice_id}
                    onclick={() => onNewPin(p.practice_id)}
                >
                    {p.pin_created ? t.sharedDevice.pinNew : t.sharedDevice.pinCreate}
                </button>
            </div>
        {/each}

        {#if shownPin}
            <div class="shown" role="status">
                <p>{t.sharedDevice.pinShow.replace('{practice}', shownPin.practice)}</p>
                <p class="pin font-mono" aria-label={shownPin.pin.split('').join(' ')}>
                    {shownPin.pin}
                </p>
                <p class="hint">{t.sharedDevice.pinShowHint}</p>
                <button type="button" class="btn" onclick={() => (shownPin = undefined)}>
                    {t.sharedDevice.pinDone}
                </button>
            </div>
        {/if}

        {#if err}
            <p class="err" role="alert">{err}</p>
        {/if}
    </section>

    {#if mfaPurpose}
        <WebauthnRequest purpose={mfaPurpose} onSuccess={onMfaSuccess} onError={onMfaError} />
    {/if}
{/if}

<style>
    .pins {
        max-width: 30rem;
        margin: 2rem 0 1rem;
    }

    h3 {
        margin: 0 0 0.5rem;
    }

    .desc {
        margin: 0 0 1rem;
        color: hsla(var(--text) / 0.8);
    }

    .row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        padding: 0.5rem 0;
        border-top: 1px solid hsl(var(--bg-high));
    }

    .info {
        display: flex;
        flex-direction: column;
    }

    .state {
        font-size: 0.9rem;
        color: hsla(var(--text) / 0.8);
    }

    .btn {
        padding: 0.4rem 0.8rem;
        border: 1px solid hsl(var(--action));
        border-radius: var(--border-radius);
        background: hsl(var(--action));
        color: var(--btn-text);
        font: inherit;
        cursor: pointer;
        white-space: nowrap;
    }

    .btn:disabled {
        opacity: 0.7;
        cursor: progress;
    }

    .btn:focus-visible {
        outline: 2px solid hsl(var(--accent));
        outline-offset: 2px;
    }

    .shown {
        margin-top: 1rem;
        padding: 1rem;
        border: 1px solid hsl(var(--action));
        border-radius: var(--border-radius);
    }

    .shown p {
        margin: 0 0 0.5rem;
    }

    .pin {
        font-size: 2rem;
        letter-spacing: 0.5em;
    }

    .hint {
        font-size: 0.9rem;
        color: hsla(var(--text) / 0.8);
    }

    .err {
        color: hsl(var(--error));
    }
</style>
