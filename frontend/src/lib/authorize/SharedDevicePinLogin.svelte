<script lang="ts">
    import ClientLogo from '$lib5/ClientLogo.svelte';
    import IconKey from '$icons/IconKey.svelte';
    import { useI18n } from '$state/i18n.svelte';
    import { fetchPost, type IResponse } from '$api/fetch';
    import { signWithDeviceKey } from '$utils/sharedDeviceKey';
    import type {
        PinLoginErrorResponse,
        PinLoginRequest,
        SharedDeviceChallengeResponse,
        SharedDeviceTemplate,
    } from '$api/types/shared_devices';

    /**
     * The login on a registered shared device: 4 digits, signed with the device key, see
     * `rauthy_data::entity::shared_devices`. A locked device is unlocked by a passkey login of
     * a member.
     */
    let {
        device,
        clientId,
        clientName,
        clientLogoUpdated,
        loginParams,
        onAuthRes,
        onPasskey,
    }: {
        device: SharedDeviceTemplate;
        clientId?: string;
        clientName: string;
        clientLogoUpdated?: number;
        /** the parameters of the authorize request, without the PIN parts */
        loginParams: () => Omit<PinLoginRequest, 'pin' | 'challenge_id' | 'signature'>;
        /** a response that is not a PIN error, handled like the one of `POST /oidc/authorize` */
        onAuthRes: (res: IResponse<any>) => void;
        /** the normal passkey login, which also unlocks a locked device */
        onPasskey: () => void;
    } = $props();

    let t = useI18n();

    const PIN_LEN = 4;

    let pin = $state('');
    let role = $state('staff');
    let err = $state('');
    let busy = $state(false);
    // svelte-ignore state_referenced_locally
    let locked = $state(device.locked);
    let refInput: undefined | HTMLInputElement = $state();

    $effect(() => {
        if (!locked && device.pin) {
            refInput?.focus();
        }
    });

    function onInput() {
        pin = pin.replace(/[^0-9]/g, '').slice(0, PIN_LEN);
        err = '';
        if (pin.length === PIN_LEN) {
            submit();
        }
    }

    async function onSubmit(ev: SubmitEvent) {
        ev.preventDefault();
        await submit();
    }

    async function submit() {
        if (busy) {
            return;
        }
        if (!new RegExp(`^[0-9]{${PIN_LEN}}$`).test(pin)) {
            err = t.sharedDevice.pinFormat;
            return;
        }
        busy = true;
        err = '';

        const ch = await fetchPost<SharedDeviceChallengeResponse>(
            '/auth/v1/shared_devices/challenge',
            undefined,
            'json',
            'noRedirect',
        );
        let signature: undefined | string;
        if (ch.body) {
            signature = await signWithDeviceKey(ch.body.challenge).catch(e => {
                console.error(e);
                return undefined;
            });
        }
        if (!ch.body || !signature) {
            err = t.sharedDevice.invalidDevice;
            pin = '';
            busy = false;
            return;
        }

        const payload: PinLoginRequest = {
            ...loginParams(),
            role: device.roles_enabled ? role : undefined,
            pin,
            challenge_id: ch.body.id,
            signature,
        };
        pin = '';
        const res = await fetchPost<undefined>(
            '/auth/v1/oidc/authorize/pin',
            payload,
            'json',
            'noRedirect',
        );
        busy = false;

        if (res.status >= 200 && res.status < 300) {
            onAuthRes(res);
            return;
        }
        const e = res.error as undefined | PinLoginErrorResponse;
        if (res.status === 423 || e?.error === 'locked') {
            if (device.roles_enabled) {
                err = 'Diese Rolle ist auf diesem Gerät für fünf Minuten gesperrt.';
            } else {
                locked = true;
            }
        } else if (e?.error === 'wrong_pin') {
            err = t.sharedDevice.wrongPin.replace('{n}', String(e.remaining ?? 0));
        } else if (e?.error === 'invalid_device') {
            err = t.sharedDevice.invalidDevice;
        } else if (res.status === 403) {
            err = t.sharedDevice.forbidden;
        } else {
            onAuthRes(res);
        }
        refInput?.focus();
    }
</script>

<div class="page">
    <section class="card" aria-labelledby="pin-title">
        {#if clientId}
            <div class="logo">
                <ClientLogo {clientId} updated={clientLogoUpdated} />
            </div>
        {/if}
        <h1 id="pin-title">{t.sharedDevice.pinTitle}</h1>
        <p class="device">{clientName} · {device.label} · {device.practice}</p>

        {#if locked && !device.roles_enabled}
            <div class="locked" role="alert">
                <p>{t.sharedDevice.locked}</p>
            </div>
            <button type="button" class="primary" onclick={onPasskey}>
                <IconKey width="1.2rem" />
                {t.sharedDevice.unlock}
            </button>
        {:else if device.pin}
            <form novalidate onsubmit={onSubmit}>
                {#if device.roles_enabled}
                    <label for="practice-role">Rolle wählen</label>
                    <select
                        id="practice-role"
                        bind:value={role}
                        disabled={busy}
                        onchange={() => {
                            pin = '';
                            err = '';
                            locked = false;
                        }}
                    >
                        <option value="staff">Praxismitarbeit</option>
                        <option value="management">Praxismanagement</option>
                        <option value="administration">Praxisadministration</option>
                    </select>
                {/if}
                <label for="shared-device-pin">{t.sharedDevice.pinLabel}</label>
                <input
                    bind:this={refInput}
                    id="shared-device-pin"
                    class="pin font-mono"
                    type="password"
                    name="pin"
                    inputmode="numeric"
                    autocomplete="off"
                    maxlength={PIN_LEN}
                    pattern="[0-9]{4}"
                    required
                    aria-describedby="shared-device-pin-hint"
                    aria-invalid={!!err}
                    bind:value={pin}
                    oninput={onInput}
                    disabled={busy}
                />
                <p id="shared-device-pin-hint" class="hint">{t.sharedDevice.pinHint}</p>
                <button type="submit" class="primary" disabled={busy} aria-busy={busy}>
                    {t.sharedDevice.pinSubmit}
                </button>
            </form>
            {#if err}
                <p class="err" role="alert">{err}</p>
            {/if}
            <button type="button" class="link" onclick={onPasskey}>
                {t.sharedDevice.usePasskey}
            </button>
        {:else}
            <p class="hint">{t.sharedDevice.passkeyNeeded}</p>
            <button type="button" class="primary" onclick={onPasskey}>
                <IconKey width="1.2rem" />
                {t.sharedDevice.usePasskey}
            </button>
        {/if}
    </section>
</div>

<style>
    .page {
        width: 100%;
        padding: 48px 16px 24px;
        box-sizing: border-box;
        display: flex;
        justify-content: center;
    }

    .card {
        width: 100%;
        max-width: 400px;
        padding: 32px;
        box-sizing: border-box;
        border: 1px solid hsl(var(--bg-high));
        border-radius: 12px;
        background: hsl(var(--bg));
        text-align: center;
    }

    .logo {
        width: 56px;
        height: 56px;
        margin: 0 auto 16px;
        border-radius: 12px;
        overflow: hidden;
        background: hsl(var(--bg-high));
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .logo :global(.logo) {
        height: 56px;
        margin: 0;
    }

    .logo :global(img) {
        max-width: 100%;
        max-height: 100%;
    }

    h1 {
        margin: 0 0 8px;
        font-size: 24px;
        color: hsl(var(--text-high));
    }

    .device {
        max-width: none;
        margin: 0 0 24px;
        color: hsla(var(--text) / 0.8);
    }

    form {
        display: flex;
        flex-direction: column;
        text-align: left;
    }

    label {
        margin-bottom: 6px;
        font-weight: 500;
    }

    .pin {
        height: 56px;
        padding: 0 14px;
        box-sizing: border-box;
        border: 1px solid hsla(var(--text) / 0.45);
        border-radius: 8px;
        background: hsl(var(--bg));
        color: hsl(var(--text-high));
        font-size: 28px;
        letter-spacing: 0.75em;
        text-align: center;
    }

    .hint {
        max-width: none;
        margin: 8px 0 0;
        font-size: 15px;
        color: hsla(var(--text) / 0.8);
    }

    button {
        height: 48px;
        margin-top: 20px;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        width: 100%;
        border-radius: 8px;
        font: inherit;
        font-weight: 600;
        cursor: pointer;
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

    .link {
        height: auto;
        margin-top: 16px;
        padding: 0;
        border: none;
        background: none;
        color: hsl(var(--action));
        text-decoration: underline;
        font-weight: 500;
    }

    button:focus-visible,
    input:focus-visible {
        outline: 2px solid hsl(var(--accent));
        outline-offset: 2px;
    }

    .locked {
        padding: 12px 14px;
        border-left: 3px solid hsl(var(--error));
        background: hsla(var(--error) / 0.08);
        text-align: left;
    }

    .locked p {
        max-width: none;
        margin: 0;
    }

    .err {
        max-width: none;
        margin: 16px 0 0;
        color: hsl(var(--error));
    }

    @media (max-width: 499px) {
        .card {
            padding: 20px;
        }
    }
</style>
