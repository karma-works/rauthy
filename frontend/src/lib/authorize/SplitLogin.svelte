<script lang="ts" module>
    export type SplitCard = 'existing' | 'new';
</script>

<script lang="ts">
    import ClientLogo from '$lib5/ClientLogo.svelte';
    import IconComputerDesktop from '$icons/IconComputerDesktop.svelte';
    import IconEnvelope from '$icons/IconEnvelope.svelte';
    import IconKey from '$icons/IconKey.svelte';
    import { useI18n } from '$state/i18n.svelte';

    let {
        clientId,
        clientName,
        clientLogoUpdated,
        email = $bindable(),
        loadingCard,
        disabled,
        recoveryEnabled = false,
        errExisting,
        errNew,
        errRecoveryLink = false,
        onExisting,
        onNew,
    }: {
        clientId?: string;
        clientName: string;
        clientLogoUpdated?: number;
        email: string;
        /** the card whose login is running */
        loadingCard?: SplitCard;
        disabled: boolean;
        /** `webauthn.recovery_codes` */
        recoveryEnabled?: boolean;
        errExisting: string;
        errNew: string;
        /** shows the recovery link with the error, for a passkey the backend does not know */
        errRecoveryLink?: boolean;
        onExisting: () => void;
        onNew: () => void;
    } = $props();

    let t = useI18n();

    let emailInvalid = $state(false);
    let busy = $derived(disabled || loadingCard !== undefined);

    function submitNew(ev: SubmitEvent) {
        ev.preventDefault();
        const form = ev.currentTarget as HTMLFormElement;
        emailInvalid = !form.checkValidity();
        if (!emailInvalid) {
            onNew();
        }
    }
</script>

<div class="split">
    <header>
        {#if clientId}
            <div class="logo">
                <ClientLogo {clientId} updated={clientLogoUpdated} />
            </div>
        {/if}
        <h1>{t.splitLogin.title.replace('{client}', clientName)}</h1>
        <p class="intro">{t.splitLogin.intro}</p>
    </header>

    <div class="cards">
        <section class="card" aria-labelledby="split-existing">
            <div class="tag existing">
                <span class="tagIcon"><IconComputerDesktop width="1.25rem" /></span>
                {t.splitLogin.existingTag}
            </div>
            <h2 id="split-existing">{t.splitLogin.existingTitle}</h2>
            <p class="desc">{t.splitLogin.existingDesc}</p>
            <div class="grow"></div>
            <button
                type="button"
                class="primary"
                disabled={busy}
                aria-busy={loadingCard === 'existing'}
                onclick={onExisting}
            >
                <IconKey width="1.2rem" />
                {t.splitLogin.existingButton}
            </button>
            {#if errExisting}
                <p class="err" role="alert">
                    {errExisting}
                    {#if errRecoveryLink && recoveryEnabled}
                        <a href="/auth/v1/users/recover">{t.splitLogin.lostLink}</a>
                    {/if}
                </p>
            {/if}
        </section>

        <div class="or" aria-hidden="true"><span>{t.splitLogin.or}</span></div>

        <section class="card" aria-labelledby="split-new">
            <div class="tag new">
                <span class="tagIcon"><IconEnvelope width="1.25rem" /></span>
                {t.splitLogin.newTag}
            </div>
            <h2 id="split-new">{t.splitLogin.newTitle}</h2>
            <p class="desc">{t.splitLogin.newDesc}</p>
            <form novalidate onsubmit={submitNew}>
                <label for="split-email">{t.common.email}</label>
                <input
                    id="split-email"
                    type="email"
                    name="email"
                    autocomplete="email"
                    placeholder={t.splitLogin.emailPlaceholder}
                    required
                    maxlength="256"
                    bind:value={email}
                    disabled={busy}
                    aria-invalid={emailInvalid}
                    aria-describedby={emailInvalid ? 'split-email-err' : undefined}
                    oninput={() => (emailInvalid = false)}
                />
                {#if emailInvalid}
                    <p id="split-email-err" class="err">{t.authorize.validEmail}</p>
                {/if}
                <button
                    type="submit"
                    class="secondary"
                    disabled={busy}
                    aria-busy={loadingCard === 'new'}
                >
                    {t.splitLogin.continue}
                </button>
            </form>
            {#if errNew}
                <p class="err" role="alert">
                    {errNew}
                    {#if errRecoveryLink && recoveryEnabled}
                        <a href="/auth/v1/users/recover">{t.splitLogin.lostLink}</a>
                    {/if}
                </p>
            {/if}
        </section>
    </div>

    <p class="lost">
        {#if recoveryEnabled}
            {t.splitLogin.lostPrefix}
            <a href="/auth/v1/users/recover">{t.splitLogin.lostLink}</a>
            {t.splitLogin.lostSuffix}
        {:else}
            {t.splitLogin.lost}
        {/if}
    </p>
</div>

<style>
    .split {
        width: 100%;
        max-width: calc(2 * 440px + 32px);
        margin: 0 auto;
        padding: 48px 16px 24px;
        box-sizing: border-box;
        color: hsl(var(--text));
        font-size: 16px;
    }

    header {
        text-align: center;
        margin-bottom: 40px;
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
        margin: 0 0 12px;
        font-size: 28px;
        line-height: 1.25;
        font-weight: 600;
        color: hsl(var(--text-high));
    }

    .intro {
        max-width: none;
        margin: 0;
        color: hsla(var(--text) / 0.8);
    }

    .cards {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 32px;
    }

    .card {
        display: flex;
        flex-direction: column;
        padding: 32px;
        border: 1px solid hsl(var(--bg-high));
        border-radius: 12px;
        background: hsl(var(--bg));
    }

    .tag {
        display: flex;
        align-items: center;
        gap: 12px;
        font-size: 13px;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }

    .tagIcon {
        width: 40px;
        height: 40px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .tag.existing {
        color: hsl(var(--action));
    }

    .tag.existing .tagIcon {
        background: hsla(var(--action) / 0.12);
    }

    .tag.new {
        color: hsl(var(--accent));
    }

    .tag.new .tagIcon {
        background: hsla(var(--accent) / 0.15);
    }

    h2 {
        margin: 20px 0 12px;
        font-size: 21px;
        line-height: 1.35;
        font-weight: 600;
        color: hsl(var(--text-high));
    }

    .desc {
        margin: 0 0 24px;
        line-height: 1.5;
        color: hsla(var(--text) / 0.8);
    }

    .grow {
        flex: 1;
    }

    form {
        display: flex;
        flex-direction: column;
    }

    label {
        margin-bottom: 6px;
        font-size: 15px;
        font-weight: 500;
    }

    input {
        height: 48px;
        padding: 0 14px;
        box-sizing: border-box;
        border: 1px solid hsla(var(--text) / 0.45);
        border-radius: 8px;
        background: hsl(var(--bg));
        color: hsl(var(--text-high));
        font: inherit;
    }

    input[aria-invalid='true'] {
        border-color: hsl(var(--error));
    }

    button {
        height: 48px;
        margin-top: 16px;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        border-radius: 8px;
        font: inherit;
        font-weight: 600;
        cursor: pointer;
    }

    button:disabled {
        cursor: not-allowed;
        opacity: 0.7;
    }

    button[aria-busy='true'] {
        cursor: progress;
    }

    .primary {
        border: 1px solid hsl(var(--action));
        background: hsl(var(--action));
        color: var(--btn-text);
    }

    .secondary {
        border: 1px solid hsl(var(--action));
        background: transparent;
        color: hsl(var(--action));
    }

    button:focus-visible,
    input:focus-visible {
        outline: 2px solid hsl(var(--accent));
        outline-offset: 2px;
    }

    .err {
        margin: 12px 0 0;
        line-height: 1.4;
        color: hsl(var(--error));
    }

    .or {
        display: none;
    }

    .lost a {
        color: hsl(var(--action));
    }

    .lost {
        max-width: none;
        margin: 32px 0 0;
        text-align: center;
        font-size: 15px;
        color: hsla(var(--text) / 0.8);
    }

    @media (max-width: 719px) {
        .split {
            padding-top: 24px;
        }

        header {
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 12px;
            text-align: left;
        }

        .logo {
            width: 40px;
            height: 40px;
            margin: 0;
            flex-shrink: 0;
            border-radius: 8px;
        }

        .logo :global(.logo) {
            height: 40px;
        }

        h1 {
            margin: 0;
            font-size: 22px;
        }

        .intro {
            display: none;
        }

        .cards {
            grid-template-columns: 1fr;
            gap: 16px;
        }

        .card {
            padding: 20px;
        }

        .desc,
        .grow {
            display: none;
        }

        h2 {
            margin: 12px 0 16px;
        }

        .or {
            display: flex;
            align-items: center;
            gap: 12px;
            color: hsla(var(--text) / 0.7);
            font-size: 14px;
        }

        .or::before,
        .or::after {
            content: '';
            flex: 1;
            height: 1px;
            background: hsl(var(--bg-high));
        }

        .lost {
            margin-top: 24px;
        }
    }
</style>
