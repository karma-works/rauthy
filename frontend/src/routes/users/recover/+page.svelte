<script lang="ts">
    import Main from '$lib5/Main.svelte';
    import LangSelector from '$lib5/LangSelector.svelte';
    import ThemeSwitch from '$lib5/ThemeSwitch.svelte';
    import LegalLinks from '$lib5/LegalLinks.svelte';
    import PasskeyTypeSelect from '$lib/PasskeyTypeSelect.svelte';
    import { useI18n } from '$state/i18n.svelte';
    import { fetchPost } from '$api/fetch';
    import { fetchSolvePow } from '$utils/pow';
    import { webauthnReg } from '$mfa/webauthn/registration';
    import { PATTERN_USER_NAME } from '$utils/patterns';

    /**
     * "Lost your passkey?": E-Mail + recovery code, then a code from an E-Mail, then a new
     * passkey, all in this browser. See `rauthy_data::entity::recovery_codes`.
     */
    let t = useI18n();

    type Step = 'start' | 'verify' | 'register' | 'done';
    let step: Step = $state('start');
    let isLoading = $state(false);
    let err = $state('');

    let email = $state('');
    let code = $state('');
    let challengeId = '';
    let mailCode = $state('');

    let userId = '';
    let magicLinkId = '';
    let csrfToken = '';
    let passkeyName = $state('');
    let residentKey = $state(false);

    function restart() {
        step = 'start';
        err = '';
        code = '';
        mailCode = '';
        challengeId = '';
    }

    async function onStart(ev: SubmitEvent) {
        ev.preventDefault();
        if (!(ev.currentTarget as HTMLFormElement).checkValidity()) {
            err = t.authorize.validEmail;
            return;
        }
        err = '';
        isLoading = true;
        let pow = (await fetchSolvePow()) || '';
        let res = await fetchPost<{ challenge_id: string; exp: number }>(
            '/auth/v1/users/recover/start',
            { email, code, pow },
            'json',
            'noRedirect',
        );
        isLoading = false;
        if (res.body) {
            challengeId = res.body.challenge_id;
            // the same step follows for every input, valid or not
            step = 'verify';
        } else {
            err = res.error?.message || 'Error';
        }
    }

    async function onVerify(ev: SubmitEvent) {
        ev.preventDefault();
        err = '';
        isLoading = true;
        let res = await fetchPost<{ user_id: string; magic_link_id: string; csrf_token: string }>(
            '/auth/v1/users/recover/verify',
            { challenge_id: challengeId, mail_code: mailCode.trim() },
            'json',
            'noRedirect',
        );
        isLoading = false;
        if (res.body) {
            userId = res.body.user_id;
            magicLinkId = res.body.magic_link_id;
            csrfToken = res.body.csrf_token;
            step = 'register';
        } else {
            err = t.recover.invalidMailCode;
        }
    }

    async function onRegister(ev: SubmitEvent) {
        ev.preventDefault();
        err = '';
        if (!(ev.currentTarget as HTMLFormElement).checkValidity()) {
            err = t.mfa.passkeyNameErr;
            return;
        }
        isLoading = true;
        let res = await webauthnReg(
            userId,
            passkeyName,
            t.authorize.invalidKeyUsed,
            t.authorize.requestExpired,
            magicLinkId,
            csrfToken,
            undefined,
            residentKey,
        );
        isLoading = false;
        if (res.error) {
            err = `${t.mfa.errorReg} - ${res.error}`;
        } else {
            step = 'done';
        }
    }
</script>

<svelte:head>
    <title>{t.recover.title}</title>
</svelte:head>

<Main>
    <div class="page">
        <section class="card" aria-labelledby="recover-title">
            <h1 id="recover-title">{t.recover.title}</h1>

            {#if step === 'start'}
                <p class="desc">{t.recover.desc}</p>
                <form novalidate onsubmit={onStart}>
                    <label for="recover-email">{t.common.email}</label>
                    <input
                        id="recover-email"
                        type="email"
                        name="email"
                        autocomplete="email"
                        required
                        maxlength="256"
                        bind:value={email}
                        disabled={isLoading}
                    />
                    <label for="recover-code">{t.recover.code}</label>
                    <input
                        id="recover-code"
                        class="font-mono"
                        name="code"
                        autocomplete="off"
                        autocapitalize="characters"
                        spellcheck="false"
                        placeholder={t.recover.codePlaceholder}
                        required
                        maxlength="32"
                        bind:value={code}
                        disabled={isLoading}
                    />
                    <button
                        type="submit"
                        class="primary"
                        disabled={isLoading}
                        aria-busy={isLoading}
                    >
                        {t.recover.continue}
                    </button>
                </form>
                <p class="hint">{t.recover.noCodes}</p>
            {:else if step === 'verify'}
                <p class="desc" role="status">{t.recover.mailSent}</p>
                <form novalidate onsubmit={onVerify}>
                    <label for="recover-mail-code">{t.recover.mailCode}</label>
                    <input
                        id="recover-mail-code"
                        class="font-mono"
                        name="mail_code"
                        inputmode="numeric"
                        autocomplete="one-time-code"
                        required
                        maxlength="16"
                        bind:value={mailCode}
                        disabled={isLoading}
                    />
                    <button
                        type="submit"
                        class="primary"
                        disabled={isLoading}
                        aria-busy={isLoading}
                    >
                        {t.recover.confirm}
                    </button>
                </form>
                <button type="button" class="link" onclick={restart}>{t.recover.restart}</button>
            {:else if step === 'register'}
                <p class="desc">{t.recover.newPasskey}</p>
                <form novalidate onsubmit={onRegister}>
                    <PasskeyTypeSelect bind:residentKey />
                    <label for="recover-passkey-name">{t.mfa.passkeyName}</label>
                    <input
                        id="recover-passkey-name"
                        name="passkey_name"
                        autocomplete="off"
                        required
                        maxlength="32"
                        pattern={PATTERN_USER_NAME}
                        bind:value={passkeyName}
                        disabled={isLoading}
                    />
                    <button
                        type="submit"
                        class="primary"
                        disabled={isLoading}
                        aria-busy={isLoading}
                    >
                        {t.mfa.register}
                    </button>
                </form>
            {:else}
                <p class="desc" role="status">{t.recover.done}</p>
                <a class="button primary" href="/auth/v1/account">{t.recover.toAccount}</a>
            {/if}

            {#if err}
                <p class="err" role="alert">{err}</p>
            {/if}
        </section>

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
        max-width: 440px;
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

    .desc,
    .hint {
        max-width: none;
        margin: 0 0 20px;
        line-height: 1.5;
        color: hsla(var(--text) / 0.85);
    }

    .hint {
        margin: 20px 0 0;
        font-size: 15px;
    }

    form {
        display: flex;
        flex-direction: column;
    }

    label {
        margin: 12px 0 6px;
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

    button,
    .button {
        height: 48px;
        margin-top: 20px;
        display: flex;
        align-items: center;
        justify-content: center;
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
    input:focus-visible,
    .button:focus-visible {
        outline: 2px solid hsl(var(--accent));
        outline-offset: 2px;
    }

    .err {
        margin: 16px 0 0;
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
