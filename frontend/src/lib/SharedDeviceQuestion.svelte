<script lang="ts">
    import Template from '$lib5/Template.svelte';
    import { useI18n } from '$state/i18n.svelte';
    import { TPL_ASK_SHARED_DEVICE } from '$utils/constants';
    import type { PasskeyHint, SharedDeviceChoice } from '$mfa/webauthn/types.ts';
    import { genKey } from '$utils/helpers';

    /**
     * Asks before a passkey registration whether this computer is shared, if
     * `webauthn.ask_shared_device` is enabled. For "yes" and "don't know", the browser is asked
     * to offer a smartphone or a security key first, unless this computer should be used anyway.
     */
    let {
        enabled = $bindable(false),
        choice = $bindable(),
        hints = $bindable(),
        showRequired = false,
    }: {
        enabled?: boolean;
        choice?: SharedDeviceChoice;
        hints?: PasskeyHint[];
        showRequired?: boolean;
    } = $props();

    let t = useI18n();
    let name = genKey();

    let useThisDevice = $state(false);
    let warn = $derived(choice === 'yes' || choice === 'unknown');

    $effect(() => {
        hints = warn && !useThisDevice ? ['hybrid', 'security-key'] : undefined;
    });

    let options: { value: SharedDeviceChoice; label: string }[] = $derived([
        { value: 'yes', label: t.passkeyDevice.sharedYes },
        { value: 'no', label: t.passkeyDevice.sharedNo },
        { value: 'unknown', label: t.passkeyDevice.sharedUnknown },
    ]);
</script>

<Template id={TPL_ASK_SHARED_DEVICE} bind:value={enabled} />

{#if enabled}
    <fieldset class="shared" aria-describedby="{name}-hint">
        <legend>{t.passkeyDevice.sharedQuestion}</legend>
        <p id="{name}-hint" class="hint">{t.passkeyDevice.sharedQuestionHint}</p>
        {#each options as opt (opt.value)}
            <label class="opt">
                <input type="radio" {name} value={opt.value} bind:group={choice} />
                {opt.label}
            </label>
        {/each}
        {#if showRequired && !choice}
            <p class="err" role="alert">{t.passkeyDevice.sharedRequired}</p>
        {/if}
        {#if warn}
            <div class="warn" role="note">
                <p>{t.passkeyDevice.sharedWarning}</p>
                <label class="opt">
                    <input type="checkbox" bind:checked={useThisDevice} />
                    {t.passkeyDevice.useThisDevice}
                </label>
            </div>
        {/if}
    </fieldset>
{/if}

<style>
    .shared {
        max-width: 30rem;
        margin: 0.5rem 0 1rem;
        padding: 0;
        border: none;
    }

    legend {
        padding: 0;
        font-weight: bold;
    }

    .hint {
        margin: 0.25rem 0 0.5rem;
        color: hsla(var(--text) / 0.8);
    }

    .opt {
        display: flex;
        align-items: flex-start;
        gap: 0.5rem;
        margin: 0.4rem 0;
        cursor: pointer;
    }

    .opt input {
        margin-top: 0.2rem;
    }

    .warn {
        margin-top: 0.5rem;
        padding: 0.5rem 0.75rem;
        border-left: 3px solid hsl(var(--error));
        background: hsla(var(--error) / 0.06);
    }

    .warn p {
        margin: 0 0 0.25rem;
    }

    .err {
        color: hsl(var(--error));
    }
</style>
