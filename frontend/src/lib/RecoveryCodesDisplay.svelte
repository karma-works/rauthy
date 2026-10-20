<script lang="ts">
    import { useI18n } from '$state/i18n.svelte';

    /**
     * Shows freshly created recovery codes once. They are never shown again, so "Done" is only
     * possible after confirming that they have been stored.
     */
    let {
        codes,
        onDone,
    }: {
        codes: string[];
        onDone: () => void;
    } = $props();

    let t = useI18n();

    let stored = $state(false);
    let copied = $state(false);

    let text = $derived(
        `${t.recoveryCodes.fileTitle}\n\n${codes.map((c, i) => `${i + 1}. ${c}`).join('\n')}\n`,
    );

    async function copy() {
        try {
            await navigator.clipboard.writeText(text);
            copied = true;
            setTimeout(() => (copied = false), 3000);
        } catch (e) {
            console.error(e);
        }
    }

    function download() {
        const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
        const a = document.createElement('a');
        a.href = url;
        a.download = 'recovery-codes.txt';
        a.click();
        URL.revokeObjectURL(url);
    }
</script>

<section class="recoveryCodes" aria-labelledby="recovery-codes-title">
    <h2 id="recovery-codes-title">{t.recoveryCodes.title}</h2>
    <p class="desc">{t.recoveryCodes.desc}</p>

    <ol class="codes">
        {#each codes as code (code)}
            <li><span class="font-mono">{code}</span></li>
        {/each}
    </ol>

    <div class="actions">
        <button type="button" onclick={copy}>
            {copied ? t.recoveryCodes.copied : t.recoveryCodes.copy}
        </button>
        <button type="button" onclick={download}>{t.recoveryCodes.download}</button>
        <button type="button" onclick={() => window.print()}>{t.recoveryCodes.print}</button>
    </div>

    <p class="warn" role="note">{t.recoveryCodes.warning}</p>

    <label class="confirm">
        <input type="checkbox" bind:checked={stored} />
        {t.recoveryCodes.confirm}
    </label>

    <div class="done">
        <button type="button" class="primary" disabled={!stored} onclick={onDone}>
            {t.recoveryCodes.done}
        </button>
    </div>
</section>

<style>
    .recoveryCodes {
        max-width: 34rem;
        padding: 1.5rem;
        border: 1px solid hsl(var(--bg-high));
        border-radius: 12px;
        background: hsl(var(--bg));
    }

    h2 {
        margin: 0 0 0.5rem;
        font-size: 1.3rem;
    }

    .desc {
        margin: 0 0 1rem;
        color: hsla(var(--text) / 0.8);
    }

    .codes {
        margin: 0 0 1rem;
        padding: 1rem 1rem 1rem 2.5rem;
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 0.5rem 2rem;
        border: 1px solid hsl(var(--bg-high));
        border-radius: 8px;
        background: hsla(var(--bg-high) / 0.3);
        font-size: 1.05rem;
    }

    .codes li {
        margin: 0;
        color: hsla(var(--text) / 0.6);
    }

    .codes span {
        color: hsl(var(--text-high));
        letter-spacing: 0.04em;
    }

    .actions {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 0.75rem;
        margin-bottom: 1rem;
    }

    button {
        min-height: 44px;
        padding: 0 0.75rem;
        border: 1px solid hsl(var(--action));
        border-radius: 8px;
        background: transparent;
        color: hsl(var(--action));
        font: inherit;
        font-weight: 600;
        cursor: pointer;
    }

    button:disabled {
        cursor: not-allowed;
        opacity: 0.6;
    }

    button:focus-visible,
    input:focus-visible {
        outline: 2px solid hsl(var(--accent));
        outline-offset: 2px;
    }

    .primary {
        min-width: 7rem;
        background: hsl(var(--action));
        color: var(--btn-text);
    }

    .warn {
        margin: 0 0 1rem;
        padding: 0.75rem 1rem;
        border: 1px solid hsla(var(--accent) / 0.5);
        border-radius: 8px;
        background: hsla(var(--accent) / 0.08);
    }

    .confirm {
        display: flex;
        align-items: center;
        gap: 0.6rem;
        cursor: pointer;
    }

    .done {
        display: flex;
        justify-content: flex-end;
        margin-top: 1.5rem;
    }

    @media (max-width: 499px) {
        .codes {
            grid-template-columns: 1fr;
        }

        .actions {
            grid-template-columns: 1fr;
        }
    }

    @media print {
        :global(body *) {
            visibility: hidden;
        }

        .codes,
        .codes * {
            visibility: visible;
        }

        .codes {
            position: absolute;
            top: 0;
            left: 0;
        }
    }
</style>
