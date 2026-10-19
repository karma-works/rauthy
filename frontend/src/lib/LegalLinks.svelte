<script lang="ts">
    import Template from '$lib5/Template.svelte';
    import { useI18n } from '$state/i18n.svelte';
    import { TPL_LEGAL_LINKS } from '$utils/constants';
    import type { LegalLinksTemplate } from '$api/templates/LegalLinks';

    let { absolute }: { absolute?: boolean } = $props();

    let t = useI18n();

    let legal: LegalLinksTemplate = $state({});
    let links = $derived(
        [
            { href: legal.imprint_url, label: t.legal.imprint },
            { href: legal.privacy_url, label: t.legal.privacy },
            { href: legal.help_url, label: t.legal.help },
        ].filter(l => !!l.href),
    );
</script>

<Template id={TPL_LEGAL_LINKS} bind:value={legal} />

{#if links.length > 0}
    <nav class="legal" class:absolute aria-label={t.legal.imprint}>
        {#each links as link (link.label)}
            <a href={link.href} target="_blank" rel="noopener noreferrer">{link.label}</a>
        {/each}
    </nav>
{/if}

<style>
    .legal {
        display: flex;
        flex-wrap: wrap;
        gap: 0.75rem;
        font-size: 0.9rem;
    }

    .legal a {
        color: hsla(var(--text) / 0.8);
    }

    .absolute {
        position: absolute;
        bottom: 0.35rem;
        right: 0.75rem;
    }
</style>
