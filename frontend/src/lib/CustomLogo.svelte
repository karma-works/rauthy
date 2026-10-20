<script lang="ts">
    import ClientLogo from '$lib5/ClientLogo.svelte';
    import Template from '$lib5/Template.svelte';
    import { TPL_CLIENT_LOGO_UPDATED } from '$utils/constants';

    /**
     * The logo of the `rauthy` client for pages that are not bound to a client (account, account
     * setup, device). Only shown when a custom logo has been uploaded, so that these pages stay
     * unchanged otherwise.
     */
    let { height = '56px' }: { height?: string } = $props();

    // we can't use undefined to avoid a JSON error in the Template component
    let updated = $state(-1);
</script>

<Template id={TPL_CLIENT_LOGO_UPDATED} bind:value={updated} />

{#if updated > -1}
    <div class="customLogo" style:height>
        <ClientLogo clientId="rauthy" {updated} />
    </div>
{/if}

<style>
    .customLogo {
        display: flex;
        justify-content: center;
        margin-bottom: 0.5rem;
    }

    .customLogo :global(.logo) {
        height: 100%;
    }

    .customLogo :global(img) {
        max-height: 100%;
    }
</style>
