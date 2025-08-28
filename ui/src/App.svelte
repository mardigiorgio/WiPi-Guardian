<script>
  import { onMount } from 'svelte'
  import Overview from './routes/Overview.svelte'
  import Alerts from './routes/Alerts.svelte'
  import Defense from './routes/Defense.svelte'

  let tab = 'overview'
  const tabs = [
    { id: 'overview', label: 'Overview', comp: Overview },
    { id: 'alerts', label: 'Alerts', comp: Alerts },
    { id: 'defense', label: 'Defense', comp: Defense },
  ]
</script>

<div class="max-w-5xl mx-auto p-4">
  <h1 class="text-2xl font-bold mb-4">WIDS</h1>
  <nav class="flex gap-2 mb-4">
    {#each tabs as t}
      <button class="px-3 py-2 rounded border text-sm bg-white hover:bg-slate-100 {tab===t.id ? 'border-slate-900' : 'border-slate-300'}" on:click={() => tab = t.id}>
        {t.label}
      </button>
    {/each}
  </nav>
  <div class="bg-white border border-slate-200 rounded p-4">
    {#if tab === 'overview'}
      <Overview />
    {:else if tab === 'alerts'}
      <Alerts />
    {:else}
      <Defense />
    {/if}
  </div>
  <p class="text-xs text-slate-500 mt-4">API: /api — set API key in ui/src/lib/api.js</p>
  </div>

<style>
</style>

