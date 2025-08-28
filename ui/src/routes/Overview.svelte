<script>
  import { onMount } from 'svelte'
  import { getOverview } from '../lib/api'
  let overview = null
  let err = null
  async function load() {
    err = null
    try { overview = await getOverview() } catch (e) { err = e.message }
  }
  onMount(load)
</script>

<div class="space-y-2">
  {#if err}
    <div class="text-red-600 text-sm">{err}</div>
  {/if}
  {#if overview}
    <div class="grid grid-cols-2 gap-4">
      <div class="p-4 border rounded">
        <div class="text-slate-500 text-sm">Events</div>
        <div class="text-2xl font-semibold">{overview.events}</div>
      </div>
      <div class="p-4 border rounded">
        <div class="text-slate-500 text-sm">Alerts</div>
        <div class="text-2xl font-semibold">{overview.alerts}</div>
      </div>
    </div>
  {:else}
    <div class="text-slate-500">Loading…</div>
  {/if}
</div>

