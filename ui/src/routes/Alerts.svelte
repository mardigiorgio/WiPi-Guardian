<script>
  import { onMount } from 'svelte'
  import { getAlerts, sse } from '../lib/api'
  let alerts = []
  let err = null
  let es
  async function load() {
    try {
      alerts = await getAlerts(100)
    } catch (e) {
      err = e.message
    }
    try {
      es = sse('/stream', (msg) => {
        if (msg && msg.kind) {
          alerts = [msg, ...alerts].slice(0, 100)
        }
      })
    } catch {}
  }
  onMount(() => { load(); return () => { if (es) es.close() } })
</script>

<div class="space-y-3">
  {#if err}
    <div class="text-red-600 text-sm">{err}</div>
  {/if}
  <ul class="space-y-2">
    {#each alerts as a}
      <li class="border rounded p-3">
        <div class="text-xs text-slate-500">{a.ts || ''}</div>
        <div class="flex items-center gap-2">
          <span class="px-2 py-0.5 rounded text-white text-xs {a.severity==='critical' ? 'bg-red-600' : a.severity==='warn' ? 'bg-amber-500' : 'bg-slate-500'}">{a.severity}</span>
          <span class="font-semibold">{a.kind}</span>
        </div>
        <div class="text-sm">{a.summary}</div>
      </li>
    {/each}
    {#if alerts.length === 0}
      <li class="text-slate-500">No alerts yet.</li>
    {/if}
  </ul>
</div>

