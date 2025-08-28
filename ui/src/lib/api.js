const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8080/api'
const API_KEY = import.meta.env.VITE_API_KEY || 'change-me'

async function request(path, opts = {}) {
  const headers = opts.headers || {}
  headers['X-Api-Key'] = API_KEY
  if (opts.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json'
  const res = await fetch(`${API_BASE}${path}`, { ...opts, headers })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return await res.json()
}

export async function getOverview() {
  return request('/overview')
}
export async function getAlerts(limit = 100) {
  return request(`/alerts?limit=${limit}`)
}
export async function getSSIDs() {
  return request('/ssids')
}
export async function getDefense() {
  return request('/defense')
}
export async function postDefense(payload) {
  return request('/defense', { method: 'POST', body: JSON.stringify(payload) })
}

export function sse(url, onData) {
  const es = new EventSource(`${API_BASE}${url}`)
  es.onmessage = (ev) => { try { onData(JSON.parse(ev.data)) } catch {} }
  return es
}

