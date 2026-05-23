// Small REST client. In dev Vite proxies /api to the backend.
// In production the nginx container proxies /api and /ws to the backend.

const baseHeaders = { 'Content-Type': 'application/json' }

async function get(path) {
  const r = await fetch(path, { headers: baseHeaders })
  if (!r.ok) throw new Error(`GET ${path} → ${r.status}`)
  return r.json()
}

async function post(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: baseHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!r.ok) throw new Error(`POST ${path} → ${r.status}`)
  return r.json()
}

async function del(path) {
  const r = await fetch(path, { method: 'DELETE', headers: baseHeaders })
  if (!r.ok) throw new Error(`DELETE ${path} → ${r.status}`)
  return r.json()
}

export const api = {
  health:     () => get('/health'),
  modules:    () => get('/api/modules'),
  target:     () => get('/api/target'),

  // Tutorial/Lab mission sessions
  sessions: {
    create:    (module_id)   => post('/api/sessions', { module_id }),
    list:      (module_id)    => get(module_id ? `/api/sessions?module_id=${encodeURIComponent(module_id)}` : '/api/sessions'),
    get:       (sid)          => get(`/api/sessions/${sid}`),
    remove:    (sid)          => del(`/api/sessions/${sid}`),
    setOption: (sid, k, v)    => post(`/api/sessions/${sid}/options`, { key: k, value: v }),
    setTarget: (sid, host, port) => post(`/api/sessions/${sid}/target`, { host, port }),
    start:     (sid)          => post(`/api/sessions/${sid}/start`),
    execute:   (sid)          => post(`/api/sessions/${sid}/execute`),
    checkProgress:  (sid, mode = 'tutorial') => post(`/api/sessions/${sid}/check-progress?mode=${encodeURIComponent(mode)}`),
    resetEvidence:  (sid)     => post(`/api/sessions/${sid}/reset-evidence`),
    restart:        (sid)     => post(`/api/sessions/${sid}/restart`),
    logs:         (sid)       => get(`/api/sessions/${sid}/logs`),
    labAnalysis:  (sid)       => get(`/api/sessions/${sid}/lab-analysis`),
    getReport:       (sid) => get(`/api/sessions/${sid}/report`),
    regenReport:     (sid) => post(`/api/sessions/${sid}/report/regenerate`),
    getAttackReport: (sid) => get(`/api/sessions/${sid}/attack-report`),

    // ── Variants (Phase 1) ──
    setVariant:    (sid, variant_id) => post(`/api/sessions/${sid}/variant`, { variant_id }),

    // ── Timeline (Phase 2) ──
    timeline:      (sid)      => get(`/api/sessions/${sid}/timeline`),
  },

  // Variants per module (called from the variant picker before create)
  variants: (module_id) => get(`/api/modules/${encodeURIComponent(module_id)}/variants`),

  // Lab action telemetry (Phase 2)
  actions: {
    record: (payload) => post('/api/lab/actions', payload),
  },

  // Lab Mode: AttackBox
  attackbox: {
    status:   ()              => get('/api/operator/attackbox/status'),
    exec:     (command, module_id) => post('/api/operator/attackbox/exec', { command, module_id }),
    evidence: (since = 0)     => get(`/api/operator/attackbox/evidence?since=${since}`),
  },

  // Lab Mode: ZAP
  zap: {
    status:   ()              => get('/api/operator/zap/status'),
    history:  (limit = 50)    => get(`/api/operator/zap/history?limit=${limit}`),
    repeater: (method, path, headers, body) =>
      post('/api/operator/zap/repeater/send', { method, path, headers, body }),
  },
}
