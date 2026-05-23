import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import { SeverityBadge, CATEGORY_ICON } from '../components/SeverityBadge.jsx'

export default function Modules() {
  const navigate  = useNavigate()
  const [modules, setModules]   = useState([])
  const [loading, setLoading]   = useState(true)
  const [error,   setError]     = useState(null)
  const [launching, setLaunching] = useState(null)
  const [query,   setQuery]     = useState('')
  const [category, setCategory] = useState('ALL')

  useEffect(() => {
    api.modules()
      .then(m => { setModules(m); setLoading(false) })
      .catch(e => { setError(e.message); setLoading(false) })
  }, [])

  const categories = ['ALL', ...new Set(modules.map(m => m.category).filter(Boolean))]

  const visible = modules.filter(m => {
    const q = query.trim().toLowerCase()
    if (category !== 'ALL' && m.category !== category) return false
    if (!q) return true
    return m.name?.toLowerCase().includes(q) || m.module_id?.toLowerCase().includes(q)
  })

  const launch = (mod) => {
    navigate(`/mission/${mod.module_id}`)
  }

  const SEV_COLOR = { critical:'#ff1535', high:'#ff6b00', medium:'#f5c400', low:'#00c8ff', info:'#8b8faa' }

  return (
    <div className="h-full overflow-y-auto" style={{ padding: '26px 30px' }}>
      <div className="mb-6">
        <h1 className="text-[21px] font-bold tracking-tight text-attense-text">Lab Modules</h1>
        <p className="font-mono text-[11px] text-attense-dim mt-1">
          {modules.length} modules loaded · choose a lab to start learning
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 mb-5">
        <div className="flex gap-1.5 flex-wrap">
          {categories.map(cat => (
            <button key={cat} onClick={() => setCategory(cat)}
              className="font-mono text-[10px] tracking-[0.12em] px-3 py-1.5 rounded-md transition-all"
              style={{
                background: category === cat ? 'rgba(255,21,53,0.12)' : 'transparent',
                border: `1px solid ${category === cat ? 'rgba(255,21,53,0.3)' : 'rgba(255,255,255,0.07)'}`,
                color: category === cat ? '#ff4060' : '#4a5280',
              }}
            >{cat}</button>
          ))}
        </div>
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Search modules…"
          className="ml-auto font-mono text-[11.5px] text-attense-text rounded-lg px-3 py-1.5"
          style={{
            background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)',
            outline: 'none', width: 220,
          }}
          onFocus={e => e.target.style.borderColor = 'rgba(255,21,53,0.4)'}
          onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.1)'}
        />
      </div>

      {error && (
        <div className="rounded-lg p-4 font-mono text-[11px] mb-4"
          style={{ background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)', color: '#ff4060' }}>
          Backend offline — {error}
        </div>
      )}

      {loading ? (
        <div className="py-14 text-center font-mono text-[11px] text-attense-dim tracking-widest">LOADING MODULES…</div>
      ) : (
        <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))' }}>
          {visible.map(m => {
            const color = SEV_COLOR[m.severity] || '#8b8faa'
            const isLaunching = launching === m.module_id
            return (
              <div key={m.module_id}
                className="relative rounded-xl overflow-hidden cursor-default transition-all duration-200 hover:-translate-y-0.5"
                style={{
                  background: 'rgba(255,255,255,0.022)',
                  border: '1px solid rgba(255,255,255,0.07)',
                }}
                onMouseEnter={e => e.currentTarget.style.borderColor = color + '44'}
                onMouseLeave={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)'}
              >
                {/* top glow */}
                <div className="absolute top-0 left-0 right-0 h-px"
                  style={{ background: `linear-gradient(90deg,transparent,${color}55,transparent)` }} />

                <div style={{ padding: '18px 20px 16px' }}>
                  <div className="flex justify-between items-start mb-3">
                    <div className="flex items-center gap-2.5">
                      <div
                        className="w-9 h-9 rounded-lg flex items-center justify-center text-base shrink-0"
                        style={{ background: color + '12', border: `1px solid ${color}30`, color }}
                      >
                        {CATEGORY_ICON[m.category] || '▪'}
                      </div>
                      <div>
                        <div className="font-mono text-[9px] tracking-[0.18em] text-attense-dim">{m.category} · {m.scenario_id}</div>
                        <div className="text-[13.5px] font-semibold text-attense-text">{m.name}</div>
                      </div>
                    </div>
                    <SeverityBadge severity={m.severity} />
                  </div>

                  <p className="text-[12px] text-attense-dim leading-relaxed mb-4 line-clamp-2">{m.description}</p>

                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10px] text-attense-dim">
                      {m.steps?.length ?? 0} steps
                    </span>
                    <button
                      onClick={() => launch(m)}
                      disabled={!!launching}
                      className="font-mono text-[10px] font-bold tracking-[0.1em] px-4 py-1.5 rounded-lg transition-all"
                      style={{
                        background: isLaunching ? 'rgba(255,21,53,0.06)' : 'rgba(255,21,53,0.1)',
                        border: '1px solid rgba(255,21,53,0.3)',
                        color: '#ff4060',
                        opacity: launching && !isLaunching ? 0.5 : 1,
                        cursor: launching ? 'not-allowed' : 'pointer',
                      }}
                      onMouseEnter={e => { if (!launching) e.currentTarget.style.background = 'rgba(255,21,53,0.18)' }}
                      onMouseLeave={e => { e.currentTarget.style.background = isLaunching ? 'rgba(255,21,53,0.06)' : 'rgba(255,21,53,0.1)' }}
                    >
                      {isLaunching ? 'OPENING…' : 'Enter Mission →'}
                    </button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {!loading && visible.length === 0 && (
        <div className="py-14 text-center font-mono text-[11px] text-attense-dim">No modules match that filter.</div>
      )}
    </div>
  )
}
