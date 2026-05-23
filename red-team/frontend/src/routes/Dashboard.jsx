import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, animate, useInView, AnimatePresence } from 'framer-motion'
import { api } from '../api/client.js'
import { SeverityBadge } from '../components/SeverityBadge.jsx'
import { FallingPattern } from '../components/FallingPattern.jsx'

// ── Hex helper ───────────────────────────────────────────────────────────────
function hexToRgb(hex) {
  const r = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
  return r ? `${parseInt(r[1],16)},${parseInt(r[2],16)},${parseInt(r[3],16)}` : '255,255,255'
}

// ── Module metadata ───────────────────────────────────────────────────────────
const MODULE_ICONS = {
  recon:         '🔭',
  brute_force:   '🔐',
  xss:           '⚡',
  cmd_injection: '💉',
  dir_traversal: '📂',
  file_upload:   '📤',
  csrf:          '🎭',
}
const MODULE_COLORS = {
  recon:         '#00c8ff',
  brute_force:   '#ff1535',
  xss:           '#f5c400',
  cmd_injection: '#ff6b00',
  dir_traversal: '#2ee39a',
  file_upload:   '#8b2fff',
  csrf:          '#e040fb',
}

// ── Mission row ───────────────────────────────────────────────────────────────
function MissionRow({ session, onOpen, onReport, index }) {
  const isCompleted = session.learning_success || session.learning_state === 'completed'
  const isRunning   = !isCompleted && !!session.mission_started_at
  const done  = session.learning_completed_tasks?.length ?? session.completed_steps?.length ?? 0
  const total = session.learning_total_tasks || session.total_steps || 0
  const pct   = isCompleted ? 100 : (total > 0 ? Math.round((done / total) * 100) : (session.learning_progress_percent || 0))

  const startedStr = session.created_at
    ? (() => {
        const d = new Date((session.created_at || 0) * 1000)
        const pad = n => String(n).padStart(2, '0')
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
      })()
    : '—'

  const durationStr = (() => {
    if (isRunning) return '—'
    const secs = session.learning_duration_s
    if (secs != null) {
      if (secs < 60) return `${secs}s`
      return `${Math.floor(secs / 60)}m ${secs % 60}s`
    }
    const ms = session.duration_ms
    if (!ms) return '—'
    return ms < 1000 ? `${Math.round(ms)}ms` : `${(ms / 1000).toFixed(1)}s`
  })()

  const accentColor = isRunning ? '#ff1535' : isCompleted ? '#00c8ff' : '#2a3050'
  const modColor = MODULE_COLORS[session.module_id] || accentColor

  return (
    <motion.div
      className="group relative flex items-center gap-3 px-4 py-3.5 rounded-xl cursor-pointer overflow-hidden"
      style={{
        background: 'rgba(255,255,255,0.018)',
        border: '1px solid rgba(255,255,255,0.055)',
        transition: 'background 0.2s ease',
      }}
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.44 + index * 0.055, duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      whileHover={{ background: 'rgba(255,255,255,0.032)' }}
      onClick={() => onOpen(session.session_id)}
    >
      {/* left accent stripe */}
      <div
        className="absolute left-0 top-0 bottom-0 w-[3px] rounded-l-xl"
        style={{
          background: isRunning
            ? 'linear-gradient(180deg,#ff1535,#ff6b00)'
            : isCompleted
              ? '#00c8ff'
              : '#1e2640',
          boxShadow: isRunning ? '0 0 8px #ff153588' : isCompleted ? '0 0 6px #00c8ff55' : 'none',
        }}
      />

      {/* module icon bubble */}
      <div
        className="shrink-0 w-9 h-9 rounded-lg flex items-center justify-center text-[16px] ml-1"
        style={{
          background: `rgba(${hexToRgb(modColor)},0.1)`,
          border: `1px solid ${modColor}30`,
        }}
      >
        {MODULE_ICONS[session.module_id] || '▪'}
      </div>

      {/* name + progress */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="font-mono text-[9px] text-attense-dim">{session.session_id?.slice(0, 8)}</span>
          <SeverityBadge severity={session.severity} />
          {isRunning && (
            <span className="font-mono text-[8px] tracking-[0.18em] px-1.5 py-0.5 rounded"
              style={{ background: 'rgba(255,21,53,0.1)', color: '#ff4060', border: '1px solid rgba(255,21,53,0.25)' }}>
              LIVE
            </span>
          )}
        </div>
        <div className="text-[13px] font-semibold text-attense-text truncate mb-2.5">
          {session.module_name || session.module_id}
        </div>
        <div className="flex items-center gap-2.5">
          <div className="flex-1 h-[3px] rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
            <motion.div
              className={`h-full rounded-full ${isRunning ? 'progress-shimmer' : ''}`}
              style={{
                width: pct + '%',
                background: isRunning
                  ? undefined
                  : isCompleted ? '#00c8ff' : '#1e2640',
                boxShadow: isCompleted ? '0 0 8px #00c8ff66' : 'none',
              }}
              initial={{ width: 0 }}
              animate={{ width: pct + '%' }}
              transition={{ delay: 0.5 + index * 0.06, duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
            />
          </div>
          <span className="font-mono text-[9.5px] text-attense-dim whitespace-nowrap shrink-0">{done}/{total}</span>
        </div>
      </div>

      {/* timestamp (desktop only) */}
      <div className="shrink-0 hidden md:flex flex-col items-end gap-1 mx-1">
        <div className="font-mono text-[10px] text-attense-dim">{startedStr}</div>
        <div className="font-mono text-[9px] text-attense-dim opacity-60">dur: {durationStr}</div>
      </div>

      {/* report button */}
      {isCompleted && (
        <motion.button
          onClick={e => { e.stopPropagation(); onReport?.(session.session_id) }}
          className="shrink-0 font-mono text-[9.5px] font-bold tracking-[0.1em] px-3 py-1.5 rounded-lg"
          style={{ color: '#00c8ff', background: 'rgba(0,200,255,0.07)', border: '1px solid rgba(0,200,255,0.22)' }}
          whileHover={{ background: 'rgba(0,200,255,0.15)', borderColor: 'rgba(0,200,255,0.45)' }}
          whileTap={{ scale: 0.96 }}
        >REPORT</motion.button>
      )}

      {/* state badge */}
      <div
        className="shrink-0 px-2.5 py-1 rounded-lg font-mono text-[9px] font-bold tracking-[0.1em]"
        style={{
          color:      isRunning ? '#ff4060' : isCompleted ? '#00c8ff' : '#3a4568',
          background: isRunning ? 'rgba(255,21,53,0.09)' : isCompleted ? 'rgba(0,200,255,0.07)' : 'rgba(255,255,255,0.03)',
          border: `1px solid ${isRunning ? 'rgba(255,21,53,0.28)' : isCompleted ? 'rgba(0,200,255,0.2)' : 'rgba(255,255,255,0.07)'}`,
        }}
      >
        {(session.state || 'idle').toUpperCase()}
      </div>
    </motion.div>
  )
}

// ── Empty state ───────────────────────────────────────────────────────────────
function EmptyState({ onLaunch }) {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const t = setInterval(() => setTick(v => v + 1), 1200)
    return () => clearInterval(t)
  }, [])

  const dots = '...'.slice(0, (tick % 4))

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
      className="flex flex-col items-center py-16"
    >
      {/* animated crosshair */}
      <div className="relative mb-7" style={{ width: 88, height: 88 }}>
        <motion.div
          className="absolute inset-0 rounded-full"
          style={{ border: '1px dashed rgba(255,21,53,0.2)' }}
          animate={{ rotate: 360 }}
          transition={{ duration: 18, repeat: Infinity, ease: 'linear' }}
        />
        <div
          className="absolute animate-ring-pulse rounded-full"
          style={{ inset: 10, border: '1px solid rgba(255,21,53,0.15)' }}
        />
        <div
          className="absolute animate-ring-pulse rounded-full"
          style={{ inset: 20, border: '1px solid rgba(255,21,53,0.1)', animationDelay: '0.6s' }}
        />
        <svg viewBox="0 0 88 88" fill="none" width={88} height={88} className="absolute inset-0">
          <circle cx="44" cy="44" r="26" stroke="rgba(255,21,53,0.25)" strokeWidth="1.5" />
          <circle cx="44" cy="44" r="15" stroke="rgba(255,21,53,0.15)" strokeWidth="1" />
          <motion.circle cx="44" cy="44" r="4"
            fill="rgba(255,21,53,0.6)"
            animate={{ r: [3.5, 5, 3.5], opacity: [0.6, 0.9, 0.6] }}
            transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
          />
          <circle cx="44" cy="44" r="1.8" fill="rgba(255,21,53,0.95)" />
          {[
            [44, 8, 44, 24], [44, 64, 44, 80],
            [8, 44, 24, 44], [64, 44, 80, 44]
          ].map(([x1,y1,x2,y2], i) => (
            <motion.line key={i} x1={x1} y1={y1} x2={x2} y2={y2}
              stroke="rgba(255,21,53,0.35)" strokeWidth="1.5" strokeLinecap="round"
              initial={{ opacity: 0 }}
              animate={{ opacity: [0.35, 0.7, 0.35] }}
              transition={{ duration: 2.4, delay: i * 0.15, repeat: Infinity }}
            />
          ))}
          {[
            'M26 26 l5 0 l0 5', 'M62 26 l-5 0 l0 5',
            'M26 62 l5 0 l0 -5', 'M62 62 l-5 0 l0 -5',
          ].map((d, i) => (
            <path key={i} d={d} stroke="rgba(255,21,53,0.2)" strokeWidth="1.2" fill="none" strokeLinecap="round" />
          ))}
        </svg>
      </div>

      <h3 style={{
        fontFamily: "'Rajdhani', sans-serif",
        fontSize: 22, fontWeight: 700,
        letterSpacing: '0.04em', color: '#c0c8dc',
        marginBottom: 10,
      }}>
        No Active Missions
      </h3>

      <div className="font-mono text-[10.5px] mb-7 text-center leading-relaxed"
        style={{ color: '#1e2d45', maxWidth: 300 }}>
        <span style={{ color: '#2a4060' }}>$</span>{' '}
        <span style={{ color: '#3a5070' }}>awaiting mission assignment{dots}</span>
        <br />
        <span style={{ color: '#1a2840', fontSize: 10 }}>
          Select a lab module to begin tracking attack chains,
          detection signals, and learning progress.
        </span>
      </div>

      <div className="flex items-center gap-3 flex-wrap justify-center">
        <motion.button
          onClick={onLaunch}
          className="relative overflow-hidden btn-shimmer font-mono font-bold text-white"
          style={{
            fontSize: 11, letterSpacing: '0.12em',
            padding: '10px 24px', borderRadius: 9,
            background: 'linear-gradient(135deg,#ff1535,#cc0020)',
            boxShadow: '0 0 22px rgba(255,21,53,0.38), 0 4px 14px rgba(255,21,53,0.2), inset 0 1px 0 rgba(255,255,255,0.1)',
          }}
          whileHover={{
            y: -2,
            boxShadow: '0 0 40px rgba(255,21,53,0.6), 0 8px 24px rgba(255,21,53,0.3), inset 0 1px 0 rgba(255,255,255,0.14)',
          }}
          whileTap={{ y: 0, scale: 0.975 }}
        >
          ⚡ BROWSE MODULES
        </motion.button>
      </div>
    </motion.div>
  )
}

// ── Threat level ticker ───────────────────────────────────────────────────────
function ThreatTicker({ running }) {
  const items = [
    `${running} ACTIVE THREAT${running !== 1 ? 'S' : ''}`,
    'LAB NETWORK: ISOLATED',
    'WAZUH: MONITORING',
    'TARGET-AGENT: ONLINE',
    'SIGNAL STORE: READY',
    'ALL SYSTEMS NOMINAL',
  ]
  const [idx, setIdx] = useState(0)
  useEffect(() => {
    const t = setInterval(() => setIdx(v => (v + 1) % items.length), 2800)
    return () => clearInterval(t)
  }, [running])
  return (
    <div className="flex items-center gap-2 overflow-hidden">
      <span className="font-mono text-[8.5px] tracking-[0.22em] shrink-0" style={{ color: '#1a2840' }}>
        SYS
      </span>
      <div className="w-px h-3 shrink-0" style={{ background: '#1a2840' }} />
      <AnimatePresence mode="wait">
        <motion.span
          key={idx}
          className="font-mono text-[8.5px] tracking-[0.18em] truncate"
          style={{ color: running > 0 ? '#ff4060' : '#1e3050' }}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -6 }}
          transition={{ duration: 0.3 }}
        >
          {items[idx]}
        </motion.span>
      </AnimatePresence>
    </div>
  )
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const navigate = useNavigate()
  const [modules,  setModules]  = useState([])
  const [sessions, setSessions] = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)

  useEffect(() => {
    let cancelled = false
    Promise.all([
      api.modules(),
      api.sessions.list().catch(() => []),
    ]).then(([m, s]) => {
      if (cancelled) return
      setModules(m)
      setSessions(Array.isArray(s) ? s : [])
      setLoading(false)
    }).catch(err => {
      if (!cancelled) { setError(err.message); setLoading(false) }
    })
    return () => { cancelled = true }
  }, [])

  const completed = sessions.filter(s => s.learning_success || s.learning_state === 'completed')
  const running   = sessions.filter(s => s.mission_started_at && !s.learning_success && s.learning_state !== 'completed')

  const recent = [...sessions].sort((a, b) => (b.created_at || 0) - (a.created_at || 0)).slice(0, 6)

  return (
    <div
      className="h-full overflow-y-auto relative db-mesh-bg db-scanlines"
      style={{ padding: '28px 32px' }}
    >
      {/* ── Deep vignette ── */}
      <div className="pointer-events-none" style={{
        position: 'fixed', inset: 0, zIndex: 0,
        background: 'radial-gradient(ellipse 120% 110% at 50% 50%, transparent 12%, rgba(4,6,10,0.72) 100%)',
      }} />

      {/* ── Cinematic corner glows ── */}
      <div className="pointer-events-none" style={{
        position: 'fixed', top: -120, left: -120, width: 480, height: 480, zIndex: 0,
        background: 'radial-gradient(ellipse at center, rgba(255,21,53,0.04) 0%, transparent 70%)',
      }} />
      <div className="pointer-events-none" style={{
        position: 'fixed', bottom: -80, right: -80, width: 400, height: 400, zIndex: 0,
        background: 'radial-gradient(ellipse at center, rgba(139,47,255,0.04) 0%, transparent 70%)',
      }} />

      <div className="relative" style={{ zIndex: 1 }}>

        {/* ── Hero ── */}
        <div
          className="relative rounded-2xl overflow-hidden mb-4"
          style={{
            minHeight: 256,
            border: '1px solid rgba(255,255,255,0.06)',
            background: '#07090f',
          }}
        >
          {/* FallingPattern background */}
          <div className="absolute inset-0" style={{ zIndex: 0 }}>
            <FallingPattern
              color="#ff1535"
              backgroundColor="#07090f"
              duration={120}
              blurIntensity="0.15em"
              density={1.2}
            />
          </div>

          {/* left-side gradient — only covers text area, leaves right side open */}
          <div className="absolute inset-0 pointer-events-none" style={{
            zIndex: 1,
            background: 'linear-gradient(95deg, rgba(5,7,12,0.97) 0%, rgba(5,7,12,0.88) 35%, rgba(5,7,12,0.4) 55%, rgba(5,7,12,0.05) 70%, transparent 100%)',
          }} />

          {/* bottom haze */}
          <div className="absolute bottom-0 left-0 right-0 pointer-events-none" style={{
            zIndex: 1,
            height: 80,
            background: 'linear-gradient(0deg, rgba(5,7,12,0.75) 0%, transparent 100%)',
          }} />

          {/* ── Ticker strip (bottom of hero) ── */}
          <div className="absolute bottom-0 left-0 right-0 flex items-center px-6 py-2"
            style={{ zIndex: 2, borderTop: '1px solid rgba(255,255,255,0.04)' }}>
            <ThreatTicker running={running.length} />
          </div>

          {/* ── Hero content ── */}
          <div className="relative" style={{ zIndex: 2, padding: '42px 44px 56px', maxWidth: 540 }}>

            {/* SYSTEM OPERATIONAL pill */}
            <div
              className="inline-flex items-center gap-2 mb-5 px-3 py-1.5 rounded-full"
              style={{
                background: 'rgba(255,21,53,0.06)',
                border: '1px solid rgba(255,21,53,0.18)',
              }}
            >
              <div className="w-1.5 h-1.5 rounded-full animate-pulse-dot" style={{ background: '#ff1535' }} />
              <span className="font-mono" style={{ fontSize: 8.5, letterSpacing: '0.3em', color: '#ff1535' }}>
                SYSTEM OPERATIONAL
              </span>
            </div>

            {/* Title */}
            <h1
              style={{
                fontFamily: "'Rajdhani', sans-serif",
                fontSize: 48, fontWeight: 700,
                lineHeight: 1.02, letterSpacing: '-0.01em',
                color: '#edf0f8',
                marginBottom: 14,
              }}
            >
              Welcome to{' '}
              <span style={{
                color: '#ff1535',
                textShadow: '0 0 40px rgba(255,21,53,0.55), 0 0 80px rgba(255,21,53,0.22)',
              }}>
                ATTENSE
              </span>
            </h1>

            {/* Sub */}
            <p
              style={{ fontSize: 13.5, lineHeight: 1.72, color: '#2e4060', maxWidth: 400, marginBottom: 30 }}
            >
              {running.length > 0
                ? `${running.length} active mission${running.length !== 1 ? 's' : ''} in progress. `
                : 'No active missions running. '}
              {modules.length} lab modules available across multiple attack vectors.
            </p>

            {/* CTAs */}
            <div className="flex gap-3 flex-wrap">
              <motion.button
                onClick={() => navigate('/modules')}
                className="relative overflow-hidden btn-shimmer font-mono font-bold text-white"
                style={{
                  fontSize: 11.5, letterSpacing: '0.1em',
                  padding: '12px 28px', borderRadius: 10,
                  background: 'linear-gradient(135deg, #ff1535 0%, #cc0020 100%)',
                  boxShadow: '0 0 26px rgba(255,21,53,0.48), 0 6px 20px rgba(255,21,53,0.26), inset 0 1px 0 rgba(255,255,255,0.12)',
                  cursor: 'pointer',
                }}
                whileHover={{
                  y: -2,
                  boxShadow: '0 0 50px rgba(255,21,53,0.72), 0 10px 32px rgba(255,21,53,0.38), inset 0 1px 0 rgba(255,255,255,0.16)',
                }}
                whileTap={{ y: 0, scale: 0.975 }}
                transition={{ duration: 0.13 }}
              >
                ⚡ LAUNCH MISSION
              </motion.button>

              <motion.button
                onClick={() => navigate('/missions')}
                className="font-mono font-semibold"
                style={{
                  fontSize: 11, letterSpacing: '0.06em',
                  padding: '12px 24px', borderRadius: 10,
                  color: '#364a68',
                  background: 'rgba(255,255,255,0.02)',
                  border: '1px solid rgba(255,255,255,0.07)',
                  cursor: 'pointer',
                }}
                whileHover={{
                  borderColor: 'rgba(255,255,255,0.18)',
                  color: '#a0b0c8',
                  background: 'rgba(255,255,255,0.06)',
                  y: -1,
                }}
                whileTap={{ y: 0 }}
                transition={{ duration: 0.14 }}
              >
                VIEW SESSIONS
              </motion.button>
            </div>
          </div>
        </div>

        {/* ── Active missions panel ── */}
        <motion.div
          className="rounded-xl overflow-hidden"
          style={{
            background: 'rgba(8,10,17,0.7)',
            backdropFilter: 'blur(16px)',
            border: '1px solid rgba(255,255,255,0.058)',
            boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
          }}
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.38, duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
        >
          {/* panel header */}
          <div
            className="flex justify-between items-center"
            style={{
              padding: '16px 20px 14px',
              borderBottom: '1px solid rgba(255,255,255,0.048)',
              background: 'linear-gradient(90deg, rgba(255,21,53,0.03) 0%, transparent 60%)',
            }}
          >
            <div className="flex items-center gap-3">
              <div className="w-px h-5 rounded-full" style={{ background: 'linear-gradient(180deg,#ff1535,rgba(255,21,53,0.2))' }} />
              <div>
                <h2 style={{
                  fontFamily: "'Rajdhani', sans-serif",
                  fontSize: 16.5, fontWeight: 700,
                  letterSpacing: '0.05em', color: '#d0d6e8', margin: 0,
                }}>
                  Active Missions
                </h2>
                <p className="text-[10.5px] mt-0.5" style={{ color: '#1e2d45' }}>Latest lab activity</p>
              </div>
            </div>
            <motion.button
              onClick={() => navigate('/missions')}
              className="font-mono text-[10px] tracking-[0.1em] px-3.5 py-2 rounded-lg flex items-center gap-1.5"
              style={{ color: '#1e2d45', border: '1px solid rgba(255,255,255,0.06)', background: 'transparent', cursor: 'pointer' }}
              whileHover={{ color: '#6a7898', borderColor: 'rgba(255,255,255,0.14)', background: 'rgba(255,255,255,0.02)' }}
            >
              View all →
            </motion.button>
          </div>

          {/* body */}
          <div style={{ padding: '14px 16px 18px' }}>
            {loading && (
              <div className="py-10 text-center font-mono text-[10.5px] tracking-widest flex items-center justify-center gap-2" style={{ color: '#1e2d45' }}>
                <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                  style={{ width: 12, height: 12, border: '1.5px solid rgba(255,21,53,0.3)', borderTopColor: '#ff1535', borderRadius: '50%' }} />
                LOADING…
              </div>
            )}

            {error && (
              <div className="rounded-xl px-4 py-3.5 font-mono text-[11px] flex items-center gap-2"
                style={{ background: 'rgba(255,21,53,0.06)', border: '1px solid rgba(255,21,53,0.2)', color: '#ff4060' }}>
                <span>⚠</span> Backend offline — {error}
              </div>
            )}

            {!loading && !error && recent.length === 0 && (
              <EmptyState onLaunch={() => navigate('/modules')} />
            )}

            {!loading && !error && recent.length > 0 && (
              <div className="flex flex-col gap-2">
                {recent.map((s, i) => (
                  <MissionRow
                    key={s.session_id}
                    session={s}
                    index={i}
                    onOpen={sid => navigate(`/workspace/${sid}`)}
                    onReport={sid => navigate(`/report/${sid}`)}
                  />
                ))}
              </div>
            )}
          </div>
        </motion.div>

      </div>
    </div>
  )
}
