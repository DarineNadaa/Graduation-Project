import { Outlet } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../api/client.js'
import { Sidebar } from './Sidebar.jsx'

const PAGE_LABELS = {
  '/':           'Dashboard',
  '/missions':   'Missions',
  '/modules':    'Lab Modules',
  '/reports':    'Reports',
  '/settings':   'Settings',
}

function TopBar({ health, activeCount, sidebarOpen, onOpenSidebar }) {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const path = window.location.pathname
  let label = PAGE_LABELS[path] || 'Workspace'
  if (path.startsWith('/workspace/')) label = 'Workspace'
  if (path.startsWith('/mission/'))   label = 'Mission'

  const timeStr = time.toLocaleTimeString('en-US', { hour12: false })
  const dateStr = time.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })

  return (
    <header
      className="shrink-0 flex items-center relative"
      style={{
        height: 48,
        padding: '0 22px 0 14px',
        borderBottom: '1px solid rgba(255,255,255,0.05)',
        background: 'rgba(7,9,15,0.85)',
        backdropFilter: 'blur(12px)',
        zIndex: 5,
      }}
    >
      <div className="topbar-glow" />

      {/* Sidebar open button (shown only when sidebar is closed) */}
      <AnimatePresence initial={false}>
        {!sidebarOpen && (
          <motion.button
            key="sidebar-open-btn"
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -8 }}
            transition={{ duration: 0.2, ease: 'easeOut' }}
            onClick={onOpenSidebar}
            title="Open sidebar"
            aria-label="Open sidebar"
            className="mr-3 shrink-0 flex items-center justify-center text-attense-muted hover:text-attense-red transition-colors rounded"
            style={{
              width: 32, height: 32,
              border: '1px solid rgba(255,255,255,0.08)',
              background: 'rgba(255,255,255,0.02)',
            }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <path d="M4 6h16M4 12h16M4 18h16"/>
            </svg>
          </motion.button>
        )}
      </AnimatePresence>

      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 flex-1 min-w-0">
        <span className="text-attense-dim font-mono text-[10px]">ATTENSE</span>
        <span className="text-attense-dim font-mono text-[10px]">/</span>
        <span className="text-attense-muted font-mono text-[11px] font-semibold">{label}</span>
      </div>

      {/* Right badges */}
      <div className="flex items-center gap-5">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <div
              className="rounded-full animate-pulse-dot"
              style={{ width: 5, height: 5, background: '#ff1535', color: '#ff1535' }}
            />
            <span className="text-attense-red font-mono text-[10px] font-semibold">
              {activeCount ?? 0} Active
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <div
              className="rounded-full"
              style={{ width: 5, height: 5, background: health?.ok ? '#2ee39a' : '#ff1535' }}
            />
            <span
              className="font-mono text-[10px]"
              style={{ color: health?.ok ? '#2ee39a' : '#ff4060' }}
            >
              {health?.ok ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
        </div>
        <div className="font-mono text-[10px] text-attense-dim">
          {dateStr} <span className="text-attense-red">{timeStr}</span>
        </div>
      </div>
    </header>
  )
}

export function AppLayout() {
  const [health, setHealth] = useState({ ok: false, modules: 0 })
  const [activeCount, setActiveCount] = useState(0)
  const [sidebarOpen, setSidebarOpen] = useState(() => {
    try { return JSON.parse(localStorage.getItem('attense_sidebar_open') || 'true') }
    catch { return true }
  })

  useEffect(() => {
    localStorage.setItem('attense_sidebar_open', JSON.stringify(sidebarOpen))
  }, [sidebarOpen])

  // Poll /health every 5s
  useEffect(() => {
    let cancelled = false
    const poll = async () => {
      try {
        const h = await api.health()
        if (!cancelled) setHealth(h)
      } catch {
        if (!cancelled) setHealth({ ok: false, modules: 0 })
      }
    }
    poll()
    const t = setInterval(poll, 5000)
    return () => { cancelled = true; clearInterval(t) }
  }, [])

  // Poll active sessions every 4s for the TopBar "Active" counter
  useEffect(() => {
    let cancelled = false
    const pollSessions = async () => {
      try {
        const list = await api.sessions.list()
        if (cancelled) return
        const active = Array.isArray(list)
          ? list.filter(s => s.state === 'running').length
          : 0
        setActiveCount(active)
      } catch {
        if (!cancelled) setActiveCount(0)
      }
    }
    pollSessions()
    const t = setInterval(pollSessions, 4000)
    return () => { cancelled = true; clearInterval(t) }
  }, [])

  return (
    <div className="h-full w-full flex overflow-hidden" style={{ background: '#07090f' }}>
      <Sidebar
        health={health}
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <TopBar
          health={health}
          activeCount={activeCount}
          sidebarOpen={sidebarOpen}
          onOpenSidebar={() => setSidebarOpen(true)}
        />
        <main className="flex-1 min-h-0 overflow-hidden animate-fade-up">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
