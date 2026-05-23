import { NavLink } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'

const NAV = [
  {
    to: '/', end: true, label: 'Dashboard',
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>,
  },
  {
    to: '/missions', label: 'Missions',
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/></svg>,
  },
  {
    to: '/modules', label: 'Lab Modules',
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>,
  },
  {
    to: '/reports', label: 'Reports',
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>,
  },
  {
    to: '/settings', label: 'Settings',
    icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065zM15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>,
  },
]

export function Sidebar({ health, open, onClose }) {
  return (
    <AnimatePresence initial={false}>
      {open && (
        <motion.aside
          key="sidebar"
          className="h-full flex flex-col shrink-0 overflow-hidden"
          initial={{ width: 0, opacity: 0 }}
          animate={{ width: 216, opacity: 1 }}
          exit={{ width: 0, opacity: 0 }}
          transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
          style={{
            minWidth: 0,
            background: 'rgba(7,9,15,0.97)',
            borderRight: '1px solid rgba(255,21,53,0.1)',
          }}
        >
      {/* Logo + close button */}
      <div
        className="flex items-center gap-2.5 shrink-0"
        style={{ padding: '18px 14px 14px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}
      >
        <div
          className="shrink-0 flex items-center justify-center rounded-lg"
          style={{
            width: 30, height: 30,
            background: 'linear-gradient(135deg,#ff1535,#8b2fff)',
            boxShadow: '0 0 14px rgba(255,21,53,0.45)',
          }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M13 10V3L4 14h7v7l9-11h-7z"/>
          </svg>
        </div>
        <div className="min-w-0 flex-1">
          <div className="font-mono font-bold tracking-[0.16em] text-[13px] text-attense-text">ATTENSE</div>
          <div className="font-mono text-[8.5px] tracking-[0.24em] text-attense-red">CYBER LAB</div>
        </div>
        <button
          onClick={onClose}
          title="Close sidebar"
          aria-label="Close sidebar"
          className="ml-auto shrink-0 text-attense-dim hover:text-attense-red transition-colors p-1 rounded"
          style={{ border: '1px solid rgba(255,255,255,0.08)' }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M4 6h16M4 12h16M4 18h16"/>
          </svg>
        </button>
      </div>

      {/* Online badge */}
      <div style={{ padding: '9px 12px' }}>
        <div
          className="flex items-center gap-2 rounded-md px-2.5 py-1.5"
          style={{ background: health?.ok ? 'rgba(46,227,154,0.06)' : 'rgba(255,21,53,0.07)', border: `1px solid ${health?.ok ? 'rgba(46,227,154,0.18)' : 'rgba(255,21,53,0.18)'}` }}
        >
          <div
            className="animate-pulse-dot shrink-0 rounded-full"
            style={{ width: 6, height: 6, background: health?.ok ? '#2ee39a' : '#ff1535', color: health?.ok ? '#2ee39a' : '#ff1535' }}
          />
          <span
            className="font-mono text-[9px] tracking-[0.14em]"
            style={{ color: health?.ok ? '#2ee39a' : '#ff4060' }}
          >
            {health?.ok ? 'LAB ONLINE' : 'BACKEND OFFLINE'}
          </span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 flex flex-col gap-0.5 px-2 py-1 overflow-y-auto">
        {NAV.map(item => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `relative flex items-center rounded-lg transition-all duration-150 select-none gap-2.5 px-2.5 py-2 ${
                isActive
                  ? 'text-attense-red bg-attense-red/10 border border-attense-red/25'
                  : 'text-attense-dim hover:text-attense-muted hover:bg-white/[0.03] border border-transparent'
              }`
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <div
                    className="absolute left-0 rounded-r"
                    style={{ top: '20%', height: '60%', width: 2, background: '#ff1535', boxShadow: '0 0 8px #ff1535' }}
                  />
                )}
                <span className="shrink-0">{item.icon}</span>
                <span className={`text-[12.5px] truncate ${isActive ? 'font-semibold' : 'font-normal'}`}>
                  {item.label}
                </span>
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User */}
      <div
        className="flex items-center gap-2.5 shrink-0"
        style={{ padding: '10px 12px', borderTop: '1px solid rgba(255,255,255,0.05)' }}
      >
        <div
          className="shrink-0 rounded-full flex items-center justify-center text-[10px] font-bold text-white"
          style={{ width: 26, height: 26, background: 'linear-gradient(135deg,#ff1535,#8b2fff)' }}
        >
          OP
        </div>
        <div className="min-w-0">
          <div className="text-attense-text text-[11.5px] font-semibold leading-tight">Learner</div>
          <div className="text-attense-dim font-mono text-[9px] tracking-widest leading-tight">CYBER RANGE</div>
        </div>
      </div>
        </motion.aside>
      )}
    </AnimatePresence>
  )
}
