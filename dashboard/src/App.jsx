import { useState, useEffect } from 'react'
import Overview from './pages/Overview'
import Events from './pages/Events'
import BlockList from './pages/BlockList'
import { usePolling } from './hooks/useApi'
import './App.css'

const NAV = [
  { id: 'overview',  label: 'Overview'   },
  { id: 'events',    label: 'Events'     },
  { id: 'blocklist', label: 'Block List' },
]

function LiveClock() {
  const [now, setNow] = useState(new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  const timeStr = now.toLocaleTimeString('en-GB', { hour12: false })
  const dateStr = now.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone
  return (
    <div className="clock">
      <span className="clock-time">{timeStr}</span>
      <span className="clock-date">{dateStr} · {tz}</span>
    </div>
  )
}

function LastDetection() {
  const { data } = usePolling('/events?limit=1', 15000)
  const events = data?.events ?? []
  const last = events[0]
  if (!last) return (
    <div className="last-detect">
      <span className="last-detect-label">Last detection</span>
      <span className="last-detect-value muted">none</span>
    </div>
  )
  const ts = new Date(last.timestamp)
  const ago = Math.floor((Date.now() - ts) / 1000)
  const agoStr = ago < 60 ? `${ago}s ago` : ago < 3600 ? `${Math.floor(ago/60)}m ago` : `${Math.floor(ago/3600)}h ago`
  const sev = last.severity || 'low'
  return (
    <div className="last-detect">
      <span className="last-detect-label">Last detection</span>
      <span className={`last-detect-value sev-${sev}`}>{last.ip} · {agoStr}</span>
    </div>
  )
}

export default function App() {
  const [page, setPage] = useState('overview')
  return (
    <div className="app">
      <header className="header">
        <div className="header-brand">
          <span className="brand-icon">⬡</span>
          <span className="brand-name">security<span className="brand-accent">-core</span></span>
        </div>
        <nav className="nav">
          {NAV.map(n => (
            <button key={n.id} className={`nav-btn ${page === n.id ? 'active' : ''}`} onClick={() => setPage(n.id)}>
              {n.label}
            </button>
          ))}
        </nav>
        <div className="header-right">
          <LastDetection />
          <div className="header-divider" />
          <LiveClock />
          <div className="header-divider" />
          <div className="header-status">
            <span className="status-dot" />
            <span className="status-text">LIVE</span>
          </div>
        </div>
      </header>
      <main className="main">
        {page === 'overview'  && <Overview />}
        {page === 'events'    && <Events />}
        {page === 'blocklist' && <BlockList />}
      </main>
    </div>
  )
}
