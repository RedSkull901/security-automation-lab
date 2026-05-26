import { useState } from 'react'
import Overview from './pages/Overview'
import Events from './pages/Events'
import BlockList from './pages/BlockList'
import './App.css'

const NAV = [
  { id: 'overview', label: 'Overview' },
  { id: 'events',   label: 'Events' },
  { id: 'blocklist', label: 'Block List' },
]

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
            <button
              key={n.id}
              className={`nav-btn ${page === n.id ? 'active' : ''}`}
              onClick={() => setPage(n.id)}
            >
              {n.label}
            </button>
          ))}
        </nav>
        <div className="header-status">
          <span className="status-dot" />
          <span className="status-text">LIVE</span>
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
