// src/pages/Events.jsx
import { useState } from 'react'
import { usePolling } from '../hooks/useApi'

const FILTERS = ['all', 'high', 'medium', 'low']

function formatTime(iso) {
  if (!iso) return '—'
  const raw = iso.includes('+') || iso.endsWith('Z') ? iso : iso + 'Z'
  return new Date(raw).toLocaleString()
}

function EventRow({ event, expanded, onToggle }) {
  const sev = event.severity || 'low'
  const triage = event.response?.triage_summary || null

  return (
    <>
      <tr onClick={onToggle} style={{ cursor: 'pointer' }}>
        <td className="ip-cell">{event.ip}</td>
        <td><span className={`badge badge-${sev}`}>{sev}</span></td>
        <td className="score-cell">{event.risk_score ?? '—'}</td>
        <td className="score-cell">{event.failed_attempts ?? '—'}</td>
        <td className="score-cell">{event.abuse_confidence_score ?? 0}%</td>
        <td className="score-cell">{event.country ?? '—'}</td>
        <td className="score-cell">{event.action ?? '—'}</td>
        <td className="score-cell" style={{ fontSize: 11 }}>
          {formatTime(event.timestamp)}
        </td>
        <td style={{ color: 'var(--text3)', fontSize: 11 }}>
          {expanded ? '▲' : '▼'}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={9} style={{ padding: '0 12px 12px', background: 'var(--bg3)' }}>
            {triage
              ? (
                <>
                  <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 10,
                                color: 'var(--green)', marginBottom: 6,
                                letterSpacing: '.08em', textTransform: 'uppercase' }}>
                    🤖 AI Triage
                  </div>
                  <div className="triage-text">{triage}</div>
                </>
              )
              : (
                <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 11,
                               color: 'var(--text3)' }}>
                  No AI triage available for this event.
                </span>
              )
            }
          </td>
        </tr>
      )}
    </>
  )
}

export default function Events() {
  const [filter,   setFilter]   = useState('all')
  const [expanded, setExpanded] = useState(null)

  const path = filter === 'all'
    ? '/events?limit=100'
    : `/events?severity=${filter}&limit=100`

  const { data, loading, error, refetch } = usePolling(path, 20000)

  const events = data?.events ?? []

  return (
    <>
      <p className="page-title">Event feed — auto-refreshes every 20s</p>

      <div className="filter-bar">
        {FILTERS.map(f => (
          <button
            key={f}
            className={`filter-btn ${filter === f ? 'active' : ''}`}
            onClick={() => { setFilter(f); setExpanded(null) }}
          >
            {f}
          </button>
        ))}
        <span style={{ marginLeft: 'auto', fontFamily: 'IBM Plex Mono',
                       fontSize: 11, color: 'var(--text3)' }}>
          {events.length} event{events.length !== 1 ? 's' : ''}
        </span>
        <button className="filter-btn" onClick={refetch}>↺ refresh</button>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {loading && <div className="loading">fetching events...</div>}
        {error   && <div className="empty">Error: {error}</div>}
        {!loading && !error && events.length === 0 && (
          <div className="empty">
            No events yet. Run the detector to generate some:<br />
            <code style={{ color: 'var(--green)', fontSize: 11 }}>
              SAL_DRY_RUN=true python -m security_core.detectors.ssh_bruteforce
            </code>
          </div>
        )}
        {!loading && events.length > 0 && (
          <div style={{ overflowX: 'auto' }}>
            <table className="events-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Attempts</th>
                  <th>Abuse%</th>
                  <th>Country</th>
                  <th>Action</th>
                  <th>Time</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {events.map(e => (
                  <EventRow
                    key={e.id}
                    event={e}
                    expanded={expanded === e.id}
                    onToggle={() => setExpanded(expanded === e.id ? null : e.id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
