import { useState } from 'react'
import { usePolling, api } from '../hooks/useApi'

function formatTime(iso) {
  if (!iso) return '—'
  const raw = iso.includes('+') || iso.endsWith('Z') ? iso : iso + 'Z'
  return new Date(raw).toLocaleString()
}

export default function BlockList() {
  const [ip,       setIp]       = useState('')
  const [duration, setDuration] = useState(30)
  const [log,      setLog]      = useState([])   // action log
  const [busy,     setBusy]     = useState(false)

  const { data, loading, error, refetch } = usePolling('/events?limit=500', 30000)

  const blocked = (data?.events ?? []).filter(e =>
    e.response?.action === 'block_temp' && e.response?.success === true
  )
  const seen = new Set()
  const unique = blocked.filter(e => {
    if (seen.has(e.ip)) return false
    seen.add(e.ip); return true
  })

  // Also pull manual block events
  const manualEvents = (data?.events ?? []).filter(e =>
    e.type === 'manual_block' || e.type === 'manual_unblock'
  )

  function addLog(msg, type = 'ok') {
    const ts = new Date().toLocaleTimeString('en-GB', { hour12: false })
    setLog(prev => [{ ts, msg, type }, ...prev].slice(0, 20))
  }

  async function handleBlock() {
    if (!ip.trim()) return
    setBusy(true)
    try {
      await api.post(`/block/${ip.trim()}`, { duration_min: Number(duration) })
      addLog(`Blocked ${ip.trim()} for ${duration} minutes`, 'ok')
      setIp('')
      refetch()
    } catch (e) {
      addLog(`Failed to block ${ip.trim()}: ${e.response?.data?.detail || e.message}`, 'err')
    } finally { setBusy(false) }
  }

  async function handleUnblock(targetIp) {
    setBusy(true)
    try {
      await api.delete(`/block/${targetIp}`)
      addLog(`Unblocked ${targetIp}`, 'ok')
      refetch()
    } catch (e) {
      addLog(`Failed to unblock ${targetIp}: ${e.response?.data?.detail || e.message}`, 'err')
    } finally { setBusy(false) }
  }

  return (
    <>
      <p className="page-title">IP block management</p>

      {/* Manual block form */}
      <div className="card" style={{ marginBottom:12 }}>
        <div className="card-title">Manual block</div>
        <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
          <input className="input" placeholder="IP address (e.g. 1.2.3.4)"
            value={ip} onChange={e => setIp(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleBlock()}
            style={{ width:220 }}
          />
          <input className="input" type="number" min={1} max={1440}
            value={duration} onChange={e => setDuration(e.target.value)}
            style={{ width:80 }}
          />
          <span style={{ fontFamily:'IBM Plex Mono', fontSize:11, color:'var(--text3)' }}>minutes</span>
          <button className="btn btn-block" onClick={handleBlock} disabled={busy || !ip.trim()}>
            {busy ? 'working...' : 'block IP'}
          </button>
        </div>
      </div>

      {/* Action log */}
      {log.length > 0 && (
        <div className="card" style={{ marginBottom:12, padding:'12px 16px' }}>
          <div className="card-title" style={{ marginBottom:8 }}>Action log</div>
          {log.map((entry, i) => (
            <div key={i} style={{
              fontFamily:'IBM Plex Mono', fontSize:11,
              color: entry.type === 'ok' ? 'var(--green)' : 'var(--red)',
              padding:'3px 0', borderBottom:'1px solid var(--border)',
            }}>
              <span style={{ color:'var(--text3)', marginRight:8 }}>{entry.ts}</span>
              {entry.type === 'ok' ? '✓' : '✗'} {entry.msg}
            </div>
          ))}
        </div>
      )}

      {/* Block list */}
      <div className="card" style={{ padding:0 }}>
        <div style={{ padding:'16px 20px 0', marginBottom:0 }}>
          <div className="card-title">
            Active blocks
            <span style={{ marginLeft:8, color:'var(--text3)', fontSize:10 }}>
              ({unique.length} IP{unique.length !== 1 ? 's' : ''})
            </span>
          </div>
        </div>
        {loading && <div className="loading">loading...</div>}
        {error   && <div className="empty">Error: {error}</div>}
        {!loading && unique.length === 0 && (
          <div className="empty">No blocked IPs in the event store.</div>
        )}
        {!loading && unique.length > 0 && (
          <table className="events-table">
            <thead>
              <tr>
                <th>IP address</th><th>Country</th><th>Risk score</th>
                <th>Attempts</th><th>Abuse %</th><th>Blocked at</th><th>Action</th>
              </tr>
            </thead>
            <tbody>
              {unique.map(e => (
                <tr key={e.id}>
                  <td className="ip-cell">{e.ip}</td>
                  <td className="score-cell">{e.country ?? '—'}</td>
                  <td className="score-cell">{e.risk_score ?? '—'}</td>
                  <td className="score-cell">{e.failed_attempts ?? '—'}</td>
                  <td className="score-cell">{e.abuse_confidence_score ?? 0}%</td>
                  <td className="score-cell" style={{ fontSize:11 }}>{formatTime(e.timestamp)}</td>
                  <td>
                    <button className="btn btn-unblock" onClick={() => handleUnblock(e.ip)} disabled={busy}>
                      unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Manual action history from event store */}
      {manualEvents.length > 0 && (
        <div className="card" style={{ marginTop:12 }}>
          <div className="card-title">Manual action history</div>
          <table className="events-table">
            <thead>
              <tr><th>Action</th><th>IP</th><th>Time</th></tr>
            </thead>
            <tbody>
              {manualEvents.slice(0, 20).map(e => (
                <tr key={e.id}>
                  <td>
                    <span className={`badge ${e.type === 'manual_block' ? 'badge-high' : 'badge-low'}`}>
                      {e.type === 'manual_block' ? 'blocked' : 'unblocked'}
                    </span>
                  </td>
                  <td className="ip-cell">{e.ip}</td>
                  <td className="score-cell" style={{ fontSize:11 }}>{formatTime(e.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
