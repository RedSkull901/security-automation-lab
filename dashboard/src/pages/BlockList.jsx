// src/pages/BlockList.jsx
import { useState } from 'react'
import { usePolling, api } from '../hooks/useApi'

export default function BlockList() {
  const [ip,       setIp]       = useState('')
  const [duration, setDuration] = useState(30)
  const [msg,      setMsg]      = useState(null)
  const [busy,     setBusy]     = useState(false)

  // Pull blocked events from the event store
  const { data, loading, error, refetch } = usePolling('/events?limit=200', 30000)

  const blocked = (data?.events ?? []).filter(e =>
    e.response?.action === 'block_temp' && e.response?.success === true
  )

  // Deduplicate by IP — show latest per IP
  const seen = new Set()
  const unique = blocked.filter(e => {
    if (seen.has(e.ip)) return false
    seen.add(e.ip); return true
  })

  async function handleBlock() {
    if (!ip.trim()) return
    setBusy(true); setMsg(null)
    try {
      await api.post(`/block/${ip.trim()}`, { duration_min: Number(duration) })
      setMsg({ type: 'ok', text: `Blocked ${ip} for ${duration} minutes.` })
      setIp('')
      refetch()
    } catch (e) {
      setMsg({ type: 'err', text: e.response?.data?.detail || e.message })
    } finally { setBusy(false) }
  }

  async function handleUnblock(targetIp) {
    setBusy(true); setMsg(null)
    try {
      await api.delete(`/block/${targetIp}`)
      setMsg({ type: 'ok', text: `Unblocked ${targetIp}.` })
      refetch()
    } catch (e) {
      setMsg({ type: 'err', text: e.response?.data?.detail || e.message })
    } finally { setBusy(false) }
  }

  return (
    <>
      <p className="page-title">IP block management</p>

      {/* ── Manual block form ── */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title">Manual block</div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            className="input"
            placeholder="IP address (e.g. 1.2.3.4)"
            value={ip}
            onChange={e => setIp(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleBlock()}
            style={{ width: 220 }}
          />
          <input
            className="input"
            type="number"
            min={1} max={1440}
            value={duration}
            onChange={e => setDuration(e.target.value)}
            style={{ width: 80 }}
          />
          <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 11,
                         color: 'var(--text3)' }}>minutes</span>
          <button
            className="btn btn-block"
            onClick={handleBlock}
            disabled={busy || !ip.trim()}
          >
            {busy ? 'blocking...' : 'block IP'}
          </button>
        </div>
        {msg && (
          <div style={{
            marginTop: 10,
            fontFamily: 'IBM Plex Mono', fontSize: 11,
            color: msg.type === 'ok' ? 'var(--green)' : 'var(--red)',
          }}>
            {msg.type === 'ok' ? '✓' : '✗'} {msg.text}
          </div>
        )}
      </div>

      {/* ── Block list ── */}
      <div className="card" style={{ padding: 0 }}>
        {loading && <div className="loading">loading block list...</div>}
        {error   && <div className="empty">Error: {error}</div>}
        {!loading && unique.length === 0 && (
          <div className="empty">No blocked IPs in the event store.</div>
        )}
        {!loading && unique.length > 0 && (
          <table className="events-table">
            <thead>
              <tr>
                <th>IP address</th>
                <th>Country</th>
                <th>Risk score</th>
                <th>Attempts</th>
                <th>Blocked at</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {unique.map(e => (
                <tr key={e.id}>
                  <td className="ip-cell">{e.ip}</td>
                  <td className="score-cell">{e.country ?? '—'}</td>
                  <td className="score-cell">{e.risk_score ?? '—'}</td>
                  <td className="score-cell">{e.failed_attempts ?? '—'}</td>
                  <td className="score-cell" style={{ fontSize: 11 }}>
                    {e.timestamp ? new Date(e.timestamp).toLocaleString() : '—'}
                  </td>
                  <td>
                    <button
                      className="btn btn-unblock"
                      onClick={() => handleUnblock(e.ip)}
                      disabled={busy}
                    >
                      unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
