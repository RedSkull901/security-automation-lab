import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { usePolling } from '../hooks/useApi'

const COLOURS = { high: '#ff4d6a', medium: '#f0a500', low: '#30dca0' }

function buildTimeline(events) {
  const buckets = {}
  const now = Date.now()
  // Create 24 hourly buckets
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now - i * 3600000)
    const key = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false })
    buckets[key] = { time: key, high: 0, medium: 0, low: 0 }
  }
  events.forEach(e => {
    if (!e.timestamp) return
    const age = now - new Date(e.timestamp)
    if (age > 86400000) return
    const key = new Date(e.timestamp).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false })
    const nearest = Object.keys(buckets).reduce((a, b) =>
      Math.abs(parseInt(b) - parseInt(key)) < Math.abs(parseInt(a) - parseInt(key)) ? b : a
    )
    const sev = e.severity || 'low'
    if (buckets[nearest]) buckets[nearest][sev]++
  })
  return Object.values(buckets).filter((_, i) => i % 2 === 0) // every 2 hours
}

function buildTopIPs(events) {
  const counts = {}
  events.forEach(e => {
    if (!e.ip) return
    if (!counts[e.ip]) counts[e.ip] = { ip: e.ip, count: 0, risk: 0, severity: e.severity }
    counts[e.ip].count++
    counts[e.ip].risk = Math.max(counts[e.ip].risk, e.risk_score || 0)
  })
  return Object.values(counts).sort((a, b) => b.risk - a.risk).slice(0, 8)
}

export default function Overview() {
  const { data: stats,  loading: sl } = usePolling('/stats', 15000)
  const { data: evData, loading: el } = usePolling('/events?limit=200', 15000)

  if (sl) return <div className="loading">loading stats...</div>
  if (!stats) return <div className="empty">API unreachable — is the Docker stack running?</div>

  const events   = evData?.events ?? []
  const timeline = buildTimeline(events)
  const topIPs   = buildTopIPs(events)
  const rl       = stats.rate_limiter || {}

  const chartData = [
    { name: 'High',   value: stats.high_severity   || 0 },
    { name: 'Medium', value: stats.medium_severity || 0 },
    { name: 'Low',    value: stats.low_severity    || 0 },
  ].filter(d => d.value > 0)

  const tooltipStyle = {
    background: '#0d1117', border: '1px solid rgba(48,220,160,.2)',
    borderRadius: 6, fontFamily: 'IBM Plex Mono', fontSize: 11,
  }

  return (
    <>
      <p className="page-title">Overview — refreshes every 15s</p>

      {/* Stat cards */}
      <div className="stats-grid">
        {[
          { label: 'Total events',    value: stats.total_events   ?? '—', cls: 'blue'  },
          { label: 'High severity',   value: stats.high_severity  ?? '—', cls: 'red'   },
          { label: 'Medium severity', value: stats.medium_severity ?? '—', cls: 'amber' },
          { label: 'IPs blocked',     value: stats.blocked_ips    ?? '—', cls: 'green' },
        ].map(s => (
          <div className="stat-card" key={s.label}>
            <div className="stat-label">{s.label}</div>
            <div className={`stat-value ${s.cls}`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Row 1: Severity pie + Rate limiter */}
      <div className="two-col">
        <div className="card">
          <div className="card-title">Severity distribution</div>
          {chartData.length === 0
            ? <div className="empty">No events yet</div>
            : <>
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie data={chartData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={3} dataKey="value">
                      {chartData.map(entry => (
                        <Cell key={entry.name} fill={COLOURS[entry.name.toLowerCase()]} opacity={0.85} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div style={{ display:'flex', gap:16, justifyContent:'center', marginTop:4 }}>
                  {chartData.map(d => (
                    <span key={d.name} style={{ fontFamily:'IBM Plex Mono', fontSize:11, color:COLOURS[d.name.toLowerCase()] }}>
                      ● {d.name} ({d.value})
                    </span>
                  ))}
                </div>
              </>
          }
        </div>

        <div className="card">
          <div className="card-title">Rate limiter</div>
          <table style={{ width:'100%', borderCollapse:'collapse', fontFamily:'IBM Plex Mono', fontSize:12 }}>
            <tbody>
              {[['Strategy', rl.strategy??'—'], ['Max hits', rl.max_hits??'—'],
                ['Window', rl.window_sec?`${rl.window_sec}s`:'—'], ['Active keys', rl.active_keys??'—']
              ].map(([k,v]) => (
                <tr key={k}>
                  <td style={{ padding:'8px 0', color:'var(--text3)', borderBottom:'1px solid var(--border)' }}>{k}</td>
                  <td style={{ padding:'8px 0', color:'var(--green)', borderBottom:'1px solid var(--border)', textAlign:'right' }}>{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ marginTop:16 }}>
            <div className="card-title">Last refreshed</div>
            <span style={{ fontFamily:'IBM Plex Mono', fontSize:11, color:'var(--text2)' }}>
              {stats.generated_at ? new Date(stats.generated_at).toLocaleString() : '—'}
            </span>
          </div>
        </div>
      </div>

      {/* Row 2: Timeline bar chart */}
      <div className="card" style={{ marginBottom:12 }}>
        <div className="card-title">Alert timeline — last 24 hours</div>
        {events.length === 0
          ? <div className="empty">No events to chart</div>
          : <ResponsiveContainer width="100%" height={160}>
              <BarChart data={timeline} margin={{ top:4, right:8, left:-20, bottom:0 }}>
                <XAxis dataKey="time" tick={{ fontFamily:'IBM Plex Mono', fontSize:10, fill:'var(--text3)' }} />
                <YAxis tick={{ fontFamily:'IBM Plex Mono', fontSize:10, fill:'var(--text3)' }} allowDecimals={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="high"   stackId="a" fill="#ff4d6a" opacity={0.8} />
                <Bar dataKey="medium" stackId="a" fill="#f0a500" opacity={0.8} />
                <Bar dataKey="low"    stackId="a" fill="#30dca0" opacity={0.8} />
              </BarChart>
            </ResponsiveContainer>
        }
      </div>

      {/* Row 3: Top attacking IPs */}
      <div className="card">
        <div className="card-title">Top attacking IPs</div>
        {topIPs.length === 0
          ? <div className="empty">No events yet</div>
          : <table className="events-table">
              <thead>
                <tr>
                  <th>#</th><th>IP address</th><th>Detections</th>
                  <th>Max risk score</th><th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {topIPs.map((row, i) => (
                  <tr key={row.ip}>
                    <td style={{ color:'var(--text3)', fontFamily:'IBM Plex Mono', fontSize:11 }}>{i+1}</td>
                    <td className="ip-cell">{row.ip}</td>
                    <td className="score-cell">{row.count}</td>
                    <td className="score-cell">{row.risk}</td>
                    <td><span className={`badge badge-${row.severity}`}>{row.severity}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
        }
      </div>
    </>
  )
}
