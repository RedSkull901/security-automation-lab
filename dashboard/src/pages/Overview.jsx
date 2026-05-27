import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { usePolling } from '../hooks/useApi'

const COLOURS = { high: '#ff4d6a', medium: '#f0a500', low: '#30dca0' }

function buildTimeline(events) {
  const now = Date.now()
  const buckets = {}
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now - i * 3600000)
    const key = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false })
    buckets[i] = { time: key, high: 0, medium: 0, low: 0 }
  }
  events.forEach(e => {
    if (!e.timestamp) return
    const raw = e.timestamp.includes('+') || e.timestamp.endsWith('Z') ? e.timestamp : e.timestamp + 'Z'
    const ts = new Date(raw)
    const age = now - ts.getTime()
    if (age < 0 || age > 86400000) return
    const bucket = Math.min(23, Math.floor(age / 3600000))
    if (buckets[bucket]) buckets[bucket][e.severity || 'low']++
  })
  // Show every 2 hours for readability, keep all for data accuracy
  return Object.values(buckets).reverse().filter((_, i) => i % 2 === 0)
}

function buildTopIPs(events) {
  const map = {}
  events.forEach(e => {
    if (!e.ip) return
    if (!map[e.ip]) map[e.ip] = { ip: e.ip, count: 0, risk: 0, severity: e.severity, country: e.country }
    map[e.ip].count++
    if ((e.risk_score || 0) > map[e.ip].risk) {
      map[e.ip].risk = e.risk_score || 0
      map[e.ip].severity = e.severity
      map[e.ip].country = e.country
    }
  })
  return Object.values(map).sort((a, b) => b.risk - a.risk).slice(0, 8)
}

const tooltipStyle = {
  background: '#0d1117', border: '1px solid rgba(48,220,160,.2)',
  borderRadius: 6, fontFamily: 'IBM Plex Mono', fontSize: 11,
}

export default function Overview() {
  const { data: stats }  = usePolling('/stats', 15000)
  const { data: evData } = usePolling('/events?limit=500', 15000)

  if (!stats) return <div className="loading">connecting to API...</div>

  const events   = evData?.events ?? []
  const timeline = buildTimeline(events)
  const topIPs   = buildTopIPs(events)
  const rl       = stats.rate_limiter || {}

  const chartData = [
    { name: 'High',   value: stats.high_severity   || 0 },
    { name: 'Medium', value: stats.medium_severity || 0 },
    { name: 'Low',    value: stats.low_severity    || 0 },
  ].filter(d => d.value > 0)

  const hasTimeline = timeline.some(b => b.high + b.medium + b.low > 0)

  return (
    <>
      <p className="page-title">Overview — refreshes every 15s</p>

      <div className="stats-grid">
        {[
          { label: 'Total events',    value: stats.total_events    ?? '—', cls: 'blue'  },
          { label: 'High severity',   value: stats.high_severity   ?? '—', cls: 'red'   },
          { label: 'Medium severity', value: stats.medium_severity ?? '—', cls: 'amber' },
          { label: 'IPs blocked',     value: stats.blocked_ips     ?? '—', cls: 'green' },
        ].map(s => (
          <div className="stat-card" key={s.label}>
            <div className="stat-label">{s.label}</div>
            <div className={`stat-value ${s.cls}`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Row 1: Pie + Rate limiter */}
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
          <div className="card-title">Rate limiter status</div>
          <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:16 }}>
            <span style={{
              width:8, height:8, borderRadius:'50%', flexShrink:0,
              background: rl.active_keys > 0 ? 'var(--amber)' : 'var(--green)',
              boxShadow: rl.active_keys > 0 ? '0 0 6px var(--amber)' : '0 0 6px var(--green)',
            }}/>
            <span style={{ fontFamily:'IBM Plex Mono', fontSize:12, color:'var(--text2)' }}>
              {rl.strategy ?? '—'} · {rl.max_hits ?? '—'} hits / {rl.window_sec ?? '—'}s
            </span>
          </div>
          <div style={{
            background:'var(--bg3)', borderRadius:'var(--radius)',
            padding:'10px 14px', fontFamily:'IBM Plex Mono', fontSize:12,
          }}>
            <span style={{ color:'var(--text3)' }}>Active tracked IPs  </span>
            <span style={{ color: rl.active_keys > 0 ? 'var(--amber)' : 'var(--green)', float:'right' }}>
              {rl.active_keys ?? 0}
            </span>
          </div>
          <div style={{ marginTop:16 }}>
            <div className="card-title">Last refreshed</div>
            <span style={{ fontFamily:'IBM Plex Mono', fontSize:11, color:'var(--text2)' }}>
              {stats.generated_at ? new Date(
                stats.generated_at.includes('+') || stats.generated_at.endsWith('Z')
                  ? stats.generated_at : stats.generated_at + 'Z'
              ).toLocaleString() : '—'}
            </span>
          </div>
        </div>
      </div>

      {/* Row 2: Timeline */}
      <div className="card" style={{ marginBottom:12 }}>
        <div className="card-title">Alert timeline — last 24 hours</div>
        {!hasTimeline
          ? <div className="empty">No events in last 24 hours</div>
          : <ResponsiveContainer width="100%" height={160}>
              <BarChart data={timeline} margin={{ top:4, right:8, left:-20, bottom:0 }}>
                <XAxis dataKey="time" tick={{ fontFamily:'IBM Plex Mono', fontSize:10, fill:'var(--text3)' }} />
                <YAxis tick={{ fontFamily:'IBM Plex Mono', fontSize:10, fill:'var(--text3)' }} allowDecimals={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="high"   stackId="a" fill="#ff4d6a" opacity={0.85} name="High" />
                <Bar dataKey="medium" stackId="a" fill="#f0a500" opacity={0.85} name="Medium" />
                <Bar dataKey="low"    stackId="a" fill="#30dca0" opacity={0.85} name="Low" />
              </BarChart>
            </ResponsiveContainer>
        }
      </div>

      {/* Row 3: Top IPs */}
      <div className="card">
        <div className="card-title">Top attacking IPs</div>
        {topIPs.length === 0
          ? <div className="empty">No events yet</div>
          : <table className="events-table">
              <thead>
                <tr>
                  <th>#</th><th>IP address</th><th>Country</th>
                  <th>Detections</th><th>Max risk</th><th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {topIPs.map((row, i) => (
                  <tr key={row.ip}>
                    <td style={{ color:'var(--text3)', fontFamily:'IBM Plex Mono', fontSize:11 }}>{i+1}</td>
                    <td className="ip-cell">{row.ip}</td>
                    <td className="score-cell">{row.country ?? '—'}</td>
                    <td className="score-cell">{row.count}</td>
                    <td className="score-cell">{row.risk}</td>
                    <td><span className={`badge badge-${row.severity || 'low'}`}>{row.severity || 'low'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
        }
      </div>
    </>
  )
}
