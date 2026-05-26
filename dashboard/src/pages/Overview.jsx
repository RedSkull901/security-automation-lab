// src/pages/Overview.jsx
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { usePolling } from '../hooks/useApi'

const COLOURS = { high: '#ff4d6a', medium: '#f0a500', low: '#30dca0' }

export default function Overview() {
  const { data: stats, loading, error } = usePolling('/stats', 15000)

  if (loading) return <div className="loading">loading stats...</div>
  if (error)   return <div className="empty">API unreachable — is the Docker stack running?</div>

  const chartData = [
    { name: 'High',   value: stats.high_severity   || 0 },
    { name: 'Medium', value: stats.medium_severity || 0 },
    { name: 'Low',    value: stats.low_severity    || 0 },
  ].filter(d => d.value > 0)

  const rl = stats.rate_limiter || {}

  return (
    <>
      <p className="page-title">Overview — refreshes every 15s</p>

      {/* ── Stat cards ── */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total events</div>
          <div className="stat-value blue">{stats.total_events ?? '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">High severity</div>
          <div className="stat-value red">{stats.high_severity ?? '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Medium severity</div>
          <div className="stat-value amber">{stats.medium_severity ?? '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">IPs blocked</div>
          <div className="stat-value green">{stats.blocked_ips ?? '—'}</div>
        </div>
      </div>

      {/* ── Two column ── */}
      <div className="two-col">

        {/* Severity chart */}
        <div className="card">
          <div className="card-title">Severity distribution</div>
          {chartData.length === 0
            ? <div className="empty">No events yet</div>
            : (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={chartData}
                    cx="50%" cy="50%"
                    innerRadius={55} outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {chartData.map(entry => (
                      <Cell key={entry.name}
                        fill={COLOURS[entry.name.toLowerCase()]}
                        opacity={0.85}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: '#0d1117',
                      border: '1px solid rgba(48,220,160,.2)',
                      borderRadius: 6,
                      fontFamily: 'IBM Plex Mono',
                      fontSize: 12,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )
          }
          {/* Legend */}
          <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 8 }}>
            {chartData.map(d => (
              <span key={d.name} style={{
                fontFamily: 'IBM Plex Mono', fontSize: 11,
                color: COLOURS[d.name.toLowerCase()]
              }}>
                ● {d.name} ({d.value})
              </span>
            ))}
          </div>
        </div>

        {/* Rate limiter stats */}
        <div className="card">
          <div className="card-title">Rate limiter</div>
          <table style={{ width: '100%', borderCollapse: 'collapse',
                          fontFamily: 'IBM Plex Mono', fontSize: 12 }}>
            <tbody>
              {[
                ['Strategy',    rl.strategy    ?? '—'],
                ['Max hits',    rl.max_hits    ?? '—'],
                ['Window',      rl.window_sec ? `${rl.window_sec}s` : '—'],
                ['Active keys', rl.active_keys ?? '—'],
              ].map(([k, v]) => (
                <tr key={k}>
                  <td style={{ padding: '8px 0', color: 'var(--text3)',
                               borderBottom: '1px solid var(--border)' }}>{k}</td>
                  <td style={{ padding: '8px 0', color: 'var(--green)',
                               borderBottom: '1px solid var(--border)',
                               textAlign: 'right' }}>{v}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <div style={{ marginTop: 20 }}>
            <div className="card-title">Generated at</div>
            <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 11,
                           color: 'var(--text2)' }}>
              {stats.generated_at
                ? new Date(stats.generated_at).toLocaleString()
                : '—'}
            </span>
          </div>
        </div>

      </div>
    </>
  )
}
