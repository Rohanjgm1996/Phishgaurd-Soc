import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import type { DashboardStats } from '@/types'

interface Props { stats: DashboardStats }

const DATA_KEYS = [
  { key: 'malicious',      label: 'Malicious',       color: '#ef4444' },
  { key: 'likely_phishing',label: 'Likely Phishing',  color: '#f97316' },
  { key: 'suspicious',     label: 'Suspicious',       color: '#eab308' },
  { key: 'benign',         label: 'Benign',           color: '#22c55e' },
] as const

export default function RiskChart({ stats }: Props) {
  const data = DATA_KEYS.map(d => ({
    name: d.label,
    value: stats[d.key] ?? 0,
    color: d.color,
  })).filter(d => d.value > 0)

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500 text-sm">
        No data yet
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={55}
          outerRadius={80}
          paddingAngle={3}
          dataKey="value"
          strokeWidth={0}
        >
          {data.map((entry, i) => (
            <Cell key={i} fill={entry.color} style={{ filter: `drop-shadow(0 0 4px ${entry.color}60)` }} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: 'rgba(13,21,38,0.95)',
            border: '1px solid rgba(6,182,212,0.2)',
            borderRadius: '8px',
            color: '#e2e8f0',
            fontSize: '12px',
          }}
          formatter={(value: number, name: string) => [value, name]}
        />
        <Legend
          iconType="circle"
          iconSize={8}
          formatter={(value) => (
            <span style={{ color: '#94a3b8', fontSize: '11px' }}>{value}</span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}
