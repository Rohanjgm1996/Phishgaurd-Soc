import { motion } from 'framer-motion'
import { AlertTriangle, Info, Shield } from 'lucide-react'
import type { Finding } from '@/types'
import { cn } from '@/lib/utils'

interface Props {
  findings: Finding[]
  maxShow?: number
}

function severity(detail: string): 'high' | 'medium' | 'low' {
  const d = detail.toLowerCase()
  if (d.includes('malware') || d.includes('clamav') || d.includes('yara') || d.includes('auto-exec')) return 'high'
  if (d.includes('macro') || d.includes('spf') || d.includes('obfuscat') || d.includes('ip-based')) return 'medium'
  return 'low'
}

const sevStyle = {
  high:   'border-red-500/30 bg-red-500/5 text-red-400',
  medium: 'border-orange-500/30 bg-orange-500/5 text-orange-400',
  low:    'border-slate-600/40 bg-slate-800/30 text-slate-400',
}
const sevIcon = {
  high:   AlertTriangle,
  medium: AlertTriangle,
  low:    Info,
}

export default function FindingCard({ findings, maxShow = 30 }: Props) {
  if (!findings.length) {
    return (
      <div className="glass-card border border-slate-700/50 rounded-xl p-6 text-center">
        <Shield className="w-8 h-8 text-green-400 mx-auto mb-2" />
        <p className="text-sm text-slate-400">No suspicious findings detected</p>
      </div>
    )
  }

  const grouped = findings.reduce<Record<string, Finding[]>>((acc, f) => {
    if (!acc[f.section]) acc[f.section] = []
    acc[f.section].push(f)
    return acc
  }, {})

  return (
    <div className="space-y-4">
      {Object.entries(grouped).map(([section, items]) => (
        <div key={section} className="glass-card border border-slate-700/50 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-700/50">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{section}</span>
          </div>
          <div className="p-3 space-y-2">
            {items.slice(0, maxShow).map((f, i) => {
              const sev = severity(f.detail)
              const Icon = sevIcon[sev]
              return (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className={cn('flex items-start gap-3 px-3 py-2.5 rounded-lg border text-sm', sevStyle[sev])}
                >
                  <Icon className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span className="leading-relaxed">{f.detail}</span>
                </motion.div>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}
