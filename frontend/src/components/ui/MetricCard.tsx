import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'
import type { LucideIcon } from 'lucide-react'

interface Props {
  title: string
  value: number | string
  icon: LucideIcon
  color?: 'cyan' | 'green' | 'yellow' | 'orange' | 'red' | 'purple'
  delta?: string
  subtitle?: string
  index?: number
}

const colorMap = {
  cyan:   { icon: 'text-cyan-400',   bg: 'from-cyan-500/10 to-transparent',   border: 'border-cyan-500/20',   glow: 'rgba(6,182,212,0.15)' },
  green:  { icon: 'text-green-400',  bg: 'from-green-500/10 to-transparent',  border: 'border-green-500/20',  glow: 'rgba(34,197,94,0.15)' },
  yellow: { icon: 'text-yellow-400', bg: 'from-yellow-500/10 to-transparent', border: 'border-yellow-500/20', glow: 'rgba(234,179,8,0.15)' },
  orange: { icon: 'text-orange-400', bg: 'from-orange-500/10 to-transparent', border: 'border-orange-500/20', glow: 'rgba(249,115,22,0.15)' },
  red:    { icon: 'text-red-400',    bg: 'from-red-500/10 to-transparent',    border: 'border-red-500/20',    glow: 'rgba(239,68,68,0.15)' },
  purple: { icon: 'text-purple-400', bg: 'from-purple-500/10 to-transparent', border: 'border-purple-500/20', glow: 'rgba(168,85,247,0.15)' },
}

export default function MetricCard({ title, value, icon: Icon, color = 'cyan', delta, subtitle, index = 0 }: Props) {
  const c = colorMap[color]

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: index * 0.08, ease: [0.22, 1, 0.36, 1] }}
      whileHover={{ y: -3, transition: { duration: 0.2 } }}
      className={cn('glass-card relative overflow-hidden p-5 group cursor-default border', c.border)}
    >
      {/* Gradient top strip */}
      <div className={cn('absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r', c.bg)} />

      {/* Glow on hover */}
      <motion.div
        className="absolute inset-0 rounded-[14px] opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{ background: `radial-gradient(ellipse at 50% 0%, ${c.glow} 0%, transparent 70%)` }}
      />

      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-500 mb-2 uppercase tracking-wider">{title}</p>
          <motion.p
            className="font-display font-bold text-2xl text-white"
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: index * 0.08 + 0.2 }}
          >
            {value}
          </motion.p>
          {subtitle && <p className="text-xs text-slate-500 mt-1">{subtitle}</p>}
          {delta && (
            <div className="flex items-center gap-1 mt-2">
              <span className="text-[10px] font-medium text-slate-400">{delta}</span>
            </div>
          )}
        </div>
        <div className={cn('p-2.5 rounded-xl', `bg-gradient-to-br ${c.bg}`, `border ${c.border}`)}>
          <Icon className={cn('w-5 h-5', c.icon)} />
        </div>
      </div>
    </motion.div>
  )
}
