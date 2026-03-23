import { motion } from 'framer-motion'
import { Shield } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'

interface Props {
  title?: string
  description?: string
  icon?: LucideIcon
  action?: { label: string; to: string }
}

export default function EmptyState({
  title = 'No analyses yet',
  description = 'Upload a suspicious email or file to get started.',
  icon: Icon = Shield,
  action = { label: 'Start Analysis', to: '/upload' },
}: Props) {
  const navigate = useNavigate()
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="flex flex-col items-center justify-center py-20 text-center"
    >
      <div className="relative mb-6">
        <div className="w-20 h-20 rounded-2xl flex items-center justify-center"
          style={{ background: 'linear-gradient(135deg, rgba(6,182,212,0.1), rgba(139,92,246,0.1))', border: '1px solid rgba(6,182,212,0.15)' }}>
          <Icon className="w-9 h-9 text-cyan-500/50" />
        </div>
        <div className="absolute inset-0 rounded-2xl blur-xl opacity-20"
          style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.5), transparent)' }} />
      </div>
      <h3 className="font-display font-semibold text-slate-300 text-lg mb-2">{title}</h3>
      <p className="text-slate-500 text-sm max-w-xs mb-6">{description}</p>
      {action && (
        <button onClick={() => navigate(action.to)} className="cyber-btn-primary">
          {action.label}
        </button>
      )}
    </motion.div>
  )
}
