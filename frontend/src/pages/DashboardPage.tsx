import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Shield, AlertTriangle, ShieldAlert, ShieldCheck, TrendingUp } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { historyApi } from '@/lib/api'
import type { DashboardStats } from '@/types'
import MetricCard from '@/components/ui/MetricCard'
import RiskChart from '@/components/dashboard/RiskChart'
import ActivityTimeline from '@/components/dashboard/ActivityTimeline'
import EmptyState from '@/components/ui/EmptyState'
import { CardSkeleton } from '@/components/ui/LoadingSkeleton'
import { useAuth } from '@/hooks/useAuth'

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const { user } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    historyApi.getDashboard()
      .then(setStats)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const hour = new Date().getHours()
  const greeting = hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening'

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Hero greeting */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <h2 className="text-2xl font-display font-bold text-white">
          {greeting}, <span className="text-gradient-cyber">{user?.full_name || user?.username}</span> 👋
        </h2>
        <p className="text-slate-500 text-sm mt-1">
          Here's your threat analysis overview for today.
        </p>
      </motion.div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {loading ? (
          Array.from({ length: 4 }).map((_, i) => <CardSkeleton key={i} />)
        ) : stats ? (
          <>
            <MetricCard title="Total Analyses" value={stats.total}      icon={Shield}      color="cyan"   index={0} />
            <MetricCard title="Malicious"       value={stats.malicious}  icon={ShieldAlert} color="red"    index={1} />
            <MetricCard title="Suspicious"      value={stats.suspicious + stats.likely_phishing} icon={AlertTriangle} color="orange" index={2} />
            <MetricCard title="Benign"          value={stats.benign}     icon={ShieldCheck} color="green"  index={3} />
          </>
        ) : null}
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity timeline — 2 cols */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25 }}
          className="lg:col-span-2 glass-card border border-slate-700/50 rounded-2xl p-5"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-display font-semibold text-slate-200 text-sm">Recent Analyses</h3>
              <p className="text-xs text-slate-500 mt-0.5">Latest uploaded samples</p>
            </div>
            <button
              onClick={() => navigate('/history')}
              className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              View all →
            </button>
          </div>
          {loading ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="h-12 rounded-xl bg-slate-800/40 animate-pulse" />
              ))}
            </div>
          ) : stats?.recent?.length ? (
            <ActivityTimeline items={stats.recent} />
          ) : (
            <EmptyState
              title="No analyses yet"
              description="Start by uploading an email or suspicious file."
              action={{ label: 'Analyze a file', to: '/upload' }}
            />
          )}
        </motion.div>

        {/* Risk distribution */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.35 }}
          className="glass-card border border-slate-700/50 rounded-2xl p-5"
        >
          <div className="mb-4">
            <h3 className="font-display font-semibold text-slate-200 text-sm">Risk Distribution</h3>
            <p className="text-xs text-slate-500 mt-0.5">Verdict breakdown</p>
          </div>
          {stats ? <RiskChart stats={stats} /> : (
            <div className="h-48 animate-pulse bg-slate-800/40 rounded-xl" />
          )}
          {stats && (
            <div className="mt-4 pt-4 border-t border-slate-700/50 grid grid-cols-2 gap-2">
              {[
                { label: 'Malicious',  v: stats.malicious,  c: '#ef4444' },
                { label: 'Phishing',   v: stats.likely_phishing, c: '#f97316' },
                { label: 'Suspicious', v: stats.suspicious, c: '#eab308' },
                { label: 'Benign',     v: stats.benign,     c: '#22c55e' },
              ].map(({ label, v, c }) => (
                <div key={label} className="flex items-center justify-between p-2 rounded-lg bg-slate-800/30">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: c }} />
                    <span className="text-[11px] text-slate-400">{label}</span>
                  </div>
                  <span className="text-[11px] font-bold font-mono text-white">{v}</span>
                </div>
              ))}
            </div>
          )}
        </motion.div>
      </div>

      {/* Quick actions */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.45 }}
        className="glass-card border border-slate-700/50 rounded-2xl p-5"
      >
        <h3 className="font-display font-semibold text-slate-200 text-sm mb-4">Quick Actions</h3>
        <div className="flex flex-wrap gap-3">
          {[
            { label: 'Analyze Email (.eml)', icon: '📧', to: '/upload', color: 'cyan' },
            { label: 'Analyze Attachment',   icon: '📎', to: '/upload', color: 'purple' },
            { label: 'View History',         icon: '📋', to: '/history', color: 'slate' },
          ].map(({ label, icon, to, color }) => (
            <motion.button
              key={label}
              whileHover={{ scale: 1.03, y: -2 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => navigate(to)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium text-slate-300 hover:text-white border border-slate-700/60 hover:border-cyan-500/30 bg-slate-800/30 hover:bg-slate-800/60 transition-all"
            >
              <span>{icon}</span>
              {label}
            </motion.button>
          ))}
        </div>
      </motion.div>
    </div>
  )
}
