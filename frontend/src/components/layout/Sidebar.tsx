import { NavLink, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  LayoutDashboard,
  Upload,
  History,
  Shield,
  ChevronRight,
  Zap,
  ShieldAlert,
  FlaskConical,
  User,
  Lock,
} from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { cn } from '@/lib/utils'

const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/upload', icon: Upload, label: 'Analyze' },
  { to: '/history', icon: History, label: 'History' },
  { to: '/profile', icon: User, label: 'Profile' },
  { to: '/security', icon: Lock, label: 'Security' },
  { to: '/threat-intelligence/virustotal', icon: ShieldAlert, label: 'Threat Intelligence' },
  { to: '/sandbox/anyrun', icon: FlaskConical, label: 'Sandbox' },
]

export default function Sidebar() {
  const { user } = useAuth()
  const location = useLocation()

  return (
    <motion.aside
      initial={{ x: -260 }}
      animate={{ x: 0 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="w-[220px] flex-shrink-0 flex flex-col h-full"
      style={{
        background: 'linear-gradient(180deg, #0a0f1e 0%, #080c18 100%)',
        borderRight: '1px solid rgba(6,182,212,0.1)',
      }}
    >
      <div className="px-5 py-6 border-b border-cyan-500/10">
        <div className="flex items-center gap-3">
          <div
            className="relative w-9 h-9 flex items-center justify-center rounded-xl"
            style={{
              background: 'linear-gradient(135deg, rgba(6,182,212,0.2), rgba(139,92,246,0.2))',
              border: '1px solid rgba(6,182,212,0.3)',
            }}
          >
            <Shield className="w-5 h-5 text-cyan-400" />
            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
          </div>
          <div>
            <div className="font-display font-bold text-white text-sm leading-none">
              PhishGuard SOC
            </div>
            <div className="text-[10px] text-cyan-500/70 mt-0.5 tracking-wide">
              Threat Intelligence by Rohan M
            </div>
          </div>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1">
        <div className="px-2 mb-3">
          <span className="text-[10px] font-semibold tracking-widest uppercase text-slate-600">
            Navigation
          </span>
        </div>

        {navItems.map(({ to, icon: Icon, label }) => {
          const active = location.pathname === to || (to !== '/dashboard' && location.pathname.startsWith(to))

          return (
            <NavLink key={to} to={to}>
              <motion.div
                whileHover={{ x: 3 }}
                transition={{ duration: 0.15 }}
                className={cn(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group relative',
                  active ? 'text-cyan-300' : 'text-slate-400 hover:text-slate-200'
                )}
                style={
                  active
                    ? {
                      background:
                        'linear-gradient(135deg, rgba(6,182,212,0.12), rgba(139,92,246,0.08))',
                      border: '1px solid rgba(6,182,212,0.2)',
                    }
                    : {}
                }
              >
                {active && (
                  <motion.span
                    layoutId="sidebar-indicator"
                    className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-cyan-400 rounded-full"
                    transition={{ duration: 0.2 }}
                  />
                )}
                <Icon
                  className={cn(
                    'w-4 h-4 flex-shrink-0',
                    active ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-300'
                  )}
                />
                {label}
                {active && <ChevronRight className="w-3 h-3 ml-auto text-cyan-500/50" />}
              </motion.div>
            </NavLink>
          )
        })}
      </nav>

      <div className="px-4 py-3 border-t border-cyan-500/10">
        <div className="glass-card p-3 rounded-xl">
          <div className="flex items-center gap-2 mb-2">
            <Zap className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-xs font-semibold text-slate-300">System Status</span>
          </div>
          <div className="space-y-1.5">
            {[['Engine', 'Online'], ['YARA', 'Active'], ['ClamAV', 'Config']].map(([k, v]) => (
              <div key={k} className="flex items-center justify-between">
                <span className="text-[10px] text-slate-500">{k}</span>
                <span
                  className={cn(
                    'text-[10px] font-mono font-semibold',
                    v === 'Online' || v === 'Active' ? 'text-green-400' : 'text-yellow-400'
                  )}
                >
                  {v}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="px-4 py-4 border-t border-cyan-500/10">
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-cyan-300"
            style={{
              background: 'linear-gradient(135deg, rgba(6,182,212,0.25), rgba(139,92,246,0.25))',
              border: '1px solid rgba(6,182,212,0.3)',
            }}
          >
            {user?.username?.[0]?.toUpperCase() ?? 'A'}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-semibold text-slate-200 truncate">
              {user?.username ?? 'analyst'}
            </div>
            <div className="text-[10px] text-slate-500 capitalize">
              {user?.role ?? 'analyst'}
            </div>
          </div>
        </div>
      </div>
    </motion.aside>
  )
}