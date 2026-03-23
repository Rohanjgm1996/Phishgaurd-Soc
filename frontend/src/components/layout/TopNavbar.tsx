import { useEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Bell,
  LogOut,
  Upload,
  User,
  Shield,
  ChevronDown,
  Settings,
  History,
  CheckCheck,
} from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'

const routeTitles: Record<string, string> = {
  '/dashboard': 'Dashboard',
  '/upload': 'Analyze Sample',
  '/history': 'Analysis History',
  '/profile': 'My Profile',
  '/security': 'Security Center',
}

export default function TopNavbar() {
  const { logout, user, markNotificationsRead } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()

  const [menuOpen, setMenuOpen] = useState(false)
  const [bellOpen, setBellOpen] = useState(false)

  const menuRef = useRef<HTMLDivElement | null>(null)
  const bellRef = useRef<HTMLDivElement | null>(null)

  const title =
    routeTitles[location.pathname] ??
    (location.pathname.startsWith('/result')
      ? 'Analysis Report'
      : 'PhishGuard SOC — Threat Intelligence by Rohan M')

  const displayName = user?.full_name?.trim() || user?.username || 'Analyst'
  const initial = displayName?.[0]?.toUpperCase() || 'A'
  const notifications = user?.notifications || []
  const unreadCount = notifications.filter((n) => n.unread).length

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      const target = event.target as Node
      if (menuRef.current && !menuRef.current.contains(target)) setMenuOpen(false)
      if (bellRef.current && !bellRef.current.contains(target)) setBellOpen(false)
    }

    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setMenuOpen(false)
        setBellOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    document.addEventListener('keydown', handleEscape)

    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [])

  const todayText = useMemo(
    () =>
      new Date().toLocaleDateString('en-US', {
        weekday: 'long',
        month: 'long',
        day: 'numeric',
      }),
    []
  )

  function handleLogout() {
    setMenuOpen(false)
    logout()
    navigate('/login')
  }

  return (
    <motion.header
      initial={{ y: -60, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      className="h-[60px] flex items-center justify-between px-6 flex-shrink-0 relative z-40"
      style={{
        background: 'rgba(8,12,24,0.85)',
        backdropFilter: 'blur(20px)',
        borderBottom: '1px solid rgba(6,182,212,0.08)',
      }}
    >
      <div>
        <h1 className="font-display font-semibold text-white text-[15px]">{title}</h1>
        <p className="text-[11px] text-slate-500 mt-0.5">{todayText}</p>
      </div>

      <div className="flex items-center gap-2 relative z-50">
        <button
          onClick={() => navigate('/upload')}
          className="cyber-btn text-xs hidden sm:flex"
        >
          <Upload className="w-3.5 h-3.5" />
          Analyze
        </button>

        <div className="relative flex items-center" ref={bellRef}>
          <button
            onClick={() => {
              setBellOpen((prev) => !prev)
              setMenuOpen(false)
            }}
            className="w-9 h-9 flex items-center justify-center rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors relative"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute top-2 right-2 min-w-[14px] h-[14px] px-1 rounded-full bg-cyan-400 text-[9px] text-slate-950 font-bold flex items-center justify-center">
                {unreadCount}
              </span>
            )}
          </button>

          <AnimatePresence>
            {bellOpen && (
              <motion.div
                initial={{ opacity: 0, y: 8, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 6, scale: 0.98 }}
                transition={{ duration: 0.22, ease: 'easeOut' }}
                className="absolute right-0 top-full mt-3 w-80 rounded-2xl overflow-hidden z-[999]"
                style={{
                  background:
                    'linear-gradient(180deg, rgba(10,15,30,0.98) 0%, rgba(8,12,24,0.98) 100%)',
                  border: '1px solid rgba(6,182,212,0.14)',
                  boxShadow: '0 20px 60px rgba(2,8,23,0.45)',
                }}
              >
                <div className="flex items-center justify-between px-4 py-3 border-b border-cyan-500/10">
                  <div>
                    <div className="text-sm font-semibold text-slate-100">Notifications</div>
                    <div className="text-[11px] text-slate-500 mt-1">
                      Analyst alerts and account reminders
                    </div>
                  </div>
                  <button
                    onClick={markNotificationsRead}
                    className="inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200"
                  >
                    <CheckCheck className="w-3.5 h-3.5" />
                    Mark all read
                  </button>
                </div>

                <div className="max-h-80 overflow-auto">
                  {notifications.length > 0 ? (
                    notifications.map((item) => (
                      <div
                        key={item.id}
                        className="px-4 py-3 border-b border-white/5 hover:bg-slate-800/40"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="text-sm text-slate-100">{item.title}</div>
                            <div className="text-xs text-slate-400 mt-1">{item.description}</div>
                            <div className="text-[10px] text-slate-500 mt-2">{item.time}</div>
                          </div>
                          {item.unread && (
                            <span className="mt-1 w-2 h-2 rounded-full bg-cyan-400 flex-shrink-0" />
                          )}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="px-4 py-8 text-center text-sm text-slate-500">
                      No notifications
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <div className="relative flex items-center" ref={menuRef}>
          <button
            onClick={() => {
              setMenuOpen((prev) => !prev)
              setBellOpen(false)
            }}
            className="flex items-center gap-2 pl-2 pr-3 h-10 rounded-xl border border-cyan-500/10 bg-slate-900/70 hover:bg-slate-800/80 transition-colors"
          >
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-cyan-300"
              style={{
                background:
                  'linear-gradient(135deg, rgba(6,182,212,0.25), rgba(139,92,246,0.25))',
                border: '1px solid rgba(6,182,212,0.25)',
              }}
            >
              {initial}
            </div>

            <div className="hidden sm:block text-left">
              <div className="text-xs font-semibold text-slate-200 leading-none">
                {displayName}
              </div>
              <div className="text-[10px] text-slate-500 mt-1 capitalize">
                {user?.role || 'analyst'}
              </div>
            </div>

            <ChevronDown
              className={`w-4 h-4 text-slate-400 transition-transform ${menuOpen ? 'rotate-180' : ''
                }`}
            />
          </button>

          <AnimatePresence>
            {menuOpen && (
              <motion.div
                initial={{ opacity: 0, y: 8, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 6, scale: 0.98 }}
                transition={{ duration: 0.22, ease: 'easeOut' }}
                className="absolute right-0 top-full mt-3 w-72 rounded-2xl overflow-hidden z-[999]"
                style={{
                  background:
                    'linear-gradient(180deg, rgba(10,15,30,0.98) 0%, rgba(8,12,24,0.98) 100%)',
                  border: '1px solid rgba(6,182,212,0.14)',
                  boxShadow: '0 20px 60px rgba(2,8,23,0.45)',
                }}
              >
                <div className="p-4 border-b border-cyan-500/10">
                  <div className="flex items-center gap-3">
                    <div
                      className="w-11 h-11 rounded-full flex items-center justify-center text-sm font-bold text-cyan-300"
                      style={{
                        background:
                          'linear-gradient(135deg, rgba(6,182,212,0.25), rgba(139,92,246,0.25))',
                        border: '1px solid rgba(6,182,212,0.25)',
                      }}
                    >
                      {initial}
                    </div>
                    <div className="min-w-0">
                      <div className="text-sm font-semibold text-slate-100 truncate">
                        {displayName}
                      </div>
                      <div className="text-xs text-slate-400 truncate">
                        {user?.email || `${user?.username || 'analyst'}@phishguard.local`}
                      </div>
                      <div className="text-[10px] text-cyan-400 mt-1 capitalize">
                        {user?.role || 'analyst'}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="p-2">
                  <button
                    onClick={() => {
                      setMenuOpen(false)
                      navigate('/profile')
                    }}
                    className="w-full flex items-center gap-3 px-3 py-3 rounded-xl text-sm text-slate-300 hover:bg-slate-800/70 hover:text-white transition-colors"
                  >
                    <User className="w-4 h-4 text-cyan-400" />
                    <span>My Profile</span>
                  </button>

                  <button
                    onClick={() => {
                      setMenuOpen(false)
                      navigate('/security')
                    }}
                    className="w-full flex items-center gap-3 px-3 py-3 rounded-xl text-sm text-slate-300 hover:bg-slate-800/70 hover:text-white transition-colors"
                  >
                    <Shield className="w-4 h-4 text-cyan-400" />
                    <span>Security</span>
                  </button>

                  <button
                    onClick={() => {
                      setMenuOpen(false)
                      navigate('/history')
                    }}
                    className="w-full flex items-center gap-3 px-3 py-3 rounded-xl text-sm text-slate-300 hover:bg-slate-800/70 hover:text-white transition-colors"
                  >
                    <History className="w-4 h-4 text-cyan-400" />
                    <span>Search History</span>
                  </button>

                  <button
                    onClick={() => {
                      setMenuOpen(false)
                      navigate('/security')
                    }}
                    className="w-full flex items-center gap-3 px-3 py-3 rounded-xl text-sm text-slate-300 hover:bg-slate-800/70 hover:text-white transition-colors"
                  >
                    <Settings className="w-4 h-4 text-cyan-400" />
                    <span>Settings</span>
                  </button>
                </div>

                <div className="px-2 pb-2">
                  <button
                    onClick={handleLogout}
                    className="w-full flex items-center gap-3 px-3 py-3 rounded-xl text-sm text-red-300 hover:bg-red-500/10 transition-colors"
                  >
                    <LogOut className="w-4 h-4" />
                    <span>Logout</span>
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.header>
  )
}