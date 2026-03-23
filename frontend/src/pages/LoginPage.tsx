import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, Eye, EyeOff, Lock, User, AlertCircle, Zap, Activity, Globe } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'

// Animated floating particle
function Particle({ x, y, size, duration, delay }: { x: number; y: number; size: number; duration: number; delay: number }) {
  return (
    <motion.div
      className="absolute rounded-full pointer-events-none"
      style={{
        left: `${x}%`, top: `${y}%`,
        width: size, height: size,
        background: `rgba(6,182,212,${Math.random() * 0.2 + 0.05})`,
        boxShadow: `0 0 ${size * 2}px rgba(6,182,212,0.3)`,
      }}
      animate={{
        y: [0, -30, 0],
        opacity: [0.3, 0.8, 0.3],
        scale: [1, 1.2, 1],
      }}
      transition={{ duration, repeat: Infinity, delay, ease: 'easeInOut' }}
    />
  )
}

// Animated grid line
function GridLine({ isHorizontal, position }: { isHorizontal: boolean; position: number }) {
  return (
    <motion.div
      className="absolute pointer-events-none"
      style={{
        [isHorizontal ? 'top' : 'left']: `${position}%`,
        [isHorizontal ? 'left' : 'top']: 0,
        [isHorizontal ? 'width' : 'height']: '100%',
        [isHorizontal ? 'height' : 'width']: '1px',
        background: 'linear-gradient(90deg, transparent, rgba(6,182,212,0.08), transparent)',
      }}
      animate={{ opacity: [0.3, 0.8, 0.3] }}
      transition={{ duration: 4 + Math.random() * 3, repeat: Infinity, delay: Math.random() * 3 }}
    />
  )
}

const STATS = [
  { icon: Activity, label: 'Threats Detected', value: '2,847', color: '#ef4444' },
  { icon: Globe, label: 'URLs Analyzed', value: '18,392', color: '#06b6d4' },
  { icon: Zap, label: 'Scans Today', value: '143', color: '#a78bfa' },
]

export default function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPass, setShowPass] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [particles] = useState(() =>
    Array.from({ length: 20 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() * 6 + 3,
      duration: Math.random() * 4 + 4,
      delay: Math.random() * 3,
    }))
  )

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (!username || !password) { setError('Please enter your credentials'); return }
    setLoading(true)
    try {
      await login(username, password)
      navigate('/dashboard')
    } catch {
      setError('Invalid username or password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex overflow-hidden relative"
      style={{ background: 'linear-gradient(135deg, #020817 0%, #040d1f 50%, #060a18 100%)' }}
    >
      {/* Animated grid */}
      <div className="absolute inset-0 bg-grid opacity-60" />

      {/* Particles */}
      {particles.map(p => <Particle key={p.id} {...p} />)}

      {/* Radial glow center */}
      <div className="absolute inset-0 pointer-events-none"
        style={{ background: 'radial-gradient(ellipse 80% 60% at 50% 50%, rgba(6,182,212,0.04) 0%, transparent 70%)' }} />

      {/* Left panel — stats */}
      <motion.div
        initial={{ opacity: 0, x: -60 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
        className="hidden lg:flex flex-1 flex-col justify-between p-14 relative"
      >
        {/* Brand */}
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl flex items-center justify-center relative"
            style={{ background: 'linear-gradient(135deg, rgba(6,182,212,0.2), rgba(139,92,246,0.2))', border: '1px solid rgba(6,182,212,0.4)' }}>
            <Shield className="w-6 h-6 text-cyan-400" />
            <span className="absolute -top-1 -right-1 w-3 h-3 bg-cyan-400 rounded-full animate-pulse border-2 border-[#020817]" />
          </div>
          <div>
            <h1 className="font-display font-bold text-xl text-white">PhishGuard SOC</h1>
            <p className="text-[11px] text-cyan-400/80 tracking-wide font-medium">Threat Intelligence by Rohan M</p>
          </div>
        </div>

        {/* Tagline */}
        <div>
          <motion.h2
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3, duration: 0.7 }}
            className="text-5xl font-display font-bold leading-tight mb-6"
          >
            <span className="text-white">AI-Powered</span>
            <br />
            <span className="text-gradient-cyber">Phishing Analysis</span>
            <br />
            <span className="text-white">for SOC Teams</span>
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5, duration: 0.6 }}
            className="text-slate-400 text-lg leading-relaxed max-w-md"
          >
            Detect, analyze and report phishing emails and malicious attachments with
            enterprise-grade forensic tooling — right in your browser.
          </motion.p>
        </div>

        {/* Stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7, duration: 0.6 }}
          className="grid grid-cols-3 gap-4"
        >
          {STATS.map(({ icon: Icon, label, value, color }, i) => (
            <motion.div
              key={label}
              whileHover={{ y: -4, transition: { duration: 0.2 } }}
              className="glass-card p-4 rounded-2xl border border-slate-700/40"
            >
              <Icon className="w-5 h-5 mb-3" style={{ color }} />
              <div className="font-display font-bold text-xl text-white">{value}</div>
              <div className="text-xs text-slate-500 mt-0.5">{label}</div>
            </motion.div>
          ))}
        </motion.div>
      </motion.div>

      {/* Right panel — login form */}
      <div className="flex-1 lg:max-w-[480px] flex items-center justify-center p-8 relative">
        {/* Right glow */}
        <div className="absolute inset-0 pointer-events-none"
          style={{ background: 'radial-gradient(ellipse 70% 70% at 60% 40%, rgba(139,92,246,0.06) 0%, transparent 70%)' }} />

        <motion.div
          initial={{ opacity: 0, y: 30, scale: 0.97 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.6, delay: 0.1, ease: [0.22, 1, 0.36, 1] }}
          className="w-full max-w-sm"
        >
          {/* Card */}
          <div className="relative"
            style={{
              background: 'rgba(10,15,30,0.85)',
              backdropFilter: 'blur(40px)',
              border: '1px solid rgba(6,182,212,0.15)',
              borderRadius: '24px',
              boxShadow: '0 40px 80px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.03)',
            }}
          >
            {/* Top accent line */}
            <div className="absolute inset-x-0 top-0 h-[2px] rounded-t-[24px]"
              style={{ background: 'linear-gradient(90deg, transparent, rgba(6,182,212,0.6), rgba(139,92,246,0.6), transparent)' }} />

            <div className="p-8">
              {/* Header */}
              <div className="mb-8">
                <div className="flex items-center gap-3 mb-6 lg:hidden">
                  <Shield className="w-6 h-6 text-cyan-400" />
                  <span className="font-display font-bold text-white">PhishGuard SOC</span>
                </div>
                <h2 className="font-display font-bold text-2xl text-white mb-1">Welcome back</h2>
                <p className="text-slate-400 text-sm">Sign in to your analyst dashboard</p>
              </div>

              {/* Form */}
              <form onSubmit={handleSubmit} className="space-y-4">
                {/* Username */}
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Username</label>
                  <div className="relative">
                    <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                      type="text"
                      value={username}
                      onChange={e => setUsername(e.target.value)}
                      placeholder="analyst"
                      className="input-cyber pl-10"
                      autoComplete="username"
                    />
                  </div>
                </div>

                {/* Password */}
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                      type={showPass ? 'text' : 'password'}
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      placeholder="••••••••"
                      className="input-cyber pl-10 pr-10"
                      autoComplete="current-password"
                    />
                    <button type="button" onClick={() => setShowPass(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors p-1">
                      {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Options */}
                <div className="flex items-center justify-between">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" className="w-3.5 h-3.5 rounded border-slate-600 bg-slate-800 text-cyan-500" />
                    <span className="text-xs text-slate-400">Remember me</span>
                  </label>
                  <button type="button" className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
                    Forgot password?
                  </button>
                </div>

                {/* Error */}
                <AnimatePresence>
                  {error && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="flex items-center gap-2 text-red-400 text-xs bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2.5"
                    >
                      <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                      {error}
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* Submit */}
                <motion.button
                  type="submit"
                  disabled={loading}
                  whileHover={{ scale: loading ? 1 : 1.02 }}
                  whileTap={{ scale: loading ? 1 : 0.98 }}
                  className="w-full py-3 rounded-xl font-semibold text-sm text-white transition-all duration-200 disabled:opacity-60 relative overflow-hidden"
                  style={{ background: 'linear-gradient(135deg, #0891b2, #7c3aed)' }}
                >
                  {loading && (
                    <motion.div
                      className="absolute inset-0 bg-white/10"
                      animate={{ x: ['-100%', '100%'] }}
                      transition={{ duration: 1, repeat: Infinity }}
                    />
                  )}
                  <span className="relative">
                    {loading ? 'Authenticating…' : 'Sign In'}
                  </span>
                </motion.button>
              </form>

              {/* Demo hint */}
              <div className="mt-6 pt-5 border-t border-slate-800">
                <p className="text-center text-[11px] text-slate-500 mb-3">Demo credentials</p>
                <div className="flex items-center justify-center gap-2 flex-wrap">
                  <button onClick={() => { setUsername('admin'); setPassword('Admin@123') }}
                    className="px-3 py-1.5 rounded-lg text-[11px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors">
                    admin / Admin@123
                  </button>
                </div>
              </div>
            </div>
          </div>

          <p className="text-center text-[10px] text-slate-600 mt-6">
            For defensive SOC use only · Not for production without hardening
          </p>
        </motion.div>
      </div>
    </div>
  )
}
