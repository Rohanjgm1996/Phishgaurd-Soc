import { useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import {
    User,
    Mail,
    Shield,
    Clock3,
    BadgeCheck,
    Fingerprint,
    Briefcase,
    Save,
} from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'

function InfoCard({
    title,
    value,
    icon: Icon,
}: {
    title: string
    value: string
    icon: React.ComponentType<{ className?: string }>
}) {
    return (
        <div className="rounded-2xl border border-cyan-500/10 bg-slate-900/70 p-4">
            <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-cyan-500/10 border border-cyan-500/10">
                    <Icon className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="min-w-0">
                    <div className="text-[11px] uppercase tracking-widest text-slate-500">{title}</div>
                    <div className="text-sm text-slate-100 mt-1 break-all">{value}</div>
                </div>
            </div>
        </div>
    )
}

export default function ProfilePage() {
    const { user, updateUser } = useAuth()

    const displayName = user?.full_name || user?.username || 'Analyst User'
    const username = user?.username || 'analyst'
    const role = user?.role || 'analyst'
    const email = user?.email || `${username}@phishguard.local`
    const verified = user?.email_verified ?? false
    const mfaEnabled = user?.mfa_enabled ?? false

    const [fullName, setFullName] = useState(displayName)
    const [emailInput, setEmailInput] = useState(email)
    const [statusMessage, setStatusMessage] = useState('')

    const lastLogin = useMemo(() => new Date().toLocaleString(), [])

    function handleSaveProfile() {
        updateUser({
            full_name: fullName,
            email: emailInput,
        })
        setStatusMessage('Profile updated successfully')
        setTimeout(() => setStatusMessage(''), 2200)
    }

    return (
        <div className="p-6 space-y-6">
            <motion.div
                initial={{ opacity: 0, y: 14 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3 }}
                className="rounded-3xl border border-cyan-500/10 overflow-hidden"
                style={{
                    background:
                        'linear-gradient(135deg, rgba(8,12,24,0.92), rgba(10,15,30,0.86))',
                }}
            >
                <div className="p-6 md:p-8">
                    <div className="flex flex-col md:flex-row md:items-center gap-5">
                        <div
                            className="w-20 h-20 rounded-2xl flex items-center justify-center text-2xl font-bold text-cyan-300"
                            style={{
                                background:
                                    'linear-gradient(135deg, rgba(6,182,212,0.22), rgba(139,92,246,0.22))',
                                border: '1px solid rgba(6,182,212,0.2)',
                            }}
                        >
                            {displayName[0]?.toUpperCase()}
                        </div>

                        <div className="flex-1">
                            <div className="flex flex-wrap items-center gap-3">
                                <h2 className="text-2xl font-display font-bold text-white">
                                    {fullName}
                                </h2>
                                <span className="px-3 py-1 rounded-full text-[11px] uppercase tracking-widest bg-cyan-500/10 text-cyan-300 border border-cyan-500/15">
                                    {role}
                                </span>
                            </div>

                            <p className="text-slate-400 text-sm mt-2">
                                PhishGuard SOC — Threat Intelligence by Rohan M
                            </p>

                            <div className="flex flex-wrap items-center gap-4 mt-4 text-xs text-slate-500">
                                <span>ID: #{user?.id ?? 1}</span>
                                <span>Username: @{username}</span>
                                <span>Status: Active</span>
                            </div>
                        </div>
                    </div>
                </div>
            </motion.div>

            <div className="grid grid-cols-1 lg:grid-cols-[1.2fr_0.8fr] gap-6">
                <motion.div
                    initial={{ opacity: 0, y: 14 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.35, delay: 0.05 }}
                    className="rounded-3xl border border-cyan-500/10 bg-slate-900/70 p-6"
                >
                    <div className="flex items-center justify-between gap-3 mb-5">
                        <div>
                            <h3 className="text-white font-semibold">Edit Profile</h3>
                            <p className="text-xs text-slate-500 mt-1">
                                Update your visible account information
                            </p>
                        </div>
                        <button
                            onClick={handleSaveProfile}
                            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm text-cyan-300 bg-cyan-500/10 border border-cyan-500/15 hover:bg-cyan-500/15"
                        >
                            <Save className="w-4 h-4" />
                            Save
                        </button>
                    </div>

                    {statusMessage && (
                        <div className="mb-4 rounded-xl border border-emerald-500/15 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
                            {statusMessage}
                        </div>
                    )}

                    <div className="space-y-4">
                        <div>
                            <label className="block text-xs uppercase tracking-widest text-slate-500 mb-2">
                                Full Name
                            </label>
                            <input
                                value={fullName}
                                onChange={(e) => setFullName(e.target.value)}
                                className="w-full h-12 rounded-xl border border-cyan-500/10 bg-slate-950/70 px-4 text-sm text-slate-100 outline-none focus:border-cyan-400/30"
                            />
                        </div>

                        <div>
                            <label className="block text-xs uppercase tracking-widest text-slate-500 mb-2">
                                Email
                            </label>
                            <input
                                value={emailInput}
                                onChange={(e) => setEmailInput(e.target.value)}
                                className="w-full h-12 rounded-xl border border-cyan-500/10 bg-slate-950/70 px-4 text-sm text-slate-100 outline-none focus:border-cyan-400/30"
                            />
                        </div>

                        <div>
                            <label className="block text-xs uppercase tracking-widest text-slate-500 mb-2">
                                Username
                            </label>
                            <input
                                value={username}
                                disabled
                                className="w-full h-12 rounded-xl border border-white/5 bg-slate-950/40 px-4 text-sm text-slate-500"
                            />
                        </div>

                        <div>
                            <label className="block text-xs uppercase tracking-widest text-slate-500 mb-2">
                                Role
                            </label>
                            <input
                                value={role}
                                disabled
                                className="w-full h-12 rounded-xl border border-white/5 bg-slate-950/40 px-4 text-sm text-slate-500 capitalize"
                            />
                        </div>
                    </div>
                </motion.div>

                <motion.div
                    initial={{ opacity: 0, y: 14 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.35, delay: 0.1 }}
                    className="space-y-4"
                >
                    <InfoCard title="Full Name" value={fullName} icon={User} />
                    <InfoCard title="Username" value={`@${username}`} icon={Fingerprint} />
                    <InfoCard title="Role" value={role} icon={Briefcase} />
                    <InfoCard title="Email" value={emailInput} icon={Mail} />
                    <InfoCard
                        title="Email Verification"
                        value={verified ? 'Verified' : 'Not Verified'}
                        icon={BadgeCheck}
                    />
                    <InfoCard
                        title="MFA Status"
                        value={mfaEnabled ? 'Enabled' : 'Disabled'}
                        icon={Shield}
                    />
                    <InfoCard title="Last Login" value={lastLogin} icon={Clock3} />
                </motion.div>
            </div>
        </div>
    )
}