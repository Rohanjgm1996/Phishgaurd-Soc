import { motion } from 'framer-motion'
import {
    Shield,
    KeyRound,
    MailCheck,
    Smartphone,
    Clock3,
    Lock,
    AlertTriangle,
    CheckCircle2,
} from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { useState } from 'react'

function SecurityItem({
    title,
    description,
    status,
    action,
    tone = 'neutral',
    icon: Icon,
    onAction,
}: {
    title: string
    description: string
    status: string
    action: string
    tone?: 'good' | 'warn' | 'neutral'
    icon: React.ComponentType<{ className?: string }>
    onAction?: () => void
}) {
    const toneClasses =
        tone === 'good'
            ? 'text-emerald-300 bg-emerald-500/10 border-emerald-500/15'
            : tone === 'warn'
                ? 'text-amber-300 bg-amber-500/10 border-amber-500/15'
                : 'text-slate-300 bg-slate-800/70 border-white/5'

    return (
        <div className="rounded-2xl border border-cyan-500/10 bg-slate-900/70 p-5">
            <div className="flex flex-col md:flex-row md:items-center gap-4">
                <div className="w-11 h-11 rounded-xl flex items-center justify-center bg-cyan-500/10 border border-cyan-500/10">
                    <Icon className="w-5 h-5 text-cyan-400" />
                </div>

                <div className="flex-1">
                    <div className="text-white font-semibold">{title}</div>
                    <div className="text-sm text-slate-400 mt-1">{description}</div>
                </div>

                <div className="flex flex-col items-start md:items-end gap-2">
                    <span className={`px-3 py-1 rounded-full border text-xs ${toneClasses}`}>
                        {status}
                    </span>
                    <button
                        onClick={onAction}
                        className="px-4 py-2 rounded-xl text-sm text-cyan-300 bg-cyan-500/10 border border-cyan-500/15 hover:bg-cyan-500/15 transition-colors"
                    >
                        {action}
                    </button>
                </div>
            </div>
        </div>
    )
}

export default function SecurityPage() {
    const { user, updateUser } = useAuth()
    const [message, setMessage] = useState('')

    const emailVerified = user?.email_verified ?? false
    const mfaEnabled = user?.mfa_enabled ?? false

    function showMessage(text: string) {
        setMessage(text)
        setTimeout(() => setMessage(''), 2200)
    }

    function toggleEmailVerification() {
        updateUser({ email_verified: !emailVerified })
        showMessage(!emailVerified ? 'Email marked as verified' : 'Email marked as unverified')
    }

    function toggleMfa() {
        updateUser({ mfa_enabled: !mfaEnabled })
        showMessage(!mfaEnabled ? 'MFA enabled locally' : 'MFA disabled locally')
    }

    function changePasswordStub() {
        showMessage('Password change backend is not connected yet')
    }

    const recentEvents = [
        {
            icon: CheckCircle2,
            text: 'Successful login from current browser session',
            time: 'Just now',
            color: 'text-emerald-400',
        },
        {
            icon: emailVerified ? CheckCircle2 : AlertTriangle,
            text: emailVerified ? 'Email is marked as verified' : 'Email verification is pending',
            time: 'Account status',
            color: emailVerified ? 'text-emerald-400' : 'text-amber-400',
        },
        {
            icon: mfaEnabled ? Shield : AlertTriangle,
            text: mfaEnabled ? 'MFA is enabled for this account' : 'MFA is not enabled',
            time: 'Security status',
            color: mfaEnabled ? 'text-emerald-400' : 'text-amber-400',
        },
    ]

    return (
        <div className="p-6 space-y-6">
            <motion.div
                initial={{ opacity: 0, y: 14 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3 }}
                className="rounded-3xl border border-cyan-500/10 p-6 md:p-8"
                style={{
                    background:
                        'linear-gradient(135deg, rgba(8,12,24,0.92), rgba(10,15,30,0.86))',
                }}
            >
                <div className="flex items-start gap-4">
                    <div className="w-14 h-14 rounded-2xl flex items-center justify-center bg-cyan-500/10 border border-cyan-500/10">
                        <Shield className="w-6 h-6 text-cyan-400" />
                    </div>
                    <div>
                        <h2 className="text-2xl font-display font-bold text-white">Security Center</h2>
                        <p className="text-slate-400 text-sm mt-2">
                            Manage password, email verification, MFA, and account protection features.
                        </p>
                    </div>
                </div>
            </motion.div>

            {message && (
                <div className="rounded-xl border border-cyan-500/15 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-300">
                    {message}
                </div>
            )}

            <motion.div
                initial={{ opacity: 0, y: 14 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, delay: 0.04 }}
                className="grid grid-cols-1 md:grid-cols-3 gap-4"
            >
                <div className="rounded-2xl border border-cyan-500/10 bg-slate-900/70 p-5">
                    <div className="text-[11px] uppercase tracking-widest text-slate-500">Password Status</div>
                    <div className="mt-3 text-xl font-semibold text-white">Configured</div>
                    <div className="text-sm text-slate-400 mt-2">UI ready. Backend change-password endpoint still needed.</div>
                </div>

                <div className="rounded-2xl border border-cyan-500/10 bg-slate-900/70 p-5">
                    <div className="text-[11px] uppercase tracking-widest text-slate-500">Email Verification</div>
                    <div className={`mt-3 text-xl font-semibold ${emailVerified ? 'text-emerald-300' : 'text-amber-300'}`}>
                        {emailVerified ? 'Verified' : 'Pending'}
                    </div>
                    <div className="text-sm text-slate-400 mt-2">Local status works now. Real email token flow still needed.</div>
                </div>

                <div className="rounded-2xl border border-cyan-500/10 bg-slate-900/70 p-5">
                    <div className="text-[11px] uppercase tracking-widest text-slate-500">MFA Protection</div>
                    <div className={`mt-3 text-xl font-semibold ${mfaEnabled ? 'text-emerald-300' : 'text-amber-300'}`}>
                        {mfaEnabled ? 'Enabled' : 'Not Enabled'}
                    </div>
                    <div className="text-sm text-slate-400 mt-2">Local toggle works now. Real TOTP/OTP backend still needed.</div>
                </div>
            </motion.div>

            <motion.div
                initial={{ opacity: 0, y: 14 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, delay: 0.08 }}
                className="space-y-4"
            >
                <SecurityItem
                    title="Change Password"
                    description="Allow users to update their account password securely."
                    status="UI Only"
                    action="Open Password Settings"
                    icon={KeyRound}
                    onAction={changePasswordStub}
                />

                <SecurityItem
                    title="Verify Email Address"
                    description="Toggle email verification status locally for now."
                    status={emailVerified ? 'Verified' : 'Pending'}
                    action={emailVerified ? 'Mark Unverified' : 'Mark Verified'}
                    tone={emailVerified ? 'good' : 'warn'}
                    icon={MailCheck}
                    onAction={toggleEmailVerification}
                />

                <SecurityItem
                    title="Enable 2FA / MFA"
                    description="Toggle MFA status locally. Real OTP/TOTP backend can be added later."
                    status={mfaEnabled ? 'Enabled' : 'Not Enabled'}
                    action={mfaEnabled ? 'Disable MFA' : 'Enable MFA'}
                    tone={mfaEnabled ? 'good' : 'warn'}
                    icon={Smartphone}
                    onAction={toggleMfa}
                />

                <SecurityItem
                    title="Session & Login Monitoring"
                    description="Track active sessions, login activity, and suspicious sign-in attempts."
                    status="Visual Only"
                    action="View Activity Plan"
                    icon={Clock3}
                    onAction={() => showMessage('Login activity backend is not connected yet')}
                />

                <SecurityItem
                    title="Account Lock / Protection"
                    description="Protect users against repeated failed login attempts and brute-force activity."
                    status="Future Upgrade"
                    action="Review Protection Design"
                    icon={Lock}
                    onAction={() => showMessage('Account lock logic is not connected yet')}
                />
            </motion.div>

            <motion.div
                initial={{ opacity: 0, y: 14 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, delay: 0.12 }}
                className="rounded-3xl border border-cyan-500/10 bg-slate-900/70 p-6"
            >
                <div className="flex items-center gap-3 mb-5">
                    <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-cyan-500/10 border border-cyan-500/10">
                        <Shield className="w-4 h-4 text-cyan-400" />
                    </div>
                    <div>
                        <h3 className="text-white font-semibold">Recent Security Notes</h3>
                        <p className="text-xs text-slate-500 mt-1">Current visible account security state</p>
                    </div>
                </div>

                <div className="space-y-3">
                    {recentEvents.map((event, index) => {
                        const Icon = event.icon
                        return (
                            <div
                                key={index}
                                className="rounded-2xl border border-white/5 bg-slate-950/50 px-4 py-3 flex items-start justify-between gap-4"
                            >
                                <div className="flex items-start gap-3">
                                    <Icon className={`w-4 h-4 mt-0.5 ${event.color}`} />
                                    <div>
                                        <div className="text-sm text-slate-200">{event.text}</div>
                                        <div className="text-xs text-slate-500 mt-1">{event.time}</div>
                                    </div>
                                </div>
                            </div>
                        )
                    })}
                </div>
            </motion.div>
        </div>
    )
}