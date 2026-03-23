import { useState } from 'react'
import { FlaskConical, Search, Fingerprint } from 'lucide-react'
import { sandboxApi } from '@/lib/api'

export default function AnyRunPage() {
    const [hash, setHash] = useState('')
    const [result, setResult] = useState<any>(null)
    const [loading, setLoading] = useState(false)

    const handleCheck = async () => {
        if (!hash.trim()) return

        try {
            setLoading(true)
            const data = await sandboxApi.checkAnyRun(hash)
            setResult(data)
        } catch (error: any) {
            setResult({
                error: error?.response?.data ?? error.message ?? 'Request failed',
            })
        } finally {
            setLoading(false)
        }
    }

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold text-white">Sandbox</h1>
                <p className="text-slate-400 mt-1">ANY.RUN sandbox hash lookup</p>
            </div>

            <div className="glass-card p-6 rounded-2xl space-y-5">
                <div className="flex items-center gap-3">
                    <div className="w-11 h-11 rounded-xl flex items-center justify-center bg-cyan-500/10 border border-cyan-500/20">
                        <FlaskConical className="w-5 h-5 text-cyan-400" />
                    </div>
                    <div>
                        <h2 className="text-xl font-semibold text-white">ANY.RUN</h2>
                        <p className="text-sm text-slate-400">Check malware sandbox results by hash</p>
                    </div>
                </div>

                <div className="grid grid-cols-1 gap-4">
                    <div className="relative">
                        <Fingerprint className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input
                            type="text"
                            placeholder="Enter file hash"
                            value={hash}
                            onChange={(e) => setHash(e.target.value)}
                            className="input-cyber pl-10"
                        />
                    </div>

                    <div>
                        <button onClick={handleCheck} disabled={loading} className="cyber-btn-primary disabled:opacity-60">
                            <Search className="w-4 h-4" />
                            {loading ? 'Checking...' : 'Check Hash'}
                        </button>
                    </div>
                </div>

                {result && (
                    <div className="glass-card rounded-xl p-4">
                        <div className="text-sm font-semibold text-cyan-300 mb-3">ANY.RUN Response</div>
                        <pre className="text-xs text-slate-300 overflow-auto whitespace-pre-wrap break-all">
                            {JSON.stringify(result, null, 2)}
                        </pre>
                    </div>
                )}
            </div>
        </div>
    )
}