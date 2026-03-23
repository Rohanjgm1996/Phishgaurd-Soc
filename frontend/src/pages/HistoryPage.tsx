import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Search, Filter, ChevronLeft, ChevronRight, Mail, FileText, ExternalLink } from 'lucide-react'
import { historyApi } from '@/lib/api'
import type { HistoryResponse, AnalysisSummary, VerdictLabel } from '@/types'
import VerdictBadge from '@/components/ui/VerdictBadge'
import EmptyState from '@/components/ui/EmptyState'
import LoadingSkeleton from '@/components/ui/LoadingSkeleton'
import { formatDate, verdictHexColor } from '@/lib/utils'
import { cn } from '@/lib/utils'

const VERDICTS: VerdictLabel[] = ['Benign', 'Suspicious', 'Likely Phishing', 'Malicious']

export default function HistoryPage() {
  const navigate = useNavigate()
  const [data, setData] = useState<HistoryResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [verdictFilter, setVerdictFilter] = useState<string>('')
  const [page, setPage] = useState(1)

  const PAGE_SIZE = 15

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const res = await historyApi.getHistory({
        page,
        page_size: PAGE_SIZE,
        verdict: verdictFilter || undefined,
        search: search || undefined,
      })
      setData(res)
    } catch {}
    finally { setLoading(false) }
  }, [page, verdictFilter, search])

  useEffect(() => { fetchData() }, [fetchData])

  // Reset to page 1 on filter/search change
  useEffect(() => { setPage(1) }, [search, verdictFilter])

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 1

  return (
    <div className="max-w-6xl mx-auto space-y-5">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
        <h2 className="text-2xl font-display font-bold text-white mb-1">Analysis History</h2>
        <p className="text-slate-500 text-sm">
          {data ? `${data.total} total ${data.total === 1 ? 'analysis' : 'analyses'}` : 'Loading…'}
        </p>
      </motion.div>

      {/* Controls */}
      <motion.div
        initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
        className="glass-card border border-slate-700/50 rounded-2xl p-4 flex flex-wrap items-center gap-3"
      >
        {/* Search */}
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search filename…"
            className="input-cyber pl-9 h-9 text-sm w-full"
          />
        </div>

        {/* Verdict filter pills */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <Filter className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
          <button
            onClick={() => setVerdictFilter('')}
            className={cn(
              'px-3 py-1 rounded-full text-xs font-medium transition-all',
              !verdictFilter ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-500 hover:text-slate-300 border border-slate-700/50 hover:border-slate-600'
            )}
          >
            All
          </button>
          {VERDICTS.map(v => (
            <button
              key={v}
              onClick={() => setVerdictFilter(verdictFilter === v ? '' : v)}
              className={cn(
                'px-3 py-1 rounded-full text-xs font-medium border transition-all',
                verdictFilter === v
                  ? 'opacity-100'
                  : 'text-slate-500 hover:text-slate-300 border-slate-700/50 hover:border-slate-600'
              )}
              style={verdictFilter === v ? {
                background: `${verdictHexColor(v)}15`,
                borderColor: `${verdictHexColor(v)}40`,
                color: verdictHexColor(v),
              } : {}}
            >
              {v}
            </button>
          ))}
        </div>
      </motion.div>

      {/* Table */}
      <motion.div
        initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
        className="glass-card border border-slate-700/50 rounded-2xl overflow-hidden"
      >
        {/* Table header */}
        <div className="grid grid-cols-[2fr_1fr_1fr_90px_70px_32px] gap-3 px-5 py-3 border-b border-slate-700/50 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
          <span>Filename</span>
          <span>Date</span>
          <span>Type</span>
          <span>Score</span>
          <span>Verdict</span>
          <span></span>
        </div>

        {loading ? (
          <LoadingSkeleton rows={8} />
        ) : !data?.items.length ? (
          <EmptyState
            title="No analyses found"
            description={search || verdictFilter ? 'Try adjusting your filters' : 'Upload a file to get started'}
            action={{ label: 'Analyze a file', to: '/upload' }}
          />
        ) : (
          <div className="divide-y divide-slate-800/60">
            {data.items.map((item, i) => (
              <HistoryRow key={item.analysis_id} item={item} index={i} onClick={() => navigate(`/result/${item.analysis_id}`)} />
            ))}
          </div>
        )}
      </motion.div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-slate-500">
            Page {page} of {totalPages} · {data?.total} results
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-2 rounded-lg border border-slate-700/50 text-slate-400 hover:text-slate-200 hover:border-slate-600 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const p = Math.max(1, Math.min(page - 2 + i, totalPages - 4 + i))
              return (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  className={cn(
                    'w-8 h-8 rounded-lg text-xs font-medium transition-all border',
                    p === page
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30'
                      : 'text-slate-400 border-slate-700/50 hover:border-slate-600 hover:text-slate-200'
                  )}
                >
                  {p}
                </button>
              )
            })}
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="p-2 rounded-lg border border-slate-700/50 text-slate-400 hover:text-slate-200 hover:border-slate-600 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function HistoryRow({ item, index, onClick }: { item: AnalysisSummary; index: number; onClick: () => void }) {
  const color = verdictHexColor(item.verdict)
  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.03 }}
      onClick={onClick}
      className="grid grid-cols-[2fr_1fr_1fr_90px_70px_32px] gap-3 items-center px-5 py-3.5 cursor-pointer hover:bg-slate-800/30 transition-colors group"
    >
      {/* Filename */}
      <div className="flex items-center gap-2.5 min-w-0">
        <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: `${color}12`, border: `1px solid ${color}25` }}>
          {item.sample_type === 'email'
            ? <Mail className="w-3.5 h-3.5" style={{ color }} />
            : <FileText className="w-3.5 h-3.5" style={{ color }} />}
        </div>
        <span className="font-mono text-xs text-slate-200 truncate group-hover:text-white transition-colors">
          {item.original_filename}
        </span>
      </div>

      {/* Date */}
      <span className="text-[11px] text-slate-500">{formatDate(item.upload_time)}</span>

      {/* Type */}
      <span className="text-[11px] text-slate-400 uppercase">{item.sample_type}</span>

      {/* Score */}
      <div className="flex items-center gap-2">
        <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
          <div className="h-full rounded-full transition-all" style={{ width: `${item.score}%`, background: color }} />
        </div>
        <span className="text-xs font-mono font-bold w-6 text-right" style={{ color }}>{item.score}</span>
      </div>

      {/* Verdict badge */}
      <VerdictBadge verdict={item.verdict} size="sm" showIcon={false} />

      {/* Arrow */}
      <ExternalLink className="w-3.5 h-3.5 text-slate-600 group-hover:text-cyan-500 transition-colors" />
    </motion.div>
  )
}
