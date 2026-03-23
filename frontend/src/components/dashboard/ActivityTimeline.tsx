import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { formatDate, verdictColorClass, verdictHexColor } from '@/lib/utils'
import type { AnalysisSummary } from '@/types'
import VerdictBadge from '@/components/ui/VerdictBadge'
import { FileText, Mail } from 'lucide-react'

interface Props { items: AnalysisSummary[] }

export default function ActivityTimeline({ items }: Props) {
  const navigate = useNavigate()

  if (!items.length) {
    return <p className="text-slate-500 text-sm py-4 text-center">No recent activity</p>
  }

  return (
    <div className="space-y-1">
      {items.map((item, i) => (
        <motion.div
          key={item.analysis_id}
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.06 }}
          onClick={() => navigate(`/result/${item.analysis_id}`)}
          className="flex items-center gap-3 px-3 py-2.5 rounded-xl cursor-pointer hover:bg-slate-800/40 transition-all group"
        >
          {/* Icon */}
          <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{
              background: `${verdictHexColor(item.verdict)}18`,
              border: `1px solid ${verdictHexColor(item.verdict)}30`,
            }}>
            {item.sample_type === 'email'
              ? <Mail className="w-3.5 h-3.5" style={{ color: verdictHexColor(item.verdict) }} />
              : <FileText className="w-3.5 h-3.5" style={{ color: verdictHexColor(item.verdict) }} />
            }
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-slate-200 truncate group-hover:text-white transition-colors">
              {item.original_filename}
            </p>
            <p className="text-[10px] text-slate-500 mt-0.5">{formatDate(item.upload_time)}</p>
          </div>

          {/* Score + badge */}
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className={`text-xs font-mono font-bold ${verdictColorClass(item.verdict)}`}>
              {item.score}
            </span>
            <VerdictBadge verdict={item.verdict} size="sm" showIcon={false} />
          </div>
        </motion.div>
      ))}
    </div>
  )
}
