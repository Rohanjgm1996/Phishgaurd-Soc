import { motion } from 'framer-motion'
import { verdictHexColor } from '@/lib/utils'
import type { VerdictLabel } from '@/types'

interface Props {
  score: number
  verdict: VerdictLabel | string
  size?: number
}

export default function ScoreGauge({ score, verdict, size = 140 }: Props) {
  const color = verdictHexColor(verdict as VerdictLabel)
  const r = 52
  const cx = size / 2
  const cy = size / 2
  const circumference = 2 * Math.PI * r
  // Only use 270° arc (from 135° to 405°)
  const arcLength = circumference * 0.75
  const dashOffset = arcLength - (score / 100) * arcLength

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="rotate-[135deg]">
        {/* Track */}
        <circle
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth="8"
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeLinecap="round"
        />
        {/* Progress */}
        <motion.circle
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${arcLength} ${circumference}`}
          initial={{ strokeDashoffset: arcLength }}
          animate={{ strokeDashoffset: dashOffset }}
          transition={{ duration: 1.2, ease: [0.22, 1, 0.36, 1], delay: 0.3 }}
          style={{ filter: `drop-shadow(0 0 6px ${color}80)` }}
        />
        {/* Glow outer */}
        <motion.circle
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke={color}
          strokeWidth="2"
          strokeOpacity="0.2"
          strokeDasharray={`${arcLength} ${circumference}`}
          initial={{ strokeDashoffset: arcLength }}
          animate={{ strokeDashoffset: dashOffset }}
          transition={{ duration: 1.2, ease: [0.22, 1, 0.36, 1], delay: 0.3 }}
        />
      </svg>

      {/* Center text */}
      <div className="absolute inset-0 flex flex-col items-center justify-center -rotate-0">
        <motion.span
          className="font-display font-bold text-3xl leading-none"
          style={{ color }}
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.6, delay: 0.5 }}
        >
          {score}
        </motion.span>
        <span className="text-[10px] text-slate-500 mt-1 tracking-wider uppercase">/ 100</span>
      </div>
    </div>
  )
}
