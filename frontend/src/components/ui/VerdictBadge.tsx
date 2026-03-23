import { cn, verdictBgClass } from '@/lib/utils'
import type { VerdictLabel, VerdictColor } from '@/types'
import { AlertTriangle, ShieldCheck, ShieldAlert, ShieldOff } from 'lucide-react'

interface Props {
  verdict: VerdictLabel | VerdictColor | string
  size?: 'sm' | 'md' | 'lg'
  showIcon?: boolean
  className?: string
}

const icons: Record<string, React.ComponentType<any>> = {
  Malicious:       ShieldOff,
  'Likely Phishing': ShieldAlert,
  Suspicious:      AlertTriangle,
  Benign:          ShieldCheck,
}

export default function VerdictBadge({ verdict, size = 'md', showIcon = true, className }: Props) {
  const Icon = icons[verdict] ?? ShieldCheck
  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5 gap-1',
    md: 'text-xs px-3 py-1 gap-1.5',
    lg: 'text-sm px-4 py-1.5 gap-2',
  }

  return (
    <span className={cn(
      'inline-flex items-center font-semibold rounded-full border',
      verdictBgClass(verdict as VerdictLabel),
      sizeClasses[size],
      className,
    )}>
      {showIcon && <Icon className={size === 'lg' ? 'w-4 h-4' : 'w-3 h-3'} />}
      {verdict}
    </span>
  )
}
