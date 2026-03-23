import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Copy, ChevronDown, ChevronUp, Link, Globe, Mail, Hash, Server } from 'lucide-react'
import type { IOCs } from '@/types'
import { cn } from '@/lib/utils'

interface Props { iocs: IOCs }

export default function IOCPanel({ iocs }: Props) {
  const [copied, setCopied] = useState<string | null>(null)

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(null), 1500)
  }

  const sections = [
    { key: 'urls',    icon: Link,   label: 'URLs',           items: iocs.urls ?? [],    color: 'text-blue-400' },
    { key: 'domains', icon: Globe,  label: 'Domains',        items: iocs.domains ?? [], color: 'text-cyan-400' },
    { key: 'ips',     icon: Server, label: 'IP Addresses',   items: iocs.ips ?? [],     color: 'text-purple-400' },
    { key: 'emails',  icon: Mail,   label: 'Email Addresses',items: iocs.emails ?? [],  color: 'text-pink-400' },
  ]

  const hashEntries = (iocs.hashes ?? []).flatMap(h => [
    { type: 'MD5', value: h.md5 },
    { type: 'SHA1', value: h.sha1 },
    { type: 'SHA256', value: h.sha256 },
  ]).filter(h => h.value)

  return (
    <div className="space-y-3">
      {sections.map(({ key, icon: Icon, label, items, color }) => (
        <IOCSection key={key} icon={Icon} label={label} items={items} color={color}
          onCopy={(v) => copyToClipboard(v, v)} copied={copied} />
      ))}

      {/* Hashes */}
      {hashEntries.length > 0 && (
        <div className="glass-card border border-slate-700/50 rounded-xl overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-700/50">
            <Hash className="w-4 h-4 text-slate-400" />
            <span className="text-sm font-medium text-slate-300">File Hashes</span>
            <span className="ml-auto text-xs text-slate-500">{hashEntries.length}</span>
          </div>
          <div className="p-3 space-y-2">
            {hashEntries.map(({ type, value }) => (
              <div key={type + value} className="flex items-start gap-3 group p-2 rounded-lg hover:bg-slate-800/40 transition-colors">
                <span className="text-[10px] font-mono font-bold text-slate-500 w-12 mt-0.5 flex-shrink-0">{type}</span>
                <span className="text-xs font-mono text-slate-300 break-all flex-1">{value}</span>
                <button
                  onClick={() => copyToClipboard(value, type + value)}
                  className="opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded text-slate-500 hover:text-cyan-400"
                >
                  {copied === type + value ? '✓' : <Copy className="w-3 h-3" />}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function IOCSection({ icon: Icon, label, items, color, onCopy, copied }: {
  icon: any; label: string; items: string[]; color: string
  onCopy: (v: string) => void; copied: string | null
}) {
  const [expanded, setExpanded] = useState(true)
  const hasItems = items.length > 0

  return (
    <div className={cn('glass-card border rounded-xl overflow-hidden', hasItems ? 'border-slate-700/50' : 'border-slate-800/30 opacity-50')}>
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center gap-2 px-4 py-3 border-b border-slate-700/50 hover:bg-slate-800/20 transition-colors"
      >
        <Icon className={cn('w-4 h-4', hasItems ? color : 'text-slate-600')} />
        <span className="text-sm font-medium text-slate-300">{label}</span>
        <span className="ml-auto text-xs text-slate-500 mr-2">{items.length}</span>
        {expanded ? <ChevronUp className="w-3.5 h-3.5 text-slate-500" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-500" />}
      </button>
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }}
            className="overflow-hidden"
          >
            <div className="p-3 space-y-1">
              {hasItems ? items.slice(0, 20).map((item, i) => (
                <div key={i} className="flex items-center gap-2 group p-2 rounded-lg hover:bg-slate-800/40 transition-colors">
                  <span className="text-xs font-mono text-slate-300 break-all flex-1">{item}</span>
                  <button
                    onClick={() => onCopy(item)}
                    className="opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded text-slate-500 hover:text-cyan-400"
                  >
                    {copied === item ? '✓' : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              )) : (
                <p className="text-xs text-slate-600 px-2 py-1">No {label.toLowerCase()} extracted</p>
              )}
              {items.length > 20 && (
                <p className="text-xs text-slate-500 px-2">+{items.length - 20} more</p>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
