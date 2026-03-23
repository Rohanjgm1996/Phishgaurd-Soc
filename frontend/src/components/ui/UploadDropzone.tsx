import { useState, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Upload, File, X, CheckCircle, AlertCircle, Loader2 } from 'lucide-react'
import { cn, formatFileSize } from '@/lib/utils'

interface Props {
  onFile: (file: File) => void
  isAnalyzing: boolean
  progress: number
  accept?: string
  label?: string
}

const ACCEPTED_EXTS = [
  '.eml', '.pdf', '.doc', '.docm', '.docx', '.xls', '.xlsm', '.xlsx',
  '.zip', '.rar', '.html', '.js', '.vbs', '.ps1', '.exe', '.dll', '.lnk',
]

export default function UploadDropzone({ onFile, isAnalyzing, progress, accept, label }: Props) {
  const [dragOver, setDragOver] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFile = useCallback((file: File) => {
    const ext = '.' + file.name.split('.').pop()?.toLowerCase()
    if (!ACCEPTED_EXTS.includes(ext)) {
      setError(`File type "${ext}" not supported`)
      return
    }
    if (file.size > 25 * 1024 * 1024) {
      setError('File exceeds 25 MB limit')
      return
    }
    setError(null)
    setSelectedFile(file)
    onFile(file)
  }, [onFile])

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  const onInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
  }, [handleFile])

  return (
    <div className="space-y-4">
      <motion.div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        onClick={() => !isAnalyzing && inputRef.current?.click()}
        animate={{
          borderColor: dragOver ? 'rgba(6,182,212,0.7)' : isAnalyzing ? 'rgba(139,92,246,0.5)' : 'rgba(6,182,212,0.2)',
          background: dragOver ? 'rgba(6,182,212,0.05)' : 'rgba(13,21,38,0.6)',
        }}
        className={cn(
          'relative rounded-2xl border-2 border-dashed p-12 flex flex-col items-center gap-4 transition-all duration-300',
          !isAnalyzing && 'cursor-pointer hover:border-cyan-500/50 hover:bg-cyan-500/5'
        )}
      >
        {/* Animated background glow */}
        <AnimatePresence>
          {dragOver && (
            <motion.div
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 rounded-2xl pointer-events-none"
              style={{ background: 'radial-gradient(ellipse at center, rgba(6,182,212,0.08) 0%, transparent 70%)' }}
            />
          )}
        </AnimatePresence>

        <input
          ref={inputRef}
          type="file"
          accept={accept}
          onChange={onInputChange}
          className="hidden"
          disabled={isAnalyzing}
        />

        {isAnalyzing ? (
          <AnalyzingState progress={progress} filename={selectedFile?.name} />
        ) : selectedFile ? (
          <SelectedState file={selectedFile} onClear={() => { setSelectedFile(null); if (inputRef.current) inputRef.current.value = '' }} />
        ) : (
          <IdleState dragOver={dragOver} />
        )}
      </motion.div>

      {/* Accepted formats */}
      {!isAnalyzing && (
        <div className="flex flex-wrap gap-1.5">
          {ACCEPTED_EXTS.map(ext => (
            <span key={ext} className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-500 border border-slate-800/80 bg-slate-900/40">
              {ext}
            </span>
          ))}
        </div>
      )}

      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="flex items-center gap-2 text-red-400 text-sm bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-3"
          >
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            {error}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function IdleState({ dragOver }: { dragOver: boolean }) {
  return (
    <>
      <motion.div
        animate={{ scale: dragOver ? 1.1 : 1, y: dragOver ? -4 : 0 }}
        transition={{ type: 'spring', stiffness: 400, damping: 20 }}
        className="w-16 h-16 rounded-2xl flex items-center justify-center"
        style={{ background: 'linear-gradient(135deg, rgba(6,182,212,0.15), rgba(139,92,246,0.15))', border: '1px solid rgba(6,182,212,0.25)' }}
      >
        <Upload className="w-7 h-7 text-cyan-400" />
      </motion.div>
      <div className="text-center">
        <p className="font-semibold text-slate-200 mb-1">
          {dragOver ? 'Drop to analyze' : 'Drop your file here'}
        </p>
        <p className="text-sm text-slate-500">or click to browse — max 25 MB</p>
      </div>
    </>
  )
}

function SelectedState({ file, onClear }: { file: File; onClear: () => void }) {
  return (
    <div className="flex items-center gap-4 w-full max-w-sm">
      <div className="w-12 h-12 rounded-xl flex items-center justify-center bg-green-500/10 border border-green-500/20 flex-shrink-0">
        <File className="w-6 h-6 text-green-400" />
      </div>
      <div className="flex-1 min-w-0 text-left">
        <p className="font-medium text-slate-200 text-sm truncate">{file.name}</p>
        <p className="text-xs text-slate-500 mt-0.5">{formatFileSize(file.size)}</p>
      </div>
      <button onClick={(e) => { e.stopPropagation(); onClear() }}
        className="p-1.5 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors">
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}

function AnalyzingState({ progress, filename }: { progress: number; filename?: string }) {
  return (
    <div className="text-center space-y-4 w-full max-w-sm">
      <div className="flex justify-center">
        <Loader2 className="w-10 h-10 text-cyan-400 animate-spin" />
      </div>
      <div>
        <p className="font-semibold text-slate-200 text-sm mb-1">Analyzing {filename ?? 'file'}…</p>
        <p className="text-xs text-slate-500">Running detection engines</p>
      </div>
      <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
        <motion.div
          className="h-full bg-gradient-to-r from-cyan-500 to-purple-500 rounded-full"
          initial={{ width: '5%' }}
          animate={{ width: `${Math.max(progress, 5)}%` }}
          transition={{ duration: 0.3 }}
        />
      </div>
      <p className="text-xs font-mono text-cyan-500">{progress}% uploaded</p>
    </div>
  )
}
