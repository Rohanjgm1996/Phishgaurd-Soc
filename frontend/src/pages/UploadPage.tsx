import { useRef, useState } from 'react'
import { Upload, FileText, Trash2, AlertTriangle } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { analysisApi } from '@/lib/api'

export default function UploadPage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState('')
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const navigate = useNavigate()

  const handleSelectFile = (file: File) => {
    setError('')
    setSelectedFile(file)
  }

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragging(false)

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleSelectFile(e.dataTransfer.files[0])
    }
  }

  const handleAnalyze = async () => {
    if (!selectedFile) {
      setError('Please select a file first')
      return
    }

    try {
      setLoading(true)
      setError('')
      setProgress(0)

      const isEmail = selectedFile.name.toLowerCase().endsWith('.eml')

      const result = isEmail
        ? await analysisApi.analyzeEmail(selectedFile, setProgress)
        : await analysisApi.analyzeFile(selectedFile, setProgress)

      if (result?.analysis_id) {
        navigate(`/result/${result.analysis_id}`)
      } else {
        setError('Analysis completed but no analysis ID returned')
      }
    } catch (err: any) {
      const detail =
        err?.response?.data?.detail ||
        err?.response?.data?.error ||
        err?.message ||
        'Upload failed'
      setError(typeof detail === 'string' ? detail : JSON.stringify(detail))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Analyze</h1>
        <p className="text-slate-400 mt-1">Upload email or file for analysis</p>
      </div>

      <div className="glass-card rounded-2xl p-6">
        <div
          onDragOver={(e) => {
            e.preventDefault()
            setIsDragging(true)
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`rounded-2xl border-2 border-dashed p-10 cursor-pointer transition ${isDragging ? 'border-cyan-400 bg-cyan-500/5' : 'border-cyan-500/20'
            }`}
        >
          <div className="flex flex-col items-center justify-center text-center">
            <Upload className="w-10 h-10 text-cyan-400 mb-4" />
            <div className="text-white font-semibold">Drag and drop file here</div>
            <div className="text-slate-400 text-sm mt-2">or click to browse</div>
          </div>

          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0]
              if (file) handleSelectFile(file)
            }}
          />
        </div>

        {selectedFile && (
          <div className="mt-6 rounded-xl border border-cyan-500/10 bg-white/[0.02] p-4 flex items-center justify-between">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-11 h-11 rounded-xl flex items-center justify-center bg-emerald-500/10 border border-emerald-500/20">
                <FileText className="w-5 h-5 text-emerald-400" />
              </div>
              <div className="min-w-0">
                <div className="text-white font-semibold truncate">{selectedFile.name}</div>
                <div className="text-slate-400 text-sm">
                  {(selectedFile.size / 1024).toFixed(1)} KB
                </div>
              </div>
            </div>

            <button
              onClick={(e) => {
                e.stopPropagation()
                setSelectedFile(null)
                setError('')
                setProgress(0)
              }}
              className="px-4 py-2 rounded-xl bg-red-500/10 text-red-300 border border-red-500/20 hover:bg-red-500/15 flex items-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              Delete
            </button>
          </div>
        )}

        {loading && (
          <div className="mt-6">
            <div className="flex items-center justify-between text-sm mb-2">
              <span className="text-slate-300">Uploading and analyzing...</span>
              <span className="text-cyan-300">{progress}%</span>
            </div>
            <div className="w-full h-3 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-cyan-500 transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {error && (
          <div className="mt-6 rounded-xl border border-red-500/20 bg-red-500/10 p-4 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5" />
            <div>
              <div className="text-red-300 font-semibold">Error</div>
              <div className="text-slate-300 text-sm mt-1 whitespace-pre-wrap break-all">{error}</div>
            </div>
          </div>
        )}

        <div className="mt-6">
          <button
            onClick={handleAnalyze}
            disabled={!selectedFile || loading}
            className="cyber-btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Analyzing...' : 'Analyze File'}
          </button>
        </div>
      </div>
    </div>
  )
}