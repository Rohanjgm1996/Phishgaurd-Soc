import React, { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

type TabKey =
  | 'summary'
  | 'authentication'
  | 'urls'
  | 'attachments'
  | 'transmission'
  | 'source'

function formatDate(value: any) {
  if (!value) return '-'
  try {
    return new Date(value).toLocaleString()
  } catch {
    return String(value)
  }
}

function formatFileSize(bytes: any) {
  const num = Number(bytes || 0)
  if (!num) return '0 B'
  if (num < 1024) return `${num} B`
  if (num < 1024 * 1024) return `${(num / 1024).toFixed(2)} KB`
  if (num < 1024 * 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(2)} MB`
  return `${(num / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function badgeStyle(verdict: string): React.CSSProperties {
  const v = (verdict || '').toLowerCase()
  if (v.includes('malicious')) {
    return {
      background: 'rgba(239,68,68,0.15)',
      color: '#fca5a5',
      border: '1px solid rgba(239,68,68,0.3)',
    }
  }
  if (v.includes('phishing')) {
    return {
      background: 'rgba(168,85,247,0.15)',
      color: '#d8b4fe',
      border: '1px solid rgba(168,85,247,0.3)',
    }
  }
  if (v.includes('suspicious')) {
    return {
      background: 'rgba(234,179,8,0.15)',
      color: '#fde68a',
      border: '1px solid rgba(234,179,8,0.3)',
    }
  }
  return {
    background: 'rgba(34,197,94,0.15)',
    color: '#86efac',
    border: '1px solid rgba(34,197,94,0.3)',
  }
}

function sectionStyle(): React.CSSProperties {
  return {
    background: 'rgba(15, 23, 42, 0.78)',
    border: '1px solid rgba(71, 85, 105, 0.45)',
    borderRadius: '18px',
    padding: '20px',
    marginBottom: '20px',
    color: '#e2e8f0',
  }
}

export default function ResultPage() {
  const params = useParams()
  const analysisId = params.analysisId || params.id || ''
  const navigate = useNavigate()

  const [data, setData] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notes, setNotes] = useState('')
  const [savingNotes, setSavingNotes] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [activeTab, setActiveTab] = useState<TabKey>('summary')

  useEffect(() => {
    const loadReport = async () => {
      if (!analysisId) {
        setError('Analysis ID not found in URL')
        setLoading(false)
        return
      }

      try {
        setLoading(true)
        setError('')

        const token = localStorage.getItem('pg_token')
        const res = await fetch(`/api/report/${analysisId}`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        })

        if (!res.ok) {
          const text = await res.text()
          throw new Error(text || 'Failed to load report')
        }

        const json = await res.json()
        setData(json)
        setNotes(json?.analyst_notes || '')
      } catch (e: any) {
        setError(e?.message || 'Failed to load report')
      } finally {
        setLoading(false)
      }
    }

    loadReport()
  }, [analysisId])

  const handleDelete = async () => {
    if (!analysisId) return
    const ok = window.confirm('Delete this analysis?')
    if (!ok) return

    try {
      setDeleting(true)
      const token = localStorage.getItem('pg_token')

      const res = await fetch(`/api/report/${analysisId}`, {
        method: 'DELETE',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })

      if (!res.ok) {
        const text = await res.text()
        throw new Error(text || 'Failed to delete analysis')
      }

      navigate('/history')
    } catch (e: any) {
      alert(e?.message || 'Failed to delete analysis')
    } finally {
      setDeleting(false)
    }
  }

  const handleSaveNotes = async () => {
    if (!analysisId) return

    try {
      setSavingNotes(true)
      const token = localStorage.getItem('pg_token')

      const res = await fetch(`/api/report/${analysisId}/notes`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ notes }),
      })

      if (!res.ok) {
        const text = await res.text()
        throw new Error(text || 'Failed to save notes')
      }

      alert('Notes saved')
    } catch (e: any) {
      alert(e?.message || 'Failed to save notes')
    } finally {
      setSavingNotes(false)
    }
  }

  const handleDownloadJson = async () => {
    if (!analysisId) return

    try {
      const token = localStorage.getItem('pg_token')
      const res = await fetch(`/api/report/${analysisId}/json`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })

      if (!res.ok) {
        const text = await res.text()
        throw new Error(text || 'Failed to download JSON')
      }

      const blob = await res.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${analysisId}.json`
      a.click()
      window.URL.revokeObjectURL(url)
    } catch (e: any) {
      alert(e?.message || 'Failed to download JSON')
    }
  }

  if (loading) {
    return (
      <div style={{ padding: '24px', color: '#e2e8f0' }}>
        Loading report...
      </div>
    )
  }

  if (error) {
    return (
      <div style={{ padding: '24px', color: '#e2e8f0' }}>
        <button onClick={() => navigate(-1)} style={btnSecondary}>
          Back
        </button>
        <div
          style={{
            marginTop: '16px',
            padding: '16px',
            borderRadius: '12px',
            background: 'rgba(239,68,68,0.12)',
            border: '1px solid rgba(239,68,68,0.25)',
            color: '#fca5a5',
          }}
        >
          {error}
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div style={{ padding: '24px', color: '#e2e8f0' }}>
        No report found
      </div>
    )
  }

  const iocs = data.iocs || {}
  const findings = Array.isArray(data.findings) ? data.findings : []
  const headers = data.headers || {}
  const attachments = Array.isArray(data.attachments) ? data.attachments : []
  const mitre = Array.isArray(data.mitre) ? data.mitre : []
  const urls = Array.isArray(iocs.urls) ? iocs.urls : []
  const domains = Array.isArray(iocs.domains) ? iocs.domains : []
  const ips = Array.isArray(iocs.ip_addresses)
    ? iocs.ip_addresses
    : Array.isArray(iocs.ips)
      ? iocs.ips
      : []
  const emails = Array.isArray(iocs.emails) ? iocs.emails : []
  const transmissionHops = Array.isArray(data.transmission_hops)
    ? data.transmission_hops
    : Array.isArray(headers.received)
      ? headers.received.map((raw: any, index: number) => ({
        hop: index + 1,
        raw: String(raw),
        from: '',
        by: '',
        ip_addresses: [],
        date: '',
      }))
      : []

  const tabs: { key: TabKey; label: string }[] = [
    { key: 'summary', label: 'Summary' },
    { key: 'authentication', label: 'Authentication' },
    { key: 'urls', label: 'URLs' },
    { key: 'attachments', label: 'Attachments' },
    { key: 'transmission', label: 'Transmission' },
    { key: 'source', label: 'Source' },
  ]

  return (
    <div style={{ padding: '24px', color: '#e2e8f0' }}>
      <div style={topRow}>
        <div>
          <button onClick={() => navigate(-1)} style={btnSecondary}>
            Back
          </button>

          <h1 style={{ fontSize: '32px', fontWeight: 700, margin: '16px 0 8px 0' }}>
            Analysis Report
          </h1>

          <div style={{ color: '#94a3b8', fontSize: '14px' }}>
            {data.original_filename || 'Unknown file'} • {formatDate(data.upload_time)} •{' '}
            {formatFileSize(data.file_size)}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <button onClick={handleDownloadJson} style={btnSecondary}>
            Download JSON
          </button>

          <a
            href={`/api/report/${data.analysis_id}/html`}
            target="_blank"
            rel="noreferrer"
            style={{ ...btnSecondary, textDecoration: 'none' }}
          >
            Open HTML
          </a>

          <button onClick={handleDelete} disabled={deleting} style={btnDelete}>
            {deleting ? 'Deleting...' : 'Delete Analysis'}
          </button>
        </div>
      </div>

      <div style={sectionStyle()}>
        <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: '24px' }}>
          <div>
            <div style={{ color: '#94a3b8', fontSize: '13px', marginBottom: '10px' }}>
              Verdict
            </div>
            <div style={{ ...badgeStyle(data.verdict), display: 'inline-block', padding: '8px 14px', borderRadius: '999px', fontWeight: 600 }}>
              {data.verdict}
            </div>

            <div style={{ marginTop: '24px' }}>
              <div style={{ color: '#94a3b8', fontSize: '13px' }}>Score</div>
              <div style={{ fontSize: '48px', fontWeight: 700, color: 'white' }}>{data.score}</div>
            </div>
          </div>

          <div style={grid2}>
            <InfoCard label="Analysis ID" value={data.analysis_id} mono />
            <InfoCard label="Sample Type" value={data.sample_type} />
            <InfoCard label="Uploaded" value={String(data.upload_time || '')} />
            <InfoCard label="Size" value={String(data.file_size || '')} />
            <InfoCard label="MD5" value={data.md5} mono />
            <InfoCard label="SHA256" value={data.sha256} mono />
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '20px' }}>
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            style={activeTab === tab.key ? tabActive : tabIdle}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'summary' && (
        <>
          <div style={sectionStyle()}>
            <h2 style={sectionTitle}>IOCs</h2>

            <SubList title="URLs" items={urls} renderItem={(item) => typeof item === 'string' ? item : item?.url || JSON.stringify(item)} />
            <SubList title="Domains" items={domains} renderItem={(item) => String(item)} />
            <SubList title="IP Addresses" items={ips} renderItem={(item) => String(item)} />
            <SubList title="Email Addresses" items={emails} renderItem={(item) => String(item)} />
          </div>

          <div style={sectionStyle()}>
            <h2 style={sectionTitle}>Findings</h2>
            {findings.length > 0 ? (
              findings.map((f: any, index: number) => (
                <div key={index} style={listItem}>
                  <div style={{ fontWeight: 600, marginBottom: '6px' }}>
                    {f.section || `Finding ${index + 1}`}
                  </div>
                  <div style={{ color: '#cbd5e1' }}>
                    {f.detail || JSON.stringify(f)}
                  </div>
                </div>
              ))
            ) : (
              <div style={muted}>No findings generated.</div>
            )}
          </div>

          <div style={sectionStyle()}>
            <h2 style={sectionTitle}>MITRE ATT&CK</h2>
            {mitre.length > 0 ? (
              mitre.map((m: any, index: number) => (
                <div key={index} style={listItem}>
                  <div style={{ fontWeight: 600 }}>
                    {m.id || 'TBD'} - {m.name || 'Technique'}
                  </div>
                  <div style={{ color: '#94a3b8', marginTop: '4px' }}>
                    Triggered by: {m.triggered_by || '-'}
                  </div>
                </div>
              ))
            ) : (
              <div style={muted}>No MITRE mapping available.</div>
            )}
          </div>
        </>
      )}

      {activeTab === 'authentication' && (
        <div style={sectionStyle()}>
          <h2 style={sectionTitle}>Authentication</h2>
          <div style={grid2}>
            <InfoCard label="SPF" value={String(headers.spf || '-')} />
            <InfoCard label="DKIM" value={String(headers.dkim || '-')} />
            <InfoCard label="DMARC" value={String(headers.dmarc || '-')} />
            <InfoCard label="Reply-To" value={String(headers.reply_to || '-')} />
            <InfoCard label="Return-Path" value={String(headers.return_path || '-')} />
            <InfoCard label="From" value={String(headers.from_email || headers.from || '-')} />
          </div>
        </div>
      )}

      {activeTab === 'urls' && (
        <div style={sectionStyle()}>
          <h2 style={sectionTitle}>URLs, Domains and IPs</h2>
          <pre style={preBlock}>
            {JSON.stringify(
              {
                urls,
                domains,
                ips,
                resolved_domain_ips: iocs.resolved_domain_ips || {},
                enrichment: iocs.enrichment || {},
              },
              null,
              2
            )}
          </pre>
        </div>
      )}

      {activeTab === 'attachments' && (
        <div style={sectionStyle()}>
          <h2 style={sectionTitle}>Attachments</h2>
          {attachments.length > 0 ? (
            attachments.map((att: any, index: number) => (
              <div key={index} style={listItem}>
                <div style={{ fontWeight: 600, marginBottom: '6px' }}>{att.filename}</div>
                <div style={{ color: '#cbd5e1', fontSize: '14px' }}>
                  Size: {formatFileSize(att.size || 0)}
                </div>
                <div style={{ color: '#cbd5e1', fontSize: '14px' }}>
                  MIME: {att.file_type?.mime_type || '-'}
                </div>
                <div style={{ color: '#cbd5e1', fontSize: '14px' }}>
                  AV: {att.clamav || 'unknown'}
                </div>
              </div>
            ))
          ) : (
            <div style={muted}>No attachments found.</div>
          )}
        </div>
      )}

      {activeTab === 'transmission' && (
        <div style={sectionStyle()}>
          <h2 style={sectionTitle}>Transmission Hops</h2>
          {transmissionHops.length > 0 ? (
            transmissionHops.map((hop: any, index: number) => (
              <div key={index} style={listItem}>
                <div style={{ color: '#67e8f9', fontWeight: 700, marginBottom: '8px' }}>
                  Hop {hop.hop || index + 1}
                </div>
                <div style={{ marginBottom: '4px' }}>
                  <span style={labelInline}>From:</span> {hop.from || '-'}
                </div>
                <div style={{ marginBottom: '4px' }}>
                  <span style={labelInline}>By:</span> {hop.by || '-'}
                </div>
                <div style={{ marginBottom: '4px' }}>
                  <span style={labelInline}>Date:</span> {hop.date || '-'}
                </div>
                <div style={{ marginBottom: '10px' }}>
                  <span style={labelInline}>IPs:</span>{' '}
                  {Array.isArray(hop.ip_addresses) && hop.ip_addresses.length > 0
                    ? hop.ip_addresses.join(', ')
                    : '-'}
                </div>
                <pre style={preBlock}>{String(hop.raw || '')}</pre>
              </div>
            ))
          ) : (
            <div style={muted}>No transmission hops found.</div>
          )}
        </div>
      )}

      {activeTab === 'source' && (
        <>
          <div style={sectionStyle()}>
            <h2 style={sectionTitle}>Raw Headers</h2>
            <pre style={preBlock}>{JSON.stringify(headers, null, 2)}</pre>
          </div>

          <div style={sectionStyle()}>
            <h2 style={sectionTitle}>Analyst Notes</h2>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={8}
              style={textarea}
              placeholder="Add observations, triage notes, escalation comments..."
            />
            <div style={{ marginTop: '12px' }}>
              <button onClick={handleSaveNotes} disabled={savingNotes} style={btnPrimary}>
                {savingNotes ? 'Saving...' : 'Save Notes'}
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function InfoCard({
  label,
  value,
  mono = false,
}: {
  label: string
  value: any
  mono?: boolean
}) {
  return (
    <div style={infoCard}>
      <div style={{ color: '#94a3b8', fontSize: '12px', marginBottom: '6px' }}>{label}</div>
      <div
        style={{
          color: '#e2e8f0',
          wordBreak: 'break-word',
          fontFamily: mono ? 'monospace' : 'inherit',
          fontSize: mono ? '12px' : '14px',
        }}
      >
        {String(value || '-')}
      </div>
    </div>
  )
}

function SubList({
  title,
  items,
  renderItem,
}: {
  title: string
  items: any[]
  renderItem: (item: any) => string
}) {
  return (
    <div style={{ marginBottom: '18px' }}>
      <h3 style={{ fontSize: '18px', fontWeight: 600, marginBottom: '10px' }}>{title}</h3>
      {items.length > 0 ? (
        items.map((item, index) => (
          <div key={index} style={listItem}>
            {renderItem(item)}
          </div>
        ))
      ) : (
        <div style={muted}>No {title.toLowerCase()} found.</div>
      )}
    </div>
  )
}

const topRow: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  gap: '16px',
  alignItems: 'flex-start',
  flexWrap: 'wrap',
  marginBottom: '24px',
}

const grid2: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
  gap: '12px',
}

const infoCard: React.CSSProperties = {
  background: 'rgba(2, 6, 23, 0.65)',
  border: '1px solid rgba(71, 85, 105, 0.35)',
  borderRadius: '12px',
  padding: '14px',
}

const btnPrimary: React.CSSProperties = {
  background: '#06b6d4',
  color: '#001018',
  border: 'none',
  padding: '10px 16px',
  borderRadius: '10px',
  cursor: 'pointer',
  fontWeight: 600,
}

const btnSecondary: React.CSSProperties = {
  background: 'rgba(30, 41, 59, 0.9)',
  color: 'white',
  border: '1px solid rgba(100, 116, 139, 0.5)',
  padding: '10px 16px',
  borderRadius: '10px',
  cursor: 'pointer',
}

const btnDelete: React.CSSProperties = {
  background: 'rgba(127, 29, 29, 0.5)',
  color: '#fecaca',
  border: '1px solid rgba(248, 113, 113, 0.4)',
  padding: '10px 16px',
  borderRadius: '10px',
  cursor: 'pointer',
}

const tabActive: React.CSSProperties = {
  background: 'rgba(6, 182, 212, 0.15)',
  color: '#67e8f9',
  border: '1px solid rgba(34, 211, 238, 0.3)',
  padding: '10px 14px',
  borderRadius: '10px',
  cursor: 'pointer',
}

const tabIdle: React.CSSProperties = {
  background: 'rgba(15, 23, 42, 0.7)',
  color: '#94a3b8',
  border: '1px solid rgba(71, 85, 105, 0.45)',
  padding: '10px 14px',
  borderRadius: '10px',
  cursor: 'pointer',
}

const textarea: React.CSSProperties = {
  width: '100%',
  background: '#020617',
  color: 'white',
  border: '1px solid rgba(71, 85, 105, 0.6)',
  borderRadius: '10px',
  padding: '12px',
  outline: 'none',
}

const preBlock: React.CSSProperties = {
  background: '#020617',
  color: '#cbd5e1',
  border: '1px solid rgba(71, 85, 105, 0.4)',
  borderRadius: '10px',
  padding: '12px',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
  marginBottom: '10px',
}

const listItem: React.CSSProperties = {
  background: '#020617',
  border: '1px solid rgba(71, 85, 105, 0.35)',
  borderRadius: '10px',
  padding: '12px',
  marginBottom: '10px',
  color: '#cbd5e1',
  wordBreak: 'break-word',
}

const sectionTitle: React.CSSProperties = {
  fontSize: '20px',
  fontWeight: 700,
  marginBottom: '14px',
}

const muted: React.CSSProperties = {
  color: '#94a3b8',
}

const labelInline: React.CSSProperties = {
  color: '#94a3b8',
  fontWeight: 600,
}