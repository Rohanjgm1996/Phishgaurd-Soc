// PhishGuard SOC - TypeScript Types

export type VerdictLabel = 'Benign' | 'Suspicious' | 'Likely Phishing' | 'Malicious';
export type VerdictColor = 'green' | 'yellow' | 'orange' | 'red';
export type SampleType = 'email' | 'attachment' | 'unknown';

export interface User {
  id: number;
  username: string;
  full_name: string;
  role: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
}

export interface AnalysisSummary {
  analysis_id: string;
  original_filename: string;
  sample_type: SampleType;
  upload_time: string;
  score: number;
  verdict: VerdictLabel;
  verdict_color: VerdictColor;
  md5: string;
  sha256: string;
}

export interface Finding {
  section: string;
  detail: string;
}

export interface IOCs {
  urls: any[];
  domains: string[];
  ips: string[];
  ip_addresses: string[];
  resolved_domain_ips?: Record<string, string[]>;
  emails: string[];
  hashes: Array<{ md5: string; sha1: string; sha256: string }>;
  enrichment?: any;
}

export interface MitreTechnique {
  id: string;
  name: string;
  triggered_by: string;
}

export interface AttachmentSummary {
  filename: string;
  size: number;
  hashes: { md5: string; sha1: string; sha256: string };
  file_type: {
    mime_type: string;
    magic_description: string;
    extension: string;
  };
  triggered_rules: string[];
  yara_matches: Array<{ rule: string; namespace: string; tags: string[] }>;
  clamav: string;
}

export interface AnalysisDetail extends AnalysisSummary {
  file_size: number;
  sha1: string;
  findings: Finding[];
  iocs: IOCs;
  score_breakdown: Record<string, number>;
  explanations: string[];
  mitre: MitreTechnique[];
  headers: Record<string, any>;
  urls: any[];
  attachments: AttachmentSummary[];
  analyst_notes: string;
  transmission_hops?: any[];
}

export interface DashboardStats {
  total: number;
  benign: number;
  suspicious: number;
  likely_phishing: number;
  malicious: number;
  recent: AnalysisSummary[];
}

export interface HistoryResponse {
  items: AnalysisSummary[];
  total: number;
  page: number;
  page_size: number;
}

export interface UploadResult {
  analysis_id: string;
  filename: string;
  sample_type: string;
  score: number;
  verdict: VerdictLabel;
  verdict_color: VerdictColor;
  md5: string;
  sha256: string;
}