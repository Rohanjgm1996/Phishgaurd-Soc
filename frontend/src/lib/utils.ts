import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { VerdictLabel, VerdictColor } from '@/types';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function verdictColorClass(verdict: VerdictLabel | VerdictColor): string {
  const map: Record<string, string> = {
    Malicious:       'text-red-400',
    'Likely Phishing': 'text-orange-400',
    Suspicious:      'text-yellow-400',
    Benign:          'text-green-400',
    red:             'text-red-400',
    orange:          'text-orange-400',
    yellow:          'text-yellow-400',
    green:           'text-green-400',
  };
  return map[verdict] || 'text-slate-400';
}

export function verdictBgClass(verdict: VerdictLabel | VerdictColor): string {
  const map: Record<string, string> = {
    Malicious:       'bg-red-500/10 border-red-500/30 text-red-400',
    'Likely Phishing': 'bg-orange-500/10 border-orange-500/30 text-orange-400',
    Suspicious:      'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
    Benign:          'bg-green-500/10 border-green-500/30 text-green-400',
    red:             'bg-red-500/10 border-red-500/30 text-red-400',
    orange:          'bg-orange-500/10 border-orange-500/30 text-orange-400',
    yellow:          'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
    green:           'bg-green-500/10 border-green-500/30 text-green-400',
  };
  return map[verdict] || 'bg-slate-500/10 border-slate-500/30 text-slate-400';
}

export function verdictHexColor(verdict: VerdictLabel | VerdictColor): string {
  const map: Record<string, string> = {
    Malicious:         '#ef4444',
    'Likely Phishing': '#f97316',
    Suspicious:        '#eab308',
    Benign:            '#22c55e',
    red:               '#ef4444',
    orange:            '#f97316',
    yellow:            '#eab308',
    green:             '#22c55e',
  };
  return map[verdict] || '#64748b';
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export function truncate(str: string, n = 40): string {
  return str.length > n ? str.slice(0, n) + '…' : str;
}

export function scoreToLabel(score: number): VerdictLabel {
  if (score >= 80) return 'Malicious';
  if (score >= 50) return 'Likely Phishing';
  if (score >= 25) return 'Suspicious';
  return 'Benign';
}
