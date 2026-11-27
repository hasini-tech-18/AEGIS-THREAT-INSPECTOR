import type { DetectedType, RiskLevel, ScanHistoryItem } from '../types/threat';

const HISTORY_STORAGE_KEY = 'aegis_threat_scan_history_v1';

export interface RiskTheme {
  label: string;
  textClass: string;
  surfaceClass: string;
  borderClass: string;
  barClass: string;
  strokeColor: string;
  trackColor: string;
}

export function getRiskTheme(level: RiskLevel): RiskTheme {
  switch (level) {
    case 'safe':
      return {
        label: 'Safe',
        textClass: 'text-emerald-400',
        surfaceClass: 'bg-emerald-500/10',
        borderClass: 'border-emerald-500/30',
        barClass: 'bg-emerald-500',
        strokeColor: '#16A34A',
        trackColor: 'rgba(22, 163, 74, 0.16)',
      };
    case 'suspicious':
      return {
        label: 'Suspicious',
        textClass: 'text-amber-400',
        surfaceClass: 'bg-amber-500/10',
        borderClass: 'border-amber-500/30',
        barClass: 'bg-amber-500',
        strokeColor: '#D97706',
        trackColor: 'rgba(217, 119, 6, 0.16)',
      };
    case 'dangerous':
      return {
        label: 'Dangerous',
        textClass: 'text-rose-400',
        surfaceClass: 'bg-rose-500/10',
        borderClass: 'border-rose-500/30',
        barClass: 'bg-rose-500',
        strokeColor: '#DC2626',
        trackColor: 'rgba(220, 38, 38, 0.16)',
      };
  }
}

export function formatDetectedType(type: DetectedType): string {
  switch (type) {
    case 'url':
      return 'Link / URL';
    case 'message':
      return 'Message / Text';
    case 'phone':
      return 'Phone Number';
  }
}

export function defangValue(value: string): string {
  return value.replace(/^http:\/\//i, 'hxxp://').replace(/^https:\/\//i, 'hxxps://').replace(/\./g, '[.]');
}

export function formatTimestamp(iso: string): string {
  try {
    const date = new Date(iso);
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(date);
  } catch {
    return iso;
  }
}

export function loadScanHistory(): ScanHistoryItem[] {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (item): item is ScanHistoryItem =>
        Boolean(item && typeof item.id === 'string' && typeof item.input === 'string' && item.result)
    );
  } catch {
    return [];
  }
}

export function saveScanHistory(items: ScanHistoryItem[]): void {
  try {
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(items.slice(0, 100)));
  } catch {
    // Ignore storage quota errors cleanly
  }
}

export function exportHistoryToCsv(items: ScanHistoryItem[]): void {
  const escapeCsv = (val: string) => `"${val.replace(/"/g, '""')}"`;
  const headers = ['Analyzed At', 'Detected Type', 'Risk Level', 'Risk Score', 'Category', 'Verdict', 'Submitted Input'];
  const rows = items.map((item) => [
    escapeCsv(item.analyzedAt),
    escapeCsv(formatDetectedType(item.result.detectedType)),
    escapeCsv(item.result.riskLevel.toUpperCase()),
    String(item.result.riskScore),
    escapeCsv(item.result.category),
    escapeCsv(item.result.verdictHeadline),
    escapeCsv(item.input.replace(/\s+/g, ' ').trim()),
  ]);
  const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `aegis-threat-history-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export interface SamplePrompt {
  id: string;
  label: string;
  hint: 'url' | 'message' | 'phone';
  value: string;
}

export const SAMPLE_PROMPTS: SamplePrompt[] = [
  {
    id: 'phishing-url',
    label: 'Phishing Link',
    hint: 'url',
    value: 'http://paypa1-security-verify.support/login/confirm-identity?session=9821a',
  },
  {
    id: 'smishing-msg',
    label: 'Delivery Scam SMS',
    hint: 'message',
    value:
      'USPS Notice: Your package #US948201 is held at customs due to an unpaid $2.95 redelivery fee. Update address within 12 hours at https://usps-redelivery-desk.xyz/pay to avoid return.',
  },
  {
    id: 'vishing-phone',
    label: 'Suspicious Caller',
    hint: 'phone',
    value: '+1 (888) 019-4821 — Caller claimed to be IRS Fraud Dept demanding immediate gift card settlement to prevent arrest warrant.',
  },
  {
    id: 'safe-url',
    label: 'Legitimate Link',
    hint: 'url',
    value: 'https://developer.mozilla.org/en-US/docs/Web/Security',
  },
];
