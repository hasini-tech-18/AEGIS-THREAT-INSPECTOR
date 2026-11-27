import { useState } from 'react';
import {
  AlertCircle,
  Check,
  Copy,
  Eye,
  EyeOff,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  RotateCcw,
} from 'lucide-react';
import type { IndicatorSeverity, ScanHistoryItem } from '../types/threat';
import {
  defangValue,
  formatDetectedType,
  formatTimestamp,
  getRiskTheme,
} from '../utils/threatHelpers';
import { RiskMeter } from './RiskMeter';

interface ThreatResultPanelProps {
  item: ScanHistoryItem | null;
  isAnalyzing: boolean;
  error: string | null;
  onRetry?: () => void;
}

function getSeverityTextClass(severity: IndicatorSeverity): string {
  switch (severity) {
    case 'high':
      return 'text-rose-400';
    case 'medium':
      return 'text-amber-400';
    case 'low':
      return 'text-emerald-400';
  }
}

function getSeverityLabel(severity: IndicatorSeverity): string {
  switch (severity) {
    case 'high':
      return 'High Risk';
    case 'medium':
      return 'Caution';
    case 'low':
      return 'Low / Clear';
  }
}

export function ThreatResultPanel({
  item,
  isAnalyzing,
  error,
  onRetry,
}: ThreatResultPanelProps) {
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
  const [defangUrls, setDefangUrls] = useState(true);

  if (isAnalyzing) {
    return (
      <section
        aria-label="Analysis in progress"
        className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-6"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800/80">
          <div className="flex items-center gap-4">
            <div className="w-24 h-24 rounded-full bg-slate-800/70 animate-pulse" />
            <div className="space-y-2.5">
              <div className="h-5 w-36 bg-slate-800 rounded animate-pulse" />
              <div className="h-4 w-56 bg-slate-800/70 rounded animate-pulse" />
            </div>
          </div>
          <div className="h-4 w-40 bg-slate-800/70 rounded animate-pulse" />
        </div>
        <div className="space-y-3">
          <div className="h-4 w-32 bg-slate-800 rounded animate-pulse" />
          <div className="h-4 w-full bg-slate-800/60 rounded animate-pulse" />
          <div className="h-4 w-4/5 bg-slate-800/60 rounded animate-pulse" />
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-2">
          <div className="h-32 bg-slate-800/40 rounded-lg animate-pulse" />
          <div className="h-32 bg-slate-800/40 rounded-lg animate-pulse" />
        </div>
      </section>
    );
  }

  if (error) {
    return (
      <section
        role="alert"
        className="bg-[#111827] border border-rose-500/40 rounded-xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
      >
        <div className="flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" aria-hidden="true" />
          <div className="space-y-1">
            <h3 className="text-sm font-semibold text-rose-300">Analysis Could Not Complete</h3>
            <p className="text-sm text-slate-300">{error}</p>
          </div>
        </div>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Try Again</span>
          </button>
        )}
      </section>
    );
  }

  if (!item) {
    return null;
  }

  const { result } = item;
  const theme = getRiskTheme(result.riskLevel);
  const hasArtifacts =
    result.extractedArtifacts.urls.length > 0 ||
    result.extractedArtifacts.domains.length > 0 ||
    result.extractedArtifacts.phoneNumbers.length > 0 ||
    result.extractedArtifacts.emails.length > 0;

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedValue(text);
      setTimeout(() => setCopiedValue(null), 1600);
    } catch {
      // Clipboard access unavailable
    }
  };

  return (
    <section
      aria-label="Threat analysis report"
      className={`bg-[#111827] border ${theme.borderClass} rounded-xl p-6 space-y-6`}
    >
      {/* Top Verdict Summary */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center gap-6">
          <RiskMeter score={result.riskScore} level={result.riskLevel} />
          <div className="space-y-2 max-w-2xl">
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <span className="font-medium text-slate-300">
                {formatDetectedType(result.detectedType)}
              </span>
              <span aria-hidden="true">·</span>
              <span>{result.category}</span>
              {result.analysisSource === 'offline' && (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="text-sky-400 font-medium">Instant Offline Check</span>
                </>
              )}
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums">{formatTimestamp(item.analyzedAt)}</span>
            </div>
            <h2 className="text-lg sm:text-xl font-semibold text-slate-100 leading-snug">
              {result.verdictHeadline}
            </h2>
          </div>
        </div>
      </div>

      {/* Submitted Input Preview */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Analyzed Input</span>
          <button
            type="button"
            onClick={() => handleCopy(item.input)}
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
          >
            {copiedValue === item.input ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Copy Input</span>
              </>
            )}
          </button>
        </div>
        <p className="text-sm font-mono text-slate-300 bg-[#0B0F17] border border-slate-800/80 rounded-lg px-4 py-3 break-all">
          {result.riskLevel !== 'safe' && result.detectedType === 'url'
            ? defangValue(item.input)
            : item.input}
        </p>
      </div>

      {/* Explanation Section */}
      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-slate-200">
          {result.riskLevel === 'safe' ? 'Why This Appears Safe' : 'Why This Is Risky'}
        </h3>
        <p className="text-sm sm:text-[15px] leading-relaxed text-slate-300">
          {result.explanation}
        </p>
      </div>

      {/* Two-Column Breakdown: Forensic Indicators & Safety Tips */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 pt-2 border-t border-slate-800/80">
        {/* Indicators */}
        <div className="space-y-3 pt-4">
          <h3 className="text-sm font-semibold text-slate-200">Detected Signals</h3>
          {result.indicators.length === 0 ? (
            <p className="text-sm text-slate-400">No notable risk signals were extracted.</p>
          ) : (
            <ul className="divide-y divide-slate-800/80">
              {result.indicators.map((ind, idx) => {
                const SevIcon =
                  ind.severity === 'high'
                    ? ShieldAlert
                    : ind.severity === 'medium'
                      ? AlertTriangle
                      : ShieldCheck;
                const sevColor = getSeverityTextClass(ind.severity);
                return (
                  <li key={`${ind.signal}-${idx}`} className="py-3 first:pt-0 last:pb-0 space-y-1">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-sm font-medium text-slate-100">{ind.signal}</span>
                      <span
                        className={`inline-flex items-center gap-1.5 text-xs font-medium shrink-0 ${sevColor}`}
                      >
                        <SevIcon className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>{getSeverityLabel(ind.severity)}</span>
                      </span>
                    </div>
                    <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
                      {ind.detail}
                    </p>
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        {/* Safety Tips */}
        <div className="space-y-3 pt-4">
          <h3 className="text-sm font-semibold text-slate-200">Recommended Safety Tips</h3>
          {result.safetyTips.length === 0 ? (
            <p className="text-sm text-slate-400">Continue following standard verification practices.</p>
          ) : (
            <ol className="space-y-3">
              {result.safetyTips.map((tip, idx) => (
                <li key={idx} className="flex items-start gap-3 text-sm text-slate-300 leading-relaxed">
                  <span className="font-mono tabular-nums text-xs font-semibold text-sky-400 bg-sky-500/10 border border-sky-500/20 rounded px-2 py-0.5 mt-0.5 shrink-0">
                    {String(idx + 1).padStart(2, '0')}
                  </span>
                  <span>{tip}</span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>

      {/* Extracted Artifacts (if any) */}
      {hasArtifacts && (
        <div className="pt-4 border-t border-slate-800/80 space-y-3">
          <div className="flex items-center justify-between gap-4">
            <h3 className="text-sm font-semibold text-slate-200">Extracted Artifacts</h3>
            {result.extractedArtifacts.urls.length > 0 && (
              <button
                type="button"
                onClick={() => setDefangUrls((prev) => !prev)}
                className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
              >
                {defangUrls ? (
                  <>
                    <Eye className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Show Raw Links</span>
                  </>
                ) : (
                  <>
                    <EyeOff className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Defang Links</span>
                  </>
                )}
              </button>
            )}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            {result.extractedArtifacts.urls.map((url) => {
              const display = defangUrls ? defangValue(url) : url;
              return (
                <div
                  key={url}
                  className="flex items-center justify-between gap-3 bg-[#0B0F17] border border-slate-800 rounded-lg px-3 py-2"
                >
                  <div className="min-w-0">
                    <span className="text-slate-500 block text-[11px]">URL</span>
                    <span className="font-mono text-slate-200 truncate block">{display}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleCopy(url)}
                    className="text-slate-400 hover:text-slate-200 shrink-0 p-1 cursor-pointer"
                    aria-label="Copy URL"
                  >
                    {copiedValue === url ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              );
            })}
            {result.extractedArtifacts.domains.map((domain) => (
              <div
                key={domain}
                className="flex items-center justify-between gap-3 bg-[#0B0F17] border border-slate-800 rounded-lg px-3 py-2"
              >
                <div className="min-w-0">
                  <span className="text-slate-500 block text-[11px]">Domain</span>
                  <span className="font-mono text-slate-200 truncate block">
                    {defangUrls ? defangValue(domain) : domain}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => handleCopy(domain)}
                  className="text-slate-400 hover:text-slate-200 shrink-0 p-1 cursor-pointer"
                  aria-label="Copy domain"
                >
                  {copiedValue === domain ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            ))}
            {result.extractedArtifacts.phoneNumbers.map((phone) => (
              <div
                key={phone}
                className="flex items-center justify-between gap-3 bg-[#0B0F17] border border-slate-800 rounded-lg px-3 py-2"
              >
                <div className="min-w-0">
                  <span className="text-slate-500 block text-[11px]">Phone Number</span>
                  <span className="font-mono tabular-nums text-slate-200 truncate block">{phone}</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleCopy(phone)}
                  className="text-slate-400 hover:text-slate-200 shrink-0 p-1 cursor-pointer"
                  aria-label="Copy phone number"
                >
                  {copiedValue === phone ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            ))}
            {result.extractedArtifacts.emails.map((email) => (
              <div
                key={email}
                className="flex items-center justify-between gap-3 bg-[#0B0F17] border border-slate-800 rounded-lg px-3 py-2"
              >
                <div className="min-w-0">
                  <span className="text-slate-500 block text-[11px]">Email Address</span>
                  <span className="font-mono text-slate-200 truncate block">{email}</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleCopy(email)}
                  className="text-slate-400 hover:text-slate-200 shrink-0 p-1 cursor-pointer"
                  aria-label="Copy email address"
                >
                  {copiedValue === email ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
