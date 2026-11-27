import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  Download,
  ExternalLink,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import type { DetectedType, RiskLevel, ScanHistoryItem } from '../types/threat';
import {
  exportHistoryToCsv,
  formatDetectedType,
  formatTimestamp,
  getRiskTheme,
} from '../utils/threatHelpers';

interface HistoryViewProps {
  history: ScanHistoryItem[];
  onInspect: (item: ScanHistoryItem) => void;
  onRerun: (item: ScanHistoryItem) => void;
  onDelete: (id: string) => void;
  onClearAll: () => void;
  onGoToScanner: () => void;
}

export function HistoryView({
  history,
  onInspect,
  onRerun,
  onDelete,
  onClearAll,
  onGoToScanner,
}: HistoryViewProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<'all' | RiskLevel>('all');
  const [typeFilter, setTypeFilter] = useState<'all' | DetectedType>('all');
  const [confirmClear, setConfirmClear] = useState(false);

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return history.filter((item) => {
      if (riskFilter !== 'all' && item.result.riskLevel !== riskFilter) return false;
      if (typeFilter !== 'all' && item.result.detectedType !== typeFilter) return false;
      if (!q) return true;
      return (
        item.input.toLowerCase().includes(q) ||
        item.result.category.toLowerCase().includes(q) ||
        item.result.verdictHeadline.toLowerCase().includes(q)
      );
    });
  }, [history, searchQuery, riskFilter, typeFilter]);

  if (history.length === 0) {
    return (
      <section className="bg-[#111827] border border-slate-800 rounded-xl p-12 text-center space-y-4">
        <div className="mx-auto w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400">
          <Search className="w-5 h-5" aria-hidden="true" />
        </div>
        <div className="space-y-1.5 max-w-md mx-auto">
          <h2 className="text-lg font-semibold text-slate-100">No Scan History Yet</h2>
          <p className="text-sm text-slate-400">
            Every link, message, or phone number you inspect is saved here so you can review past
            verdicts, compare patterns, or export a report.
          </p>
        </div>
        <div className="pt-2">
          <button
            type="button"
            onClick={onGoToScanner}
            className="px-4 py-2.5 text-sm font-medium bg-sky-500 hover:bg-sky-400 text-slate-950 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Run First Threat Check
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="space-y-6">
      {/* Toolbar: Search, Filters & Actions */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="relative flex-1 max-w-md">
            <Search
              className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
              aria-hidden="true"
            />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search links, messages, phone numbers, or categories..."
              className="w-full bg-[#0B0F17] border border-slate-800 focus:border-sky-500/70 focus:outline-none rounded-lg pl-10 pr-4 py-2 text-sm text-slate-100 placeholder:text-slate-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => exportHistoryToCsv(filtered.length > 0 ? filtered : history)}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Export CSV</span>
            </button>

            {!confirmClear ? (
              <button
                type="button"
                onClick={() => setConfirmClear(true)}
                className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-rose-300 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/25 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Clear History</span>
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    onClearAll();
                    setConfirmClear(false);
                  }}
                  className="px-3 py-2 text-xs font-medium text-white bg-rose-600 hover:bg-rose-500 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Confirm Clear
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmClear(false)}
                  className="px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Filter Segments */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
          <div className="flex flex-wrap items-center gap-1 p-1 bg-[#0B0F17] border border-slate-800 rounded-lg w-fit">
            {(['all', 'dangerous', 'suspicious', 'safe'] as const).map((level) => (
              <button
                key={level}
                type="button"
                onClick={() => setRiskFilter(level)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  riskFilter === level
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {level === 'all'
                  ? 'All Risks'
                  : level === 'dangerous'
                    ? 'Dangerous'
                    : level === 'suspicious'
                      ? 'Suspicious'
                      : 'Safe'}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-1 p-1 bg-[#0B0F17] border border-slate-800 rounded-lg w-fit">
            {(['all', 'url', 'message', 'phone'] as const).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTypeFilter(t)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  typeFilter === t
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {t === 'all'
                  ? 'All Types'
                  : t === 'url'
                    ? 'Links'
                    : t === 'message'
                      ? 'Messages'
                      : 'Phones'}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* High-Density History Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
        {filtered.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-400">
            No scans match your current search or filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs font-medium text-slate-400 bg-[#0E1420]">
                  <th className="py-3 px-4 whitespace-nowrap">Risk Verdict</th>
                  <th className="py-3 px-4 whitespace-nowrap text-right">Score</th>
                  <th className="py-3 px-4 whitespace-nowrap">Type</th>
                  <th className="py-3 px-4">Submitted Content</th>
                  <th className="py-3 px-4 whitespace-nowrap">Category</th>
                  <th className="py-3 px-4 whitespace-nowrap text-right">Checked</th>
                  <th className="py-3 px-4 whitespace-nowrap text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-sm">
                {filtered.map((item) => {
                  const theme = getRiskTheme(item.result.riskLevel);
                  const RiskIcon =
                    item.result.riskLevel === 'safe'
                      ? ShieldCheck
                      : item.result.riskLevel === 'suspicious'
                        ? AlertTriangle
                        : ShieldAlert;
                  return (
                    <tr
                      key={item.id}
                      className="hover:bg-slate-800/35 transition-colors group"
                    >
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-1.5 font-medium ${theme.textClass}`}>
                          <RiskIcon className="w-4 h-4 shrink-0" aria-hidden="true" />
                          <span>{theme.label}</span>
                        </span>
                      </td>
                      <td className={`py-3 px-4 text-right font-mono tabular-nums font-semibold ${theme.textClass}`}>
                        {item.result.riskScore}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-xs text-slate-300">
                        {formatDetectedType(item.result.detectedType)}
                      </td>
                      <td className="py-3 px-4 max-w-xs sm:max-w-sm">
                        <button
                          type="button"
                          onClick={() => onInspect(item)}
                          className="text-left font-mono text-xs text-slate-200 hover:text-sky-400 truncate block w-full cursor-pointer transition-colors"
                          title={item.input}
                        >
                          {item.input}
                        </button>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-xs text-slate-400">
                        {item.result.category}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-right font-mono tabular-nums text-xs text-slate-400">
                        {formatTimestamp(item.analyzedAt)}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-right">
                        <div className="inline-flex items-center justify-end gap-1">
                          <button
                            type="button"
                            onClick={() => onInspect(item)}
                            className="p-1.5 text-slate-400 hover:text-sky-400 rounded-md hover:bg-slate-800 transition-colors cursor-pointer"
                            title="View full report"
                            aria-label="View full report"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </button>
                          <button
                            type="button"
                            onClick={() => onRerun(item)}
                            className="p-1.5 text-slate-400 hover:text-slate-100 rounded-md hover:bg-slate-800 transition-colors cursor-pointer"
                            title="Re-run check"
                            aria-label="Re-run check"
                          >
                            <RotateCcw className="w-4 h-4" />
                          </button>
                          <button
                            type="button"
                            onClick={() => onDelete(item.id)}
                            className="p-1.5 text-slate-400 hover:text-rose-400 rounded-md hover:bg-slate-800 transition-colors cursor-pointer"
                            title="Delete entry"
                            aria-label="Delete entry"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
