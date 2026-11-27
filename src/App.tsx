import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  BookOpen,
  History,
  LayoutDashboard,
  Menu,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import type { InputTypeHint, ScanHistoryItem, ThreatAnalysisResult } from './types/threat';
import {
  SAMPLE_PROMPTS,
  formatDetectedType,
  formatTimestamp,
  getRiskTheme,
  loadScanHistory,
  saveScanHistory,
} from './utils/threatHelpers';
import { runOfflineThreatCheck } from './utils/offlineCheck';
import { ThreatResultPanel } from './components/ThreatResultPanel';
import { HistoryView } from './components/HistoryView';
import { SafetyPlaybookView } from './components/SafetyPlaybookView';

type ActiveTab = 'dashboard' | 'history' | 'playbook';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [inputText, setInputText] = useState('');
  const [inputTypeHint, setInputTypeHint] = useState<InputTypeHint>('auto');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [history, setHistory] = useState<ScanHistoryItem[]>(() => loadScanHistory());
  const [activeItem, setActiveItem] = useState<ScanHistoryItem | null>(() => {
    const initial = loadScanHistory();
    return initial.length > 0 ? initial[0] : null;
  });

  const inputRef = useRef<HTMLTextAreaElement | null>(null);

  useEffect(() => {
    saveScanHistory(history);
  }, [history]);

  const stats = useMemo(() => {
    let safe = 0;
    let suspicious = 0;
    let dangerous = 0;
    for (const item of history) {
      if (item.result.riskLevel === 'safe') safe += 1;
      else if (item.result.riskLevel === 'suspicious') suspicious += 1;
      else dangerous += 1;
    }
    return {
      total: history.length,
      safe,
      suspicious,
      dangerous,
    };
  }, [history]);

  const runAnalysis = async (overrideText?: string, overrideHint?: InputTypeHint) => {
    const textToCheck = (overrideText ?? inputText).trim();
    const hintToUse = overrideHint ?? inputTypeHint;

    if (!textToCheck) {
      setError('Paste a suspicious link, text message, or phone number before checking.');
      inputRef.current?.focus();
      return;
    }

    setError(null);
    setActiveTab('dashboard');

    const offlineResult = runOfflineThreatCheck(textToCheck, hintToUse);
    if (offlineResult) {
      const offlineItem: ScanHistoryItem = {
        id:
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        input: textToCheck,
        inputTypeHint: hintToUse,
        analyzedAt: new Date().toISOString(),
        result: offlineResult,
      };
      setHistory((prev) => [offlineItem, ...prev]);
      setActiveItem(offlineItem);
      return;
    }

    setIsAnalyzing(true);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input: textToCheck,
          inputTypeHint: hintToUse,
        }),
      });

      const payload = (await response.json()) as ThreatAnalysisResult & { error?: string };

      if (!response.ok) {
        throw new Error(payload.error || 'Failed to complete threat analysis.');
      }

      const newItem: ScanHistoryItem = {
        id:
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        input: textToCheck,
        inputTypeHint: hintToUse,
        analyzedAt: new Date().toISOString(),
        result: payload,
      };

      setHistory((prev) => [newItem, ...prev]);
      setActiveItem(newItem);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unable to analyze input right now.';
      setError(msg);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleNewScan = () => {
    setInputText('');
    setInputTypeHint('auto');
    setError(null);
    setActiveItem(null);
    setActiveTab('dashboard');
    setTimeout(() => inputRef.current?.focus(), 50);
  };

  const handleInspectItem = (item: ScanHistoryItem) => {
    setActiveItem(item);
    setInputText(item.input);
    setInputTypeHint(item.inputTypeHint);
    setError(null);
    setActiveTab('dashboard');
  };

  const handleRerunItem = (item: ScanHistoryItem) => {
    setInputText(item.input);
    setInputTypeHint(item.inputTypeHint);
    void runAnalysis(item.input, item.inputTypeHint);
  };

  const handleDeleteItem = (id: string) => {
    setHistory((prev) => {
      const next = prev.filter((item) => item.id !== id);
      if (activeItem?.id === id) {
        setActiveItem(next.length > 0 ? next[0] : null);
      }
      return next;
    });
  };

  const handleClearAll = () => {
    setHistory([]);
    setActiveItem(null);
  };

  const breadcrumbLabel =
    activeTab === 'dashboard'
      ? 'Threat Dashboard'
      : activeTab === 'history'
        ? 'Scan History'
        : 'Safety Playbook';

  const navItems: Array<{ id: ActiveTab; label: string; icon: typeof LayoutDashboard; count?: number }> = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'history', label: 'Scan History', icon: History, count: history.length },
    { id: 'playbook', label: 'Safety Playbook', icon: BookOpen },
  ];

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:flex-col lg:w-64 lg:fixed lg:inset-y-0 bg-[#0E1420] border-r border-slate-800/90">
        <div className="h-16 px-6 flex items-center gap-3 border-b border-slate-800/90">
          <div className="w-8 h-8 rounded-lg bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-400 shrink-0">
            <Shield className="w-4 h-4" aria-hidden="true" />
          </div>
          <span className="font-display font-bold text-base tracking-tight text-slate-100 whitespace-nowrap shrink-0">
            Aegis Inspector
          </span>
        </div>

        <nav className="flex-1 px-4 py-6 space-y-1" aria-label="Primary navigation">
          {navItems.map((nav) => {
            const Icon = nav.icon;
            const isActive = activeTab === nav.id;
            return (
              <button
                key={nav.id}
                type="button"
                onClick={() => setActiveTab(nav.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 text-sm font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  isActive
                    ? 'bg-slate-800/90 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <span className="flex items-center gap-3">
                  <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                  <span>{nav.label}</span>
                </span>
                {typeof nav.count === 'number' && nav.count > 0 && (
                  <span className="font-mono tabular-nums text-xs text-slate-400">
                    {nav.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="p-5 border-t border-slate-800/90 space-y-3">
          <p className="text-xs font-medium text-slate-400">Session Overview</p>
          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between text-slate-300">
              <span>Safe Cleared</span>
              <span className="font-mono tabular-nums text-emerald-400 font-semibold">
                {stats.safe}
              </span>
            </div>
            <div className="flex items-center justify-between text-slate-300">
              <span>Suspicious</span>
              <span className="font-mono tabular-nums text-amber-400 font-semibold">
                {stats.suspicious}
              </span>
            </div>
            <div className="flex items-center justify-between text-slate-300">
              <span>Dangerous</span>
              <span className="font-mono tabular-nums text-rose-400 font-semibold">
                {stats.dangerous}
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileMenuOpen(false)}
            aria-hidden="true"
          />
          <aside className="relative w-64 max-w-full bg-[#0E1420] border-r border-slate-800 flex flex-col z-10">
            <div className="h-16 px-5 flex items-center justify-between border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <Shield className="w-4 h-4 text-sky-400" aria-hidden="true" />
                <span className="font-display font-bold text-base text-slate-100 whitespace-nowrap">
                  Aegis Inspector
                </span>
              </div>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                className="p-1.5 text-slate-400 hover:text-slate-200 rounded-lg cursor-pointer"
                aria-label="Close navigation"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <nav className="flex-1 px-4 py-6 space-y-1">
              {navItems.map((nav) => {
                const Icon = nav.icon;
                const isActive = activeTab === nav.id;
                return (
                  <button
                    key={nav.id}
                    type="button"
                    onClick={() => {
                      setActiveTab(nav.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center justify-between px-3.5 py-2.5 text-sm font-medium rounded-lg transition-colors cursor-pointer ${
                      isActive
                        ? 'bg-slate-800 text-slate-100'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                    }`}
                  >
                    <span className="flex items-center gap-3">
                      <Icon className="w-4 h-4" aria-hidden="true" />
                      <span>{nav.label}</span>
                    </span>
                    {typeof nav.count === 'number' && nav.count > 0 && (
                      <span className="font-mono tabular-nums text-xs text-slate-400">
                        {nav.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </aside>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 lg:pl-64 flex flex-col min-w-0">
        {/* Top Bar */}
        <header className="h-16 px-4 sm:px-8 border-b border-slate-800/90 bg-[#0B0F17]/95 backdrop-blur-sm sticky top-0 z-30 flex items-center justify-between gap-8">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800 cursor-pointer"
              aria-label="Open navigation"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2 text-sm truncate">
              <span className="text-slate-500 hidden sm:inline">Workspace</span>
              <span className="text-slate-600 hidden sm:inline" aria-hidden="true">
                /
              </span>
              <h1 className="font-semibold text-slate-100 truncate">{breadcrumbLabel}</h1>
            </div>
          </div>

          <button
            type="button"
            onClick={handleNewScan}
            className="px-4 py-2 text-xs font-medium bg-sky-500 hover:bg-sky-400 text-slate-950 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            New Scan
          </button>
        </header>

        {/* Viewport Container */}
        <main className="flex-1 w-full max-w-6xl mx-auto px-4 sm:px-8 py-8 space-y-8">
          {activeTab === 'dashboard' && (
            <>
              {/* 4-Column Summary Strip */}
              <section aria-label="Threat check summary" className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-[#111827] border border-slate-800 rounded-xl px-5 py-4 space-y-1">
                  <span className="text-xs text-slate-400">Total Checked</span>
                  <p className="text-2xl font-bold font-mono tabular-nums text-slate-100">
                    {stats.total}
                  </p>
                </div>
                <div className="bg-[#111827] border border-slate-800 rounded-xl px-5 py-4 space-y-1">
                  <span className="text-xs text-slate-400 flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                    <span>Safe</span>
                  </span>
                  <p className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
                    {stats.safe}
                  </p>
                </div>
                <div className="bg-[#111827] border border-slate-800 rounded-xl px-5 py-4 space-y-1">
                  <span className="text-xs text-slate-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
                    <span>Suspicious</span>
                  </span>
                  <p className="text-2xl font-bold font-mono tabular-nums text-amber-400">
                    {stats.suspicious}
                  </p>
                </div>
                <div className="bg-[#111827] border border-slate-800 rounded-xl px-5 py-4 space-y-1">
                  <span className="text-xs text-slate-400 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400" aria-hidden="true" />
                    <span>Dangerous</span>
                  </span>
                  <p className="text-2xl font-bold font-mono tabular-nums text-rose-400">
                    {stats.dangerous}
                  </p>
                </div>
              </section>

              {/* Dominant Focal Anchor: Threat Analyzer Input */}
              <section
                aria-label="Threat check scanner"
                className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-5"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <h2 className="text-lg font-semibold text-slate-100 text-balance">
                      Inspect a Suspicious Link, Message, or Phone Number
                    </h2>
                    <p className="text-sm text-slate-400">
                      Paste any URL, SMS, email excerpt, or caller number for immediate risk
                      scoring and safety guidance.
                    </p>
                  </div>

                  {/* Input Type Selector Tabs */}
                  <div
                    role="tablist"
                    aria-label="Artifact type"
                    className="flex items-center gap-1 p-1 bg-[#0B0F17] border border-slate-800 rounded-lg w-fit shrink-0"
                  >
                    {(
                      [
                        { id: 'auto', label: 'Auto-Detect' },
                        { id: 'url', label: 'Link' },
                        { id: 'message', label: 'Message' },
                        { id: 'phone', label: 'Phone' },
                      ] as const
                    ).map((tab) => (
                      <button
                        key={tab.id}
                        type="button"
                        role="tab"
                        aria-selected={inputTypeHint === tab.id}
                        onClick={() => setInputTypeHint(tab.id)}
                        className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          inputTypeHint === tab.id
                            ? 'bg-slate-800 text-slate-100'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <label htmlFor="threat-input" className="sr-only">
                    Suspicious link, message, or phone number
                  </label>
                  <textarea
                    id="threat-input"
                    ref={inputRef}
                    rows={4}
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    onKeyDown={(e) => {
                      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
                        e.preventDefault();
                        void runAnalysis();
                      }
                    }}
                    placeholder="Paste a suspicious URL (e.g. https://...), SMS or email text, or phone number (e.g. +1 800 555 0199)..."
                    className="w-full bg-[#0B0F17] border border-slate-800 focus:border-sky-500/80 focus:outline-none rounded-lg px-4 py-3.5 text-sm font-mono text-slate-100 placeholder:text-slate-500 placeholder:font-sans resize-y min-h-[112px]"
                  />
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
                  {/* Sample Quick-Fills */}
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="text-slate-500">Try sample:</span>
                      {SAMPLE_PROMPTS.map((sample) => {
                        const isSampleLoaded = inputText === sample.value;
                        return (
                          <button
                            key={sample.id}
                            type="button"
                            onClick={() => {
                              setInputText(sample.value);
                              setInputTypeHint(sample.hint);
                              setError(null);
                              requestAnimationFrame(() => {
                                inputRef.current?.focus();
                              });
                            }}
                            className={`px-2.5 py-1 rounded-md border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                              isSampleLoaded
                                ? 'text-sky-300 bg-sky-500/15 border-sky-500/40'
                                : 'text-slate-300 bg-slate-800/70 hover:bg-slate-800 border-slate-700/70'
                            }`}
                          >
                            {sample.label}
                          </button>
                        );
                      })}
                    </div>

                    <div className="flex items-center justify-end gap-3 shrink-0">
                      <span className="text-xs font-mono tabular-nums text-slate-500">
                        {inputText.length} / 5000
                      </span>
                      {inputText.length > 0 && (
                        <button
                          type="button"
                          onClick={() => {
                            setInputText('');
                            setError(null);
                          }}
                          className="px-3 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          Clear
                        </button>
                      )}
                      <button
                        type="button"
                        disabled={isAnalyzing}
                        onClick={() => void runAnalysis()}
                        className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold bg-sky-500 hover:bg-sky-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        <Search className="w-4 h-4" aria-hidden="true" />
                        <span>{isAnalyzing ? 'Analyzing...' : 'Check Threat'}</span>
                      </button>
                    </div>
                  </div>
                </div>
              </section>

              {/* Analysis Output */}
              <ThreatResultPanel
                item={activeItem}
                isAnalyzing={isAnalyzing}
                error={error}
                onRetry={() => void runAnalysis()}
              />

              {/* Recent Scans Preview */}
              {history.length > 0 && (
                <section aria-label="Recent checks" className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-semibold text-slate-200">Recent Checks</h2>
                    <button
                      type="button"
                      onClick={() => setActiveTab('history')}
                      className="text-xs font-medium text-sky-400 hover:text-sky-300 transition-colors cursor-pointer"
                    >
                      View All History ({history.length})
                    </button>
                  </div>
                  <div className="bg-[#111827] border border-slate-800 rounded-xl divide-y divide-slate-800/80">
                    {history.slice(0, 5).map((item) => {
                      const theme = getRiskTheme(item.result.riskLevel);
                      const Icon =
                        item.result.riskLevel === 'safe'
                          ? ShieldCheck
                          : item.result.riskLevel === 'suspicious'
                            ? AlertTriangle
                            : ShieldAlert;
                      const isSelected = activeItem?.id === item.id;
                      return (
                        <button
                          key={item.id}
                          type="button"
                          onClick={() => handleInspectItem(item)}
                          className={`w-full text-left px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/40 transition-colors cursor-pointer ${
                            isSelected ? 'bg-slate-800/50' : ''
                          }`}
                        >
                          <div className="flex items-center gap-3 min-w-0">
                            <span
                              className={`inline-flex items-center gap-1.5 text-xs font-semibold shrink-0 w-24 ${theme.textClass}`}
                            >
                              <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                              <span>{theme.label}</span>
                            </span>
                            <span className="font-mono text-xs text-slate-200 truncate">
                              {item.input}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-xs text-slate-400 shrink-0 pl-7 sm:pl-0">
                            <span>{formatDetectedType(item.result.detectedType)}</span>
                            <span aria-hidden="true">·</span>
                            <span className={`font-mono tabular-nums font-semibold ${theme.textClass}`}>
                              {item.result.riskScore}/100
                            </span>
                            <span aria-hidden="true">·</span>
                            <span className="font-mono tabular-nums">
                              {formatTimestamp(item.analyzedAt)}
                            </span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </section>
              )}
            </>
          )}

          {activeTab === 'history' && (
            <HistoryView
              history={history}
              onInspect={handleInspectItem}
              onRerun={handleRerunItem}
              onDelete={handleDeleteItem}
              onClearAll={handleClearAll}
              onGoToScanner={() => setActiveTab('dashboard')}
            />
          )}

          {activeTab === 'playbook' && (
            <SafetyPlaybookView onGoToScanner={() => setActiveTab('dashboard')} />
          )}
        </main>
      </div>
    </div>
  );
}
