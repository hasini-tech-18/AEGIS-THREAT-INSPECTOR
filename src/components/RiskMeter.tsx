import { AlertTriangle, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { RiskLevel } from '../types/threat';
import { getRiskTheme } from '../utils/threatHelpers';

interface RiskMeterProps {
  score: number;
  level: RiskLevel;
}

export function RiskMeter({ score, level }: RiskMeterProps) {
  const theme = getRiskTheme(level);
  const clamped = Math.max(0, Math.min(100, score));
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const arcFraction = 0.75;
  const arcLength = circumference * arcFraction;
  const filledLength = arcLength * (clamped / 100);

  const Icon =
    level === 'safe' ? ShieldCheck : level === 'suspicious' ? AlertTriangle : ShieldAlert;

  return (
    <div className="flex items-center gap-5 shrink-0">
      <div className="relative w-28 h-28 flex items-center justify-center">
        <svg className="w-28 h-28 -rotate-225" viewBox="0 0 108 108" aria-hidden="true">
          <circle
            cx="54"
            cy="54"
            r={radius}
            fill="none"
            stroke={theme.trackColor}
            strokeWidth="8"
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeLinecap="round"
          />
          <circle
            cx="54"
            cy="54"
            r={radius}
            fill="none"
            stroke={theme.strokeColor}
            strokeWidth="8"
            strokeDasharray={`${filledLength} ${circumference}`}
            strokeLinecap="round"
            className="transition-[stroke-dasharray] duration-500 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center pt-1">
          <span className={`text-2xl font-bold font-mono tabular-nums ${theme.textClass}`}>
            {clamped}
          </span>
          <span className="text-[11px] text-slate-400 font-mono tabular-nums">/ 100</span>
        </div>
      </div>

      <div className="flex flex-col gap-1">
        <div className={`inline-flex items-center gap-2 text-lg font-semibold ${theme.textClass}`}>
          <Icon className="w-5 h-5 shrink-0" aria-hidden="true" />
          <span>{theme.label}</span>
        </div>
        <p className="text-xs text-slate-400">
          {level === 'safe'
            ? 'Low threat probability'
            : level === 'suspicious'
              ? 'Caution advised before proceeding'
              : 'High risk — avoid interaction'}
        </p>
      </div>
    </div>
  );
}
