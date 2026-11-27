import { Link2, MessageSquareWarning, PhoneCall, ShieldCheck } from 'lucide-react';

interface SafetyPlaybookViewProps {
  onGoToScanner: () => void;
}

export function SafetyPlaybookView({ onGoToScanner }: SafetyPlaybookViewProps) {
  const vectors = [
    {
      title: 'Suspicious Links & URLs',
      icon: Link2,
      redFlags: [
        'Lookalike domains using typosquatting (e.g., paypa1 vs paypal) or character substitution.',
        'URL shorteners or nested subdomains hiding the actual root domain.',
        'Unencrypted HTTP links requesting logins, card numbers, or identity documents.',
        'High-abuse top-level domains paired with urgent account-suspension paths.',
      ],
      action: 'Always type the official website address directly into your browser instead of tapping unexpected links.',
    },
    {
      title: 'Phishing & Smishing Messages',
      icon: MessageSquareWarning,
      redFlags: [
        'Artificial urgency demanding action within 12–24 hours to avoid fees or account locks.',
        'Unexpected parcel delivery fees, tax refunds, or unpaid toll notifications.',
        'Requests for one-time passcodes (OTP), PINs, or remote access software.',
        'Generic greetings paired with mismatched sender email domains.',
      ],
      action: 'Verify claims by opening your official bank, carrier, or service app independently before replying.',
    },
    {
      title: 'Scam Phone Numbers & Vishing',
      icon: PhoneCall,
      redFlags: [
        'Callers impersonating government agencies, law enforcement, or bank fraud desks.',
        'Demands for payment via gift cards, cryptocurrency, or instant wire transfers.',
        'Caller ID spoofing claiming to be a local number or official support hotline.',
        'Pressure to stay on the line without consulting anyone else.',
      ],
      action: 'Hang up immediately and call the official customer support number printed on the back of your card or statement.',
    },
  ];

  return (
    <section className="space-y-8">
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1 max-w-2xl">
          <h2 className="text-lg font-semibold text-slate-100">Threat Recognition Playbook</h2>
          <p className="text-sm text-slate-400">
            Learn the core signals attackers rely on across web links, text messages, and voice calls.
          </p>
        </div>
        <button
          type="button"
          onClick={onGoToScanner}
          className="px-4 py-2 text-xs font-medium bg-sky-500 hover:bg-sky-400 text-slate-950 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          Inspect an Artifact
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {vectors.map((vector) => {
          const Icon = vector.icon;
          return (
            <article
              key={vector.title}
              className="bg-[#111827] border border-slate-800 rounded-xl p-6 flex flex-col justify-between gap-6"
            >
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-slate-800/80 border border-slate-700 flex items-center justify-center text-sky-400 shrink-0">
                    <Icon className="w-4 h-4" aria-hidden="true" />
                  </div>
                  <h3 className="text-base font-semibold text-slate-100">{vector.title}</h3>
                </div>
                <ul className="space-y-2.5 text-sm text-slate-300">
                  {vector.redFlags.map((flag) => (
                    <li key={flag} className="flex items-start gap-2.5 leading-relaxed">
                      <span className="text-amber-400 font-mono text-xs mt-1 shrink-0" aria-hidden="true">
                        •
                      </span>
                      <span>{flag}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="pt-4 border-t border-slate-800/80 space-y-1.5">
                <div className="flex items-center gap-1.5 text-xs font-medium text-emerald-400">
                  <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Best Defense</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{vector.action}</p>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
