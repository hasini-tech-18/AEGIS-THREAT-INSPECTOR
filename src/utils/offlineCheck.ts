import type {
  DetectedType,
  ExtractedArtifacts,
  InputTypeHint,
  ThreatAnalysisResult,
  ThreatIndicator,
} from '../types/threat';

interface OfflineRule {
  id: string;
  label: string;
  pattern: RegExp;
  signal: string;
  detail: string;
  tip: string;
  scoreWeight: number;
}

const OFFLINE_DANGEROUS_RULES: OfflineRule[] = [
  {
    id: 'bitly',
    label: 'bit.ly',
    pattern: /(?:^|[\s/."'(])bit\.ly(?:[\s/?"'#):]|$)/i,
    signal: 'Shortened Link (bit.ly)',
    detail:
      'Contains a bit.ly shortened URL, which masks the true destination website and is commonly used in phishing campaigns to bypass link inspection.',
    tip: 'Do not open shortened bit.ly links from unexpected messages unless you can verify the destination first.',
    scoreWeight: 82,
  },
  {
    id: 'tinyurl',
    label: 'tinyurl',
    pattern: /tinyurl(?:\.com)?/i,
    signal: 'Shortened Link (tinyurl)',
    detail:
      'Contains a TinyURL redirect link that hides the real target domain, a frequent tactic for concealing malicious landing pages.',
    tip: 'Avoid clicking TinyURL links from unknown senders; navigate directly to official websites instead.',
    scoreWeight: 82,
  },
  {
    id: 'free-money',
    label: 'free money',
    pattern: /free[\s\-_+]*money/i,
    signal: 'Financial Lure ("free money")',
    detail:
      'Contains a "free money" giveaway or payout lure, a classic social-engineering hook used to harvest personal details or payment information.',
    tip: 'Treat unsolicited promises of free money, prizes, or instant payouts as scams and never share bank or card details.',
    scoreWeight: 90,
  },
  {
    id: 'verify-security-account',
    label: 'verify security account',
    pattern: /verify[\s\-_+]*security[\s\-_+]*account/i,
    signal: 'Account Verification Lure ("verify security account")',
    detail:
      'Contains "verify security account" phrasing designed to create urgency and trick users into entering credentials on a fraudulent page.',
    tip: 'Never verify your account through a pasted link; open your provider’s official app or website directly.',
    scoreWeight: 92,
  },
  {
    id: 'login',
    label: 'login',
    pattern: /(?:https?:\/\/|www\.|[a-z0-9-]+\.[a-z]{2,})[^\s]*login|(?:\blogin\b)/i,
    signal: 'Suspicious Login Reference ("login")',
    detail:
      'References a login path or sign-in prompt, which is frequently used in credential-harvesting links to impersonate trusted sign-in portals.',
    tip: 'Do not enter your username, password, or one-time code on a login page reached via a link.',
    scoreWeight: 80,
  },
];

function extractArtifactsOffline(rawInput: string): {
  artifacts: ExtractedArtifacts;
  detectedType: DetectedType;
} {
  const trimmed = rawInput.trim();
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"{}|\\^`[\]]+/gi;
  const domainOnlyRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?:\/[^\s]*)?$/i;
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const phoneRegex = /(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{3,4}/g;

  const urlMatches = trimmed.match(urlRegex) ?? [];
  const urls = Array.from(new Set(urlMatches));

  if (urls.length === 0 && domainOnlyRegex.test(trimmed)) {
    urls.push(trimmed.startsWith('http') ? trimmed : `https://${trimmed}`);
  }

  const domains: string[] = [];
  for (const candidateUrl of urls) {
    try {
      const normalized = candidateUrl.startsWith('http') ? candidateUrl : `https://${candidateUrl}`;
      const parsed = new URL(normalized);
      domains.push(parsed.hostname.toLowerCase());
    } catch {
      // Ignore malformed URL during offline parse
    }
  }

  const emails = Array.from(new Set(trimmed.match(emailRegex) ?? []));
  const phoneMatches = (trimmed.match(phoneRegex) ?? [])
    .map((p) => p.trim())
    .filter((p) => p.replace(/\D/g, '').length >= 7 && p.replace(/\D/g, '').length <= 15);
  const phoneNumbers = Array.from(new Set(phoneMatches));

  let detectedType: DetectedType = 'message';
  const cleanedPhoneDigits = trimmed.replace(/[\s().+-]/g, '');
  if (/^\d{7,15}$/.test(cleanedPhoneDigits) && !trimmed.includes(' ') && trimmed.length <= 24) {
    detectedType = 'phone';
  } else if (/^\+?[\d\s().-]{7,22}$/.test(trimmed)) {
    detectedType = 'phone';
  } else if ((urls.length > 0 && trimmed.length < 180 && !trimmed.includes(' ')) || domainOnlyRegex.test(trimmed)) {
    detectedType = 'url';
  }

  return {
    artifacts: {
      urls,
      domains: Array.from(new Set(domains)),
      phoneNumbers,
      emails,
    },
    detectedType,
  };
}

export function runOfflineThreatCheck(
  rawInput: string,
  hint: InputTypeHint = 'auto'
): ThreatAnalysisResult | null {
  const trimmed = rawInput.trim();
  if (!trimmed) return null;

  const matchedRules = OFFLINE_DANGEROUS_RULES.filter((rule) => rule.pattern.test(trimmed));
  if (matchedRules.length === 0) {
    return null;
  }

  const { artifacts, detectedType: guessedType } = extractArtifactsOffline(trimmed);
  const detectedType: DetectedType = hint === 'auto' ? guessedType : hint;

  const highestWeight = Math.max(...matchedRules.map((r) => r.scoreWeight));
  const extraMatchesBonus = (matchedRules.length - 1) * 5;
  const riskScore = Math.min(98, highestWeight + extraMatchesBonus);

  const matchedLabels = matchedRules.map((r) => `"${r.label}"`).join(', ');

  const indicators: ThreatIndicator[] = matchedRules.map((rule) => ({
    signal: rule.signal,
    severity: 'high',
    detail: rule.detail,
  }));

  const safetyTips = Array.from(
    new Set([
      ...matchedRules.map((r) => r.tip),
      'If you already opened the link or entered credentials, change your password immediately and enable two-factor authentication.',
      'Delete the message and report or block the sender.',
    ])
  ).slice(0, 5);

  return {
    detectedType,
    riskLevel: 'dangerous',
    riskScore,
    verdictHeadline: `Flagged as Dangerous by offline rule check (${matchedLabels}).`,
    category: 'Offline Rule Match — High-Risk Pattern',
    explanation: `Our free offline scanner immediately flagged this submission as Dangerous without calling AI because it contains high-risk indicator(s): ${matchedLabels}. Attackers frequently combine shortened links, credential-login paths, and urgency or payout lures to steal passwords and financial data.`,
    indicators,
    safetyTips,
    extractedArtifacts: artifacts,
    analysisSource: 'offline',
  };
}
