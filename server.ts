import 'dotenv/config';
import express from 'express';
import type { Request, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI, Type } from '@google/genai';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

type InputTypeHint = 'auto' | 'url' | 'message' | 'phone';
type DetectedType = 'url' | 'message' | 'phone';
type RiskLevel = 'safe' | 'suspicious' | 'dangerous';

interface ForensicHints {
  urls: string[];
  domains: string[];
  phoneNumbers: string[];
  emails: string[];
  structuralNotes: string[];
  guessedType: DetectedType;
}

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rb.gy',
  'cutt.ly',
  'shorturl.at',
  'tiny.cc',
  'rebrand.ly',
  'lnkd.in',
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'club',
  'icu',
  'vip',
  'work',
  'click',
  'link',
  'gq',
  'tk',
  'ml',
  'cf',
  'ga',
  'buzz',
  'loan',
  'rest',
  'support',
]);

function extractForensicHints(rawInput: string, hint: InputTypeHint): ForensicHints {
  const trimmed = rawInput.trim();
  const structuralNotes: string[] = [];

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
      const hostname = parsed.hostname.toLowerCase();
      domains.push(hostname);

      if (parsed.protocol === 'http:') {
        structuralNotes.push(`Unencrypted HTTP scheme detected on ${hostname}.`);
      }
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) {
        structuralNotes.push(`Raw IPv4 host used instead of a domain name (${hostname}).`);
      }
      if (hostname.includes('xn--')) {
        structuralNotes.push(`Punycode/IDN domain detected (${hostname}), which can indicate homograph spoofing.`);
      }
      if (URL_SHORTENERS.has(hostname)) {
        structuralNotes.push(`URL shortener detected (${hostname}), obscuring the final destination.`);
      }
      const tld = hostname.split('.').pop() ?? '';
      if (SUSPICIOUS_TLDS.has(tld)) {
        structuralNotes.push(`High-abuse top-level domain (.${tld}) used on ${hostname}.`);
      }
      if (hostname.split('.').length >= 4) {
        structuralNotes.push(`Deep subdomain nesting detected (${hostname}), often used to mimic trusted brands.`);
      }
      if (parsed.username || parsed.password || candidateUrl.includes('@')) {
        structuralNotes.push(`Embedded '@' or credential-style authority prefix found in URL.`);
      }
    } catch {
      structuralNotes.push(`Malformed URL structure detected (${candidateUrl}).`);
    }
  }

  const emails = Array.from(new Set(trimmed.match(emailRegex) ?? []));
  const phoneMatches = (trimmed.match(phoneRegex) ?? [])
    .map((p) => p.trim())
    .filter((p) => p.replace(/\D/g, '').length >= 7 && p.replace(/\D/g, '').length <= 15);
  const phoneNumbers = Array.from(new Set(phoneMatches));

  if (/\b(urgent|immediately|suspended|locked|verify now|otp|one-time|wire transfer|gift card|overdue|customs fee|tax refund|claim your|click below|act now|24 hours)\b/i.test(trimmed)) {
    structuralNotes.push('High-pressure urgency or credential/financial solicitation keywords present.');
  }

  let guessedType: DetectedType = 'message';
  if (hint !== 'auto') {
    guessedType = hint;
  } else {
    const cleanedPhoneDigits = trimmed.replace(/[\s().+-]/g, '');
    if (/^\d{7,15}$/.test(cleanedPhoneDigits) && !trimmed.includes(' ') && trimmed.length <= 24) {
      guessedType = 'phone';
    } else if (/^\+?[\d\s().-]{7,22}$/.test(trimmed)) {
      guessedType = 'phone';
    } else if ((urls.length > 0 && trimmed.length < 180 && !trimmed.includes(' ')) || domainOnlyRegex.test(trimmed)) {
      guessedType = 'url';
    } else {
      guessedType = 'message';
    }
  }

  return {
    urls,
    domains: Array.from(new Set(domains)),
    phoneNumbers,
    emails,
    structuralNotes,
    guessedType,
  };
}

function normalizeRiskLevel(score: number, modelLevel?: string): RiskLevel {
  if (modelLevel === 'safe' || modelLevel === 'suspicious' || modelLevel === 'dangerous') {
    if (score >= 65 && modelLevel !== 'dangerous') return 'dangerous';
    if (score < 30 && modelLevel !== 'safe') return 'safe';
    return modelLevel;
  }
  if (score >= 65) return 'dangerous';
  if (score >= 30) return 'suspicious';
  return 'safe';
}

async function callGeminiWithRetry<T>(fn: () => Promise<T>, maxRetries = 2): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err: unknown) {
      lastError = err;
      const msg = err instanceof Error ? err.message : String(err);
      const isTransient = msg.includes('429') || msg.includes('503') || msg.includes('RESOURCE_EXHAUSTED') || msg.includes('UNAVAILABLE');
      if (!isTransient || attempt === maxRetries) {
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, 600 * Math.pow(2, attempt)));
    }
  }
  throw lastError;
}

const app = express();
app.use(express.json({ limit: '1mb' }));

app.post('/api/analyze', async (req: Request, res: Response) => {
  try {
    const body = req.body as { input?: unknown; inputTypeHint?: unknown };
    const rawInput = typeof body?.input === 'string' ? body.input.trim() : '';
    const hintRaw = typeof body?.inputTypeHint === 'string' ? body.inputTypeHint : 'auto';
    const inputTypeHint: InputTypeHint =
      hintRaw === 'url' || hintRaw === 'message' || hintRaw === 'phone' ? hintRaw : 'auto';

    if (!rawInput) {
      res.status(400).json({ error: 'Please paste a link, message, or phone number to analyze.' });
      return;
    }

    if (rawInput.length > 5000) {
      res.status(400).json({ error: 'Input exceeds the 5,000 character analysis limit.' });
      return;
    }

    const hints = extractForensicHints(rawInput, inputTypeHint);

    const offlineRules = [
      {
        label: 'bit.ly',
        pattern: /(?:^|[\s/."'(])bit\.ly(?:[\s/?"'#):]|$)/i,
        signal: 'Shortened Link (bit.ly)',
        detail:
          'Contains a bit.ly shortened URL, which masks the true destination website and is commonly used in phishing campaigns.',
        tip: 'Do not open shortened bit.ly links from unexpected messages unless you can verify the destination first.',
        scoreWeight: 82,
      },
      {
        label: 'tinyurl',
        pattern: /tinyurl(?:\.com)?/i,
        signal: 'Shortened Link (tinyurl)',
        detail:
          'Contains a TinyURL redirect link that hides the real target domain, a frequent tactic for concealing malicious landing pages.',
        tip: 'Avoid clicking TinyURL links from unknown senders; navigate directly to official websites instead.',
        scoreWeight: 82,
      },
      {
        label: 'free money',
        pattern: /free[\s\-_+]*money/i,
        signal: 'Financial Lure ("free money")',
        detail:
          'Contains a "free money" giveaway or payout lure, a classic social-engineering hook used to harvest personal or payment details.',
        tip: 'Treat unsolicited promises of free money, prizes, or instant payouts as scams and never share bank or card details.',
        scoreWeight: 90,
      },
      {
        label: 'verify security account',
        pattern: /verify[\s\-_+]*security[\s\-_+]*account/i,
        signal: 'Account Verification Lure ("verify security account")',
        detail:
          'Contains "verify security account" phrasing designed to create urgency and trick users into entering credentials on a fraudulent page.',
        tip: 'Never verify your account through a pasted link; open your provider’s official app or website directly.',
        scoreWeight: 92,
      },
      {
        label: 'login',
        pattern: /(?:https?:\/\/|www\.|[a-z0-9-]+\.[a-z]{2,})[^\s]*login|(?:\blogin\b)/i,
        signal: 'Suspicious Login Reference ("login")',
        detail:
          'References a login path or sign-in prompt, which is frequently used in credential-harvesting links to impersonate trusted sign-in portals.',
        tip: 'Do not enter your username, password, or one-time code on a login page reached via a link.',
        scoreWeight: 80,
      },
    ];

    const matchedOffline = offlineRules.filter((rule) => rule.pattern.test(rawInput));
    if (matchedOffline.length > 0) {
      const highestWeight = Math.max(...matchedOffline.map((r) => r.scoreWeight));
      const riskScore = Math.min(98, highestWeight + (matchedOffline.length - 1) * 5);
      const matchedLabels = matchedOffline.map((r) => `"${r.label}"`).join(', ');
      res.json({
        detectedType: inputTypeHint === 'auto' ? hints.guessedType : inputTypeHint,
        riskLevel: 'dangerous',
        riskScore,
        verdictHeadline: `Flagged as Dangerous by offline rule check (${matchedLabels}).`,
        category: 'Offline Rule Match — High-Risk Pattern',
        explanation: `Our free offline scanner immediately flagged this submission as Dangerous without calling AI because it contains high-risk indicator(s): ${matchedLabels}. Attackers frequently combine shortened links, credential-login paths, and urgency or payout lures to steal passwords and financial data.`,
        indicators: matchedOffline.map((r) => ({
          signal: r.signal,
          severity: 'high',
          detail: r.detail,
        })),
        safetyTips: Array.from(
          new Set([
            ...matchedOffline.map((r) => r.tip),
            'If you already opened the link or entered credentials, change your password immediately and enable two-factor authentication.',
            'Delete the message and report or block the sender.',
          ])
        ).slice(0, 5),
        extractedArtifacts: {
          urls: hints.urls,
          domains: hints.domains,
          phoneNumbers: hints.phoneNumbers,
          emails: hints.emails,
        },
        analysisSource: 'offline',
      });
      return;
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      res.status(500).json({
        error: 'Gemini API key is not configured. Please verify GEMINI_API_KEY in Settings > Secrets.',
      });
      return;
    }

    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });

    const systemInstruction = [
      'You are an expert cybersecurity threat analyst specializing in phishing, smishing, vishing, social engineering, malicious URLs, brand impersonation, and scam phone numbers.',
      'Analyze the user-submitted artifact (which may be a URL/domain, text/SMS/email message, or phone number) together with the pre-extracted structural forensic signals.',
      'Evaluate risk accurately and objectively without false alarms on well-known legitimate domains (e.g., google.com, github.com, apple.com, official government/bank domains) unless spoofed via lookalikes, typosquatting, or malicious paths.',
      'Keep explanations crisp, factual, and accessible to everyday users while preserving technical accuracy.',
      'Scoring rubric: 0-29 = safe, 30-64 = suspicious, 65-100 = dangerous. Ensure riskLevel strictly matches riskScore.',
      'Provide 2 to 5 specific indicators grounded directly in the input, and 3 to 5 concrete, actionable safetyTips tailored to the exact threat.',
    ].join(' ');

    const userPrompt = [
      `User input type hint: ${inputTypeHint} (structural guess: ${hints.guessedType})`,
      `Pre-extracted URLs: ${hints.urls.length > 0 ? hints.urls.join(', ') : 'none'}`,
      `Pre-extracted domains: ${hints.domains.length > 0 ? hints.domains.join(', ') : 'none'}`,
      `Pre-extracted phone numbers: ${hints.phoneNumbers.length > 0 ? hints.phoneNumbers.join(', ') : 'none'}`,
      `Pre-extracted emails: ${hints.emails.length > 0 ? hints.emails.join(', ') : 'none'}`,
      `Structural forensic notes: ${hints.structuralNotes.length > 0 ? hints.structuralNotes.join(' ') : 'None flagged by deterministic parser.'}`,
      '',
      '--- BEGIN SUBMITTED CONTENT ---',
      rawInput,
      '--- END SUBMITTED CONTENT ---',
    ].join('\n');

    const response = await callGeminiWithRetry(() =>
      ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: userPrompt,
        config: {
          systemInstruction,
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              detectedType: {
                type: Type.STRING,
                enum: ['url', 'message', 'phone'],
                description: 'Classified type of the submitted artifact.',
              },
              riskLevel: {
                type: Type.STRING,
                enum: ['safe', 'suspicious', 'dangerous'],
                description: 'Overall threat tier.',
              },
              riskScore: {
                type: Type.INTEGER,
                description: 'Numeric risk score from 0 (completely safe) to 100 (confirmed dangerous threat).',
              },
              verdictHeadline: {
                type: Type.STRING,
                description: 'Concise 1-sentence summary verdict.',
              },
              category: {
                type: Type.STRING,
                description: 'Short threat or classification category, e.g. Credential Phishing, Delivery Smishing, Vishing / Robocall, Legitimate Website.',
              },
              explanation: {
                type: Type.STRING,
                description: 'Clear 2-4 sentence explanation of why this input is safe, suspicious, or dangerous.',
              },
              indicators: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    signal: { type: Type.STRING, description: 'Short name of the forensic indicator.' },
                    severity: { type: Type.STRING, enum: ['low', 'medium', 'high'] },
                    detail: { type: Type.STRING, description: 'Specific evidence observed in the input.' },
                  },
                  required: ['signal', 'severity', 'detail'],
                },
              },
              safetyTips: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: '3 to 5 concrete, actionable safety recommendations.',
              },
            },
            required: [
              'detectedType',
              'riskLevel',
              'riskScore',
              'verdictHeadline',
              'category',
              'explanation',
              'indicators',
              'safetyTips',
            ],
          },
        },
      })
    );

    const jsonText = (response.text ?? '').trim();
    if (!jsonText) {
      res.status(502).json({ error: 'Received an empty analysis response from the model.' });
      return;
    }

    const parsed = JSON.parse(jsonText) as {
      detectedType?: DetectedType;
      riskLevel?: RiskLevel;
      riskScore?: number;
      verdictHeadline?: string;
      category?: string;
      explanation?: string;
      indicators?: Array<{ signal: string; severity: 'low' | 'medium' | 'high'; detail: string }>;
      safetyTips?: string[];
    };

    const clampedScore = Math.max(0, Math.min(100, Math.round(Number(parsed.riskScore ?? 50))));
    const riskLevel = normalizeRiskLevel(clampedScore, parsed.riskLevel);
    const detectedType: DetectedType =
      parsed.detectedType === 'url' || parsed.detectedType === 'message' || parsed.detectedType === 'phone'
        ? parsed.detectedType
        : hints.guessedType;

    res.json({
      detectedType,
      riskLevel,
      riskScore: clampedScore,
      verdictHeadline: parsed.verdictHeadline || 'Threat evaluation completed.',
      category: parsed.category || 'General Assessment',
      explanation: parsed.explanation || 'Analysis completed based on structural and linguistic threat patterns.',
      indicators: Array.isArray(parsed.indicators) ? parsed.indicators : [],
      safetyTips: Array.isArray(parsed.safetyTips) ? parsed.safetyTips : [],
      extractedArtifacts: {
        urls: hints.urls,
        domains: hints.domains,
        phoneNumbers: hints.phoneNumbers,
        emails: hints.emails,
      },
      analysisSource: 'ai',
    });
  } catch (err: unknown) {
    console.error('Threat analysis error:', err);
    const message = err instanceof Error ? err.message : 'Unexpected server error during threat analysis.';
    if (message.includes('PERMISSION_DENIED') || message.includes('API_KEY_INVALID') || message.includes('403') || message.includes('400')) {
      res.status(502).json({
        error: 'Unable to authenticate with Gemini API. Please check your API key in Settings > Secrets.',
      });
      return;
    }
    if (message.includes('RESOURCE_EXHAUSTED') || message.includes('429')) {
      res.status(429).json({
        error: 'Analysis rate limit reached. Please wait a moment and try again.',
      });
      return;
    }
    res.status(500).json({ error: `Analysis failed: ${message}` });
  }
});

async function startServer() {
  if (!IS_PROD) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Aegis Threat Inspector server running at http://localhost:${PORT}`);
  });
}

startServer();
