export type InputTypeHint = 'auto' | 'url' | 'message' | 'phone';

export type DetectedType = 'url' | 'message' | 'phone';

export type RiskLevel = 'safe' | 'suspicious' | 'dangerous';

export type IndicatorSeverity = 'low' | 'medium' | 'high';

export interface ThreatIndicator {
  signal: string;
  severity: IndicatorSeverity;
  detail: string;
}

export interface ExtractedArtifacts {
  urls: string[];
  domains: string[];
  phoneNumbers: string[];
  emails: string[];
}

export interface ThreatAnalysisResult {
  detectedType: DetectedType;
  riskLevel: RiskLevel;
  riskScore: number;
  verdictHeadline: string;
  category: string;
  explanation: string;
  indicators: ThreatIndicator[];
  safetyTips: string[];
  extractedArtifacts: ExtractedArtifacts;
  analysisSource?: 'offline' | 'ai';
}

export interface ScanHistoryItem {
  id: string;
  input: string;
  inputTypeHint: InputTypeHint;
  analyzedAt: string;
  result: ThreatAnalysisResult;
}
