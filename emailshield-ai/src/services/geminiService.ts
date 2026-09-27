import { ParsedEmail, ThreatAnalysisResult } from '../types';

/**
 * Sends parsed email telemetry to the EmailShield AI backend for hybrid
 * (deterministic rules + Gemini) threat detection and linguistic forensic
 * analysis. The model actually used is reported back in `engine`.
 */
export async function analyzeEmailWithGemini(parsedEmail: ParsedEmail): Promise<ThreatAnalysisResult> {
  const response = await fetch('/api/analyze-email', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ parsedEmail }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || `Threat analysis request failed with status ${response.status}`);
  }

  const result: ThreatAnalysisResult = await response.json();
  return result;
}
