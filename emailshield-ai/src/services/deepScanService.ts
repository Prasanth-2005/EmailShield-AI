import type { DeepScanItemResult, ThreatAnalysisResult } from '../types';

export type ScanItem =
  | { kind: 'url'; url: string; displayText?: string; mismatched?: boolean; appearsCount?: number }
  | { kind: 'file'; sha256: string; filename: string; size: number; mimeType: string };

export interface ScanItemResponse {
  result: DeepScanItemResult;
  analysis: ThreatAnalysisResult;
  caseId: string;
}

/**
 * Runs one VirusTotal lookup for one item against a stored case, and returns the
 * item's result plus the freshly re-scored analysis. Callers scan selected items
 * one at a time (with a short client-side delay) for live per-item progress.
 */
export async function scanDeepScanItem(caseId: string, item: ScanItem): Promise<ScanItemResponse> {
  const res = await fetch(`/api/deep-scan/${encodeURIComponent(caseId)}/scan-item`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ item }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(body?.error || `Deep scan request failed (HTTP ${res.status})`);
  }
  return body as ScanItemResponse;
}

/** Re-poll an in-flight VirusTotal URL analysis (no resubmit). */
export async function pollDeepScanItem(
  caseId: string,
  args: { analysisId?: string; url: string; displayText?: string; mismatched?: boolean; appearsCount?: number },
): Promise<ScanItemResponse> {
  const res = await fetch(`/api/deep-scan/${encodeURIComponent(caseId)}/poll-item`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(args),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(body?.error || `Deep scan poll failed (HTTP ${res.status})`);
  }
  return body as ScanItemResponse;
}
