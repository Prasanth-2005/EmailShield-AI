import React, { useMemo, useState } from 'react';
import {
  Radar,
  Link2,
  Paperclip,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  RotateCw,
  Fingerprint,
} from 'lucide-react';
import type { DeepScanItemResult, ParsedEmail, ThreatAnalysisResult } from '../types';
import { scanDeepScanItem, pollDeepScanItem, type ScanItem } from '../services/deepScanService';

interface DeepScanPanelProps {
  email: ParsedEmail;
  analysis: ThreatAnalysisResult;
  onAnalysisUpdate: (analysis: ThreatAnalysisResult) => void;
}

interface UiItem {
  key: string;
  scan: ScanItem;
  kind: 'url' | 'file';
  label: string;
  sublabel: string;
  mismatched: boolean;
  count: number; // how many raw links share this destination
  rank: number; // sort weight: lower first
}

interface RowState {
  phase: 'idle' | 'scanning' | 'polling' | 'pending' | 'done' | 'error';
  attempt?: number;
}

const DELAY_BETWEEN_MS = 2000; // between initial scan submissions
const POLL_ATTEMPTS = 6;
const POLL_GAP_MS = 5000; // ~30 s total per pending URL
const DISPLAY_CAP = 20;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Normalized destination: scheme + host + path, query string + fragment dropped. */
function normalizeUrl(href: string): string {
  try {
    const u = new URL(href);
    const path = u.pathname.replace(/\/+$/, '') || '/';
    return `${u.protocol}//${u.host.toLowerCase()}${path}`;
  } catch {
    return href.split('#')[0].split('?')[0];
  }
}

function ratioTone(r: DeepScanItemResult): { cls: string; text: string; Icon: React.ElementType } {
  if (r.status === 'unavailable') return { cls: 'text-gray-400 bg-white/[0.04] border-white/10', text: r.message || 'Scan unavailable', Icon: AlertTriangle };
  if (r.status === 'pending') return { cls: 'text-sky-300 bg-sky-500/10 border-sky-500/25', text: r.message || 'Scan pending', Icon: Loader2 };
  if (r.kind === 'file' && r.status === 'unknown') return { cls: 'text-gray-400 bg-white/[0.03] border-white/10', text: r.message || 'No prior threat record', Icon: Fingerprint };
  const hits = (r.malicious || 0) + (r.suspicious || 0);
  const label = `${r.malicious}/${r.total} engines flagged${r.suspicious ? ` (+${r.suspicious} suspicious)` : ''}`;
  if (hits >= 3) return { cls: 'text-red-400 bg-red-500/10 border-red-500/30', text: label, Icon: ShieldAlert };
  if (hits >= 1) return { cls: 'text-amber-300 bg-amber-500/10 border-amber-500/30', text: label, Icon: AlertTriangle };
  return { cls: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/25', text: `Clean — ${r.malicious}/${r.total} flagged`, Icon: ShieldCheck };
}

const ShaChip: React.FC<{ sha: string }> = ({ sha }) => {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => navigator.clipboard?.writeText(sha).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); })}
      className="inline-flex items-center gap-1 text-[10px] font-mono text-gray-500 hover:text-gray-300 transition cursor-pointer"
      title={sha}
    >
      <span>SHA-256 {sha.slice(0, 14)}…</span>
      {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
    </button>
  );
};

export const DeepScanPanel: React.FC<DeepScanPanelProps> = ({ email, analysis, onAnalysisUpdate }) => {
  const caseId = analysis.caseId || '';

  // ---- Build the deduplicated, sorted scannable list --------------------
  const items: UiItem[] = useMemo(() => {
    const groups = new Map<
      string,
      { normalized: string; count: number; mismatched: boolean; label?: string; hasLabel: boolean }
    >();

    for (const l of email.extractedLinks || []) {
      const href = (l.href || '').trim();
      if (!href || /^(mailto:|tel:|#|javascript:)/i.test(href)) continue;
      const normalized = normalizeUrl(href);
      const text = (l.text || '').trim();
      const isLabel = !!text && text !== href && text !== normalized && !/^https?:\/\//i.test(text);
      const g = groups.get(normalized) || { normalized, count: 0, mismatched: false, hasLabel: false };
      g.count += 1;
      g.mismatched = g.mismatched || Boolean(l.isMismatched);
      if (isLabel && !g.label) g.label = text;
      g.hasLabel = g.hasLabel || isLabel;
      groups.set(normalized, g);
    }

    const urlItems: UiItem[] = [...groups.values()].map((g) => ({
      key: `u:${g.normalized}`,
      scan: {
        kind: 'url',
        url: g.normalized,
        displayText: g.label,
        mismatched: g.mismatched,
        appearsCount: g.count,
      },
      kind: 'url',
      label: g.normalized,
      sublabel: g.label ? `shown as "${g.label}"` : g.hasLabel ? 'labelled link' : 'plain link',
      mismatched: g.mismatched,
      count: g.count,
      rank: g.mismatched ? 0 : g.hasLabel ? 2 : 3,
    }));

    const fileItems: UiItem[] = (analysis.attachments || [])
      .filter((a) => a.sha256)
      .map((a) => ({
        key: `f:${a.sha256}`,
        scan: { kind: 'file', sha256: a.sha256, filename: a.filename, size: a.size, mimeType: a.mimeType },
        kind: 'file',
        label: a.filename,
        sublabel: `${a.mimeType} · ${a.size} bytes`,
        mismatched: false,
        count: 1,
        rank: 1, // attachments always near the top
      }));

    return [...urlItems, ...fileItems].sort(
      (a, b) => a.rank - b.rank || b.count - a.count || a.label.localeCompare(b.label),
    );
  }, [email.extractedLinks, analysis.attachments]);

  const priorResults = analysis.deepScan?.items || [];
  const resultByKey = new Map<string, DeepScanItemResult>();
  for (const r of priorResults) resultByKey.set(r.kind === 'url' ? `u:${r.url}` : `f:${r.sha256}`, r);

  const [open, setOpen] = useState(priorResults.length > 0);
  const [showAll, setShowAll] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [scanning, setScanning] = useState(false);
  const [rowState, setRowState] = useState<Record<string, RowState>>({});
  const [error, setError] = useState<string | null>(null);
  const [recheckKey, setRecheckKey] = useState<string | null>(null);

  const setRow = (key: string, s: RowState) => setRowState((prev) => ({ ...prev, [key]: s }));

  const toggle = (key: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  const allSelected = items.length > 0 && items.every((it) => selected.has(it.key));
  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(items.map((it) => it.key)));

  const visible = showAll ? items : items.slice(0, DISPLAY_CAP);
  const urlCount = items.filter((i) => i.kind === 'url').length;
  const fileCount = items.filter((i) => i.kind === 'file').length;

  // ---- Scan: submit all first, then poll the pending ones --------------
  const runScan = async () => {
    const queue = items.filter((it) => selected.has(it.key));
    if (queue.length === 0) return;
    setScanning(true);
    setError(null);

    const pending: { key: string; scan: Extract<ScanItem, { kind: 'url' }>; analysisId?: string }[] = [];

    for (let i = 0; i < queue.length; i++) {
      const it = queue[i];
      setRow(it.key, { phase: 'scanning' });
      try {
        const resp = await scanDeepScanItem(caseId, it.scan);
        onAnalysisUpdate(resp.analysis);
        if (resp.result.kind === 'url' && resp.result.status === 'pending') {
          pending.push({ key: it.key, scan: it.scan as any, analysisId: resp.result.analysisId });
          setRow(it.key, { phase: 'pending', attempt: 0 });
        } else {
          setRow(it.key, { phase: 'done' });
        }
      } catch (err: any) {
        setError(err?.message || 'Deep scan failed for one item.');
        setRow(it.key, { phase: 'error' });
      }
      if (i < queue.length - 1) await sleep(DELAY_BETWEEN_MS);
    }

    // Poll pass — pending URLs only. Other items already completed above.
    for (const p of pending) {
      let resolved = false;
      for (let attempt = 1; attempt <= POLL_ATTEMPTS && !resolved; attempt++) {
        setRow(p.key, { phase: 'polling', attempt });
        await sleep(POLL_GAP_MS);
        try {
          const resp = await pollDeepScanItem(caseId, {
            analysisId: p.analysisId,
            url: p.scan.url,
            displayText: p.scan.displayText,
            mismatched: p.scan.mismatched,
            appearsCount: p.scan.appearsCount,
          });
          onAnalysisUpdate(resp.analysis);
          if (resp.result.kind === 'url' && resp.result.status === 'pending') {
            p.analysisId = resp.result.analysisId || p.analysisId;
          } else {
            resolved = true;
            setRow(p.key, { phase: 'done' });
          }
        } catch {
          /* keep polling */
        }
      }
      if (!resolved) setRow(p.key, { phase: 'pending' });
    }

    setScanning(false);
  };

  // ---- "Check again" on a still-pending result ------------------------
  const recheck = async (r: DeepScanItemResult) => {
    if (r.kind !== 'url') return;
    const key = `u:${r.url}`;
    setRecheckKey(key);
    try {
      const resp = await pollDeepScanItem(caseId, {
        analysisId: r.analysisId,
        url: r.url,
        displayText: r.displayText,
        mismatched: r.mismatched,
        appearsCount: r.appearsCount,
      });
      onAnalysisUpdate(resp.analysis);
    } catch (err: any) {
      setError(err?.message || 'Re-check failed.');
    } finally {
      setRecheckKey(null);
    }
  };

  // ---- No scannable items --------------------------------------------
  if (items.length === 0) {
    return (
      <div className="rounded-xl border border-white/10 bg-[#161616] p-5 shadow-xl">
        <button
          disabled
          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-white/[0.04] border border-white/10 text-gray-500 text-sm font-semibold cursor-not-allowed"
        >
          <Radar className="w-4 h-4" />
          <span>No scannable items in this email</span>
        </button>
      </div>
    );
  }

  const addedPoints = analysis.deepScan?.addedPoints || 0;

  const rowStatusLabel = (key: string): string | null => {
    const s = rowState[key];
    if (!s || s.phase === 'idle') {
      const r = resultByKey.get(key);
      if (!r) return null;
      return r.status === 'done' ? `${r.malicious}/${r.total}` : r.status === 'unknown' ? 'no record' : r.status;
    }
    if (s.phase === 'scanning') return 'submitting…';
    if (s.phase === 'polling') return `analysing… (attempt ${s.attempt}/${POLL_ATTEMPTS})`;
    if (s.phase === 'pending') return 'pending';
    if (s.phase === 'error') return 'error';
    if (s.phase === 'done') {
      const r = resultByKey.get(key);
      return r && r.status === 'done' ? `${r.malicious}/${r.total}` : 'done';
    }
    return null;
  };

  return (
    <div className="rounded-xl border border-violet-500/25 bg-violet-500/[0.05] p-5 shadow-xl">
      <button onClick={() => setOpen((o) => !o)} className="w-full flex items-center justify-between gap-3 text-left cursor-pointer">
        <div className="flex items-center gap-2.5">
          <Radar className="w-5 h-5 text-violet-300" />
          <div>
            <div className="text-sm font-semibold text-white">Deep Scan with Threat Intelligence</div>
            <div className="text-[11px] text-gray-400">
              {urlCount} unique URL{urlCount === 1 ? '' : 's'} · {fileCount} attachment{fileCount === 1 ? '' : 's'} ·
              VirusTotal (on demand)
            </div>
          </div>
        </div>
        {open ? <ChevronDown className="w-4 h-4 text-gray-400" /> : <ChevronRight className="w-4 h-4 text-gray-400" />}
      </button>

      {open && (
        <div className="mt-4 space-y-4">
          <div className="rounded-lg border border-white/10 bg-black/30 overflow-hidden">
            <label className="flex items-center gap-2 px-3 py-2 border-b border-white/10 text-[11px] font-semibold text-gray-300 cursor-pointer">
              <input type="checkbox" checked={allSelected} onChange={toggleAll} disabled={scanning} className="accent-violet-500" />
              <span>Select all ({items.length})</span>
              <span className="text-gray-500 font-normal">— mismatched / labelled links are listed first</span>
            </label>

            <div className="max-h-72 overflow-y-auto divide-y divide-white/[0.06]">
              {visible.map((it) => {
                const r = resultByKey.get(it.key);
                const s = rowState[it.key];
                const busy = s && (s.phase === 'scanning' || s.phase === 'polling');
                return (
                  <label key={it.key} className="flex items-start gap-2.5 px-3 py-2.5 hover:bg-white/[0.03] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selected.has(it.key)}
                      onChange={() => toggle(it.key)}
                      disabled={scanning}
                      className="mt-0.5 accent-violet-500"
                    />
                    {it.kind === 'url' ? (
                      <Link2 className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${it.mismatched ? 'text-red-400' : 'text-gray-500'}`} />
                    ) : (
                      <Paperclip className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-400" />
                    )}
                    <div className="min-w-0 flex-1">
                      <div className={`text-xs font-mono break-all ${it.mismatched ? 'text-red-300' : 'text-gray-200'}`}>{it.label}</div>
                      <div className="text-[10px] text-gray-500">
                        {it.sublabel}
                        {it.count > 1 && <span className="text-gray-400"> · appears {it.count}×</span>}
                        {it.mismatched && <span className="text-red-400"> · display text ≠ destination</span>}
                      </div>
                    </div>
                    {busy ? (
                      <span className="flex items-center gap-1 text-[10px] font-mono text-violet-300 shrink-0 mt-0.5">
                        <Loader2 className="w-3 h-3 animate-spin" />
                        {rowStatusLabel(it.key)}
                      </span>
                    ) : (
                      (rowStatusLabel(it.key) || r) && (
                        <span className="text-[10px] font-mono text-gray-400 shrink-0 mt-0.5">{rowStatusLabel(it.key)}</span>
                      )
                    )}
                  </label>
                );
              })}
            </div>

            {items.length > DISPLAY_CAP && (
              <button
                onClick={() => setShowAll((v) => !v)}
                className="w-full px-3 py-2 border-t border-white/10 text-[11px] font-medium text-violet-300 hover:bg-white/[0.03] transition cursor-pointer"
              >
                {showAll ? 'Show fewer' : `Show all ${items.length} destinations`}
              </button>
            )}
          </div>

          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="text-[11px] text-gray-500">
              Free tier is rate-limited (~4/min); items are scanned one at a time, and a URL VirusTotal has
              never seen is polled for ~30 s.
            </div>
            <button
              onClick={runScan}
              disabled={scanning || selected.size === 0}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-semibold border border-violet-400/30 transition cursor-pointer shadow"
            >
              {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />}
              <span>{scanning ? 'Scanning…' : `Scan Selected (${selected.size})`}</span>
            </button>
          </div>

          {error && <div className="text-[11px] text-red-300 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">{error}</div>}

          {priorResults.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">Threat Intelligence Results</div>
                {addedPoints > 0 && (
                  <span className="text-[10px] font-mono font-bold text-red-300 bg-red-500/10 border border-red-500/30 rounded px-1.5 py-0.5">
                    +{addedPoints} pts · score updated after Threat Intelligence scan
                  </span>
                )}
              </div>
              <div className="space-y-2">
                {priorResults.map((r, i) => {
                  const tone = ratioTone(r);
                  const key = r.kind === 'url' ? `u:${r.url}` : `f:${r.sha256}`;
                  const rechecking = recheckKey === key;
                  return (
                    <div key={i} className={`rounded-lg border px-3 py-2.5 ${tone.cls}`}>
                      <div className="flex items-start justify-between gap-3 flex-wrap">
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5 text-xs font-mono break-all">
                            {r.kind === 'url' ? <Link2 className="w-3 h-3 shrink-0" /> : <Paperclip className="w-3 h-3 shrink-0" />}
                            <span>{r.kind === 'url' ? r.url : r.filename}</span>
                          </div>
                          {r.kind === 'url' && (r.appearsCount || 0) > 1 && (
                            <div className="text-[10px] text-gray-400 mt-0.5">appears {r.appearsCount}× in this email</div>
                          )}
                          {r.kind === 'url' && r.mismatched && (
                            <div className="text-[10px] text-red-300 mt-0.5">Displayed text differs from this destination.</div>
                          )}
                          {r.kind === 'file' && <div className="mt-1"><ShaChip sha={r.sha256} /></div>}
                          {r.kind === 'file' && r.status === 'unknown' && (
                            <div className="text-[10px] text-gray-500 mt-1 leading-snug max-w-md">
                              Attachments are checked by SHA-256 hash only — files are never uploaded to
                              third parties. Unique or personal documents will not have a prior record.
                            </div>
                          )}
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold">
                            <tone.Icon className={`w-3.5 h-3.5 ${r.status === 'pending' ? 'animate-spin' : ''}`} />
                            {tone.text}
                          </span>
                          {r.kind === 'url' && r.status === 'pending' && (
                            <button
                              onClick={() => recheck(r)}
                              disabled={rechecking || scanning}
                              className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded border border-sky-500/40 bg-sky-500/10 text-sky-200 hover:bg-sky-500/20 transition cursor-pointer disabled:opacity-50"
                            >
                              {rechecking ? <Loader2 className="w-3 h-3 animate-spin" /> : <RotateCw className="w-3 h-3" />}
                              Check again
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
