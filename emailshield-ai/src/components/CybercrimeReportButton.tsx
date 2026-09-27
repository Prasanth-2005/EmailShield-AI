import React, { useEffect, useRef, useState } from 'react';
import { Landmark, ExternalLink, ClipboardCheck, AlertCircle, X } from 'lucide-react';
import type { ParsedEmail, ThreatAnalysisResult } from '../types';

interface CybercrimeReportButtonProps {
  email: ParsedEmail;
  analysis: ThreatAnalysisResult;
}

const PORTAL_URL = 'https://cybercrime.gov.in';

/** Plain-text incident summary the user pastes into the complaint form. */
function buildIncidentSummary(email: ParsedEmail, analysis: ThreatAnalysisResult): string {
  const L: string[] = [];
  L.push('EMAILSHIELD AI — SUSPECTED FRAUDULENT EMAIL');
  L.push('');
  L.push(`Verdict: ${String(analysis.classification).toUpperCase()}  (risk score ${analysis.fraudScore} / 100)`);

  if (analysis.plainSummary?.trim()) {
    L.push('');
    L.push('In plain terms:');
    L.push(analysis.plainSummary.trim());
  }

  L.push('');
  L.push(`Sender name:    ${email.from?.displayName || '(not shown)'}`);
  L.push(`Sender address: ${email.from?.address || '(not shown)'}`);
  L.push(`Subject:        ${email.subject || '(none)'}`);
  L.push(`Date:           ${email.date || '(not shown)'}`);
  if (email.replyTo) L.push(`Reply-To:       ${email.replyTo}`);
  if (email.returnPath) L.push(`Return-Path:    ${email.returnPath}`);

  const signs: string[] = [];
  for (const r of analysis.triggeredRules || []) signs.push(r.rule);
  for (const f of analysis.redFlags || []) signs.push(`${f.title}${f.description ? ` — ${f.description}` : ''}`);
  if (signs.length) {
    L.push('');
    L.push('Warning signs detected:');
    for (const s of signs.slice(0, 12)) L.push(`  - ${s}`);
  }

  const og = analysis.originTrace?.originGeo;
  if (og && og.status === 'success') {
    const place = [og.city, og.region, og.country].filter(Boolean).join(', ');
    L.push('');
    L.push(
      `Probable sending location: ${place || 'unknown'}` +
        (analysis.originTrace?.originIp ? `  (origin IP ${analysis.originTrace.originIp})` : '') +
        (og.isp ? `  — network: ${og.isp}` : ''),
    );
  }

  const fromDomain = (analysis.domainIntel?.entries || []).find((e) => e.role === 'from' && e.status === 'ok');
  if (fromDomain?.registeredAt) {
    L.push('');
    L.push(
      `Sender web address "${fromDomain.domain}" was registered on ${new Date(fromDomain.registeredAt)
        .toISOString()
        .slice(0, 10)}` +
        (typeof fromDomain.ageDays === 'number' ? ` (${fromDomain.ageDays} days ago)` : '') +
        (fromDomain.registrar ? ` via ${fromDomain.registrar}` : ''),
    );
  }

  const vtFlagged = (analysis.deepScan?.items || []).filter(
    (i) => (i.malicious || 0) + (i.suspicious || 0) >= 1,
  );
  if (vtFlagged.length) {
    L.push('');
    L.push('Flagged by security vendors (VirusTotal):');
    for (const i of vtFlagged) {
      L.push(`  - ${i.kind === 'url' ? i.url : i.filename}: ${i.malicious}/${i.total} engines flagged it`);
    }
  }

  L.push('');
  L.push(`Analysed by EmailShield AI on ${new Date().toISOString().slice(0, 10)}.`);
  L.push(`National Cyber Crime Reporting Portal: ${PORTAL_URL}`);
  return L.join('\n');
}

type Toast = { kind: 'ok' | 'err'; msg: string; details?: string };

/**
 * Overview-tab call to action shown only for emails scored above the "safe"
 * threshold. Copies a ready-to-paste incident summary to the clipboard, shows a
 * toast, and opens the National Cyber Crime Reporting Portal in a new tab. It
 * never submits anything — the portal has no public submission API.
 */
export const CybercrimeReportButton: React.FC<CybercrimeReportButtonProps> = ({ email, analysis }) => {
  const [toast, setToast] = useState<Toast | null>(null);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const showToast = (t: Toast) => {
    setToast(t);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setToast(null), t.details ? 20000 : 8000);
  };

  const handleReport = () => {
    const text = buildIncidentSummary(email, analysis);

    // 1. Kick off the clipboard copy — initiated synchronously inside the click
    //    gesture so the browser allows it.
    const copyPromise: Promise<void> | undefined = navigator.clipboard?.writeText?.(text);

    // 2. Show the notice right away, while this tab still has focus.
    showToast({ kind: 'ok', msg: 'Incident details copied — paste them into the complaint form.' });
    if (copyPromise) {
      copyPromise.catch(() => {
        showToast({
          kind: 'err',
          msg: `Couldn't copy automatically. Copy the details below and paste them into the form at ${PORTAL_URL}:`,
          details: text,
        });
      });
    } else {
      showToast({
        kind: 'err',
        msg: `Automatic copy isn't available here. Copy the details below and paste them into the form at ${PORTAL_URL}:`,
        details: text,
      });
    }

    // 3. Open the portal — still within the same gesture tick.
    window.open(PORTAL_URL, '_blank', 'noopener,noreferrer');
  };

  return (
    <div className="rounded-xl border border-red-500/25 bg-red-500/[0.05] p-4 sm:p-5 shadow-xl">
      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="flex items-start gap-3 flex-1 min-w-0">
          <Landmark className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-white">Report this to the authorities</h3>
            <p className="text-xs text-gray-300 mt-1 leading-relaxed">
              If this email targeted you or your organisation, file a complaint on India&apos;s National Cyber Crime
              Reporting Portal. A ready-made summary (sender, subject, date, verdict, warning signs) is copied to your
              clipboard so you can paste it straight into the form. Nothing is submitted for you.
            </p>
          </div>
        </div>
        <button
          onClick={handleReport}
          className="shrink-0 flex items-center gap-2 px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold border border-red-400/30 transition cursor-pointer shadow"
        >
          <ExternalLink className="w-4 h-4" />
          <span>Report to Cybercrime.gov.in</span>
        </button>
      </div>

      {toast && (
        <div className="fixed left-1/2 -translate-x-1/2 bottom-6 z-50 w-[calc(100%-2rem)] max-w-md">
          <div
            className={`rounded-lg border px-4 py-3 shadow-2xl text-sm ${
              toast.kind === 'ok'
                ? 'bg-emerald-600 border-emerald-400/40 text-white'
                : 'bg-[#1b1b1b] border-white/15 text-gray-100'
            }`}
          >
            <div className="flex items-start gap-2">
              {toast.kind === 'ok' ? (
                <ClipboardCheck className="w-4 h-4 shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
              )}
              <div className="min-w-0 flex-1">
                <p className="leading-snug">{toast.msg}</p>
                {toast.details && (
                  <textarea
                    readOnly
                    value={toast.details}
                    onFocus={(e) => e.currentTarget.select()}
                    className="mt-2 w-full h-40 text-[11px] font-mono bg-black/60 border border-white/10 rounded p-2 text-gray-300 resize-none"
                  />
                )}
              </div>
              <button
                onClick={() => setToast(null)}
                className="shrink-0 text-white/70 hover:text-white cursor-pointer"
                aria-label="Dismiss"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
