import React, { useEffect, useState } from 'react';
import {
  ArrowLeft,
  RefreshCw,
  AlertCircle,
  Sparkles,
  Mail,
  Link2,
  ShieldQuestion,
} from 'lucide-react';
import {
  fetchMessage,
  runAdvancedScan,
  MailboxAuthError,
  type MessageDetail,
  type AdvancedScanResult,
  type MailProvider,
} from '../services/mailboxService';
import { RiskBadge } from './RiskBadge';
import { RuleChecksPanel } from './RuleChecksPanel';
import { Dashboard } from './Dashboard';
import type { ParsedEmail } from '../types';

interface MessageDetailViewProps {
  messageId: string;
  provider: MailProvider;
  onBack: () => void;
  onAuthLost: (message: string) => void;
}

export const MessageDetailView: React.FC<MessageDetailViewProps> = ({ messageId, provider, onBack, onAuthLost }) => {
  const [detail, setDetail] = useState<MessageDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [scan, setScan] = useState<AdvancedScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setDetail(null);
    setScan(null);
    setScanError(null);
    fetchMessage(provider, messageId)
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch((err) => {
        if (cancelled) return;
        if (err instanceof MailboxAuthError) onAuthLost(err.message);
        else setError(err?.message || 'Could not load this message.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [messageId, provider, onAuthLost]);

  const handleAdvancedScan = async () => {
    setScanning(true);
    setScanError(null);
    try {
      const result = await runAdvancedScan(provider, messageId);
      setScan(result);
    } catch (err: any) {
      if (err instanceof MailboxAuthError) onAuthLost(err.message);
      else setScanError(err?.message || 'Advanced scan failed.');
    } finally {
      setScanning(false);
    }
  };

  const providerLabel = provider === 'imap' ? 'IMAP' : 'Gmail';

  // --- Advanced scan complete -> show the full forensic dashboard ----------
  if (scan) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <button
            onClick={() => setScan(null)}
            className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 text-gray-200 transition cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to message</span>
          </button>
          <button
            onClick={onBack}
            className="text-xs font-medium text-gray-400 hover:text-white transition cursor-pointer"
          >
            Back to inbox
          </button>
        </div>
        <Dashboard
          email={scan.parsedEmail as ParsedEmail}
          analysis={scan}
          fileName={`${providerLabel} · ${detail?.parsedEmail.subject || messageId}`}
          onAnalysisUpdate={(a) => setScan({ ...(a as AdvancedScanResult), parsedEmail: scan.parsedEmail })}
        />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <button
        onClick={onBack}
        className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 text-gray-200 transition cursor-pointer"
      >
        <ArrowLeft className="w-3.5 h-3.5" />
        <span>Back to inbox</span>
      </button>

      {loading && (
        <div className="rounded-xl border border-white/10 bg-[#161616] p-10 text-center">
          <RefreshCw className="w-6 h-6 animate-spin text-blue-400 mx-auto" />
          <p className="text-sm text-gray-400 mt-3">Fetching message from {providerLabel}…</p>
        </div>
      )}

      {error && !loading && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-200 text-sm flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-white">Could not load this message</h4>
            <p className="text-xs text-red-300 mt-1">{error}</p>
          </div>
        </div>
      )}

      {detail && !loading && (
        <>
          {/* Envelope */}
          <div className="rounded-xl border border-white/10 bg-[#161616] p-5 shadow-xl">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <h2 className="text-lg font-semibold text-white break-words">{detail.parsedEmail.subject}</h2>
                <div className="mt-2 text-sm text-gray-300 flex items-center gap-2">
                  <Mail className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                  <span className="font-medium">{detail.parsedEmail.from.displayName}</span>
                  <span className="text-blue-400 font-mono text-xs truncate">&lt;{detail.parsedEmail.from.address}&gt;</span>
                </div>
                <div className="mt-1 text-xs text-gray-500 font-mono">{detail.parsedEmail.date || 'Date not specified'}</div>
              </div>
              <RiskBadge band={detail.riskBand} score={detail.ruleScore} className="shrink-0" />
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-2 text-[11px] font-mono text-gray-400">
              <span className="px-2 py-0.5 rounded bg-black border border-white/10">
                {detail.parsedEmail.receivedHopCount} Received hop{detail.parsedEmail.receivedHopCount === 1 ? '' : 's'}
              </span>
              <span className="px-2 py-0.5 rounded bg-black border border-white/10">
                SPF {detail.parsedEmail.authResults.spf?.status || '—'}
              </span>
              <span className="px-2 py-0.5 rounded bg-black border border-white/10">
                DKIM {detail.parsedEmail.authResults.dkim?.status || '—'}
              </span>
              <span className="px-2 py-0.5 rounded bg-black border border-white/10">
                DMARC {detail.parsedEmail.authResults.dmarc?.status || '—'}
              </span>
            </div>
          </div>

          {/* Rule-based verdict (no AI) */}
          <RuleChecksPanel ruleScore={detail.ruleScore} rules={detail.triggeredRules} />

          {/* Body */}
          <div className="rounded-xl border border-white/10 bg-[#161616] p-5 shadow-xl">
            <div className="flex items-center gap-2 text-sm font-semibold text-white border-b border-white/10 pb-3 mb-3">
              <Mail className="w-4 h-4 text-blue-500" />
              <span>Message Body</span>
            </div>
            <pre className="text-xs text-gray-300 whitespace-pre-wrap break-words font-sans max-h-96 overflow-y-auto leading-relaxed">
              {detail.parsedEmail.bodyText || '(no plain-text body)'}
            </pre>

            {detail.parsedEmail.extractedLinks.length > 0 && (
              <div className="mt-4 pt-3 border-t border-white/10">
                <div className="text-[10px] uppercase tracking-widest text-gray-500 font-bold mb-2">
                  Links ({detail.parsedEmail.extractedLinks.length})
                </div>
                <ul className="space-y-1.5">
                  {detail.parsedEmail.extractedLinks.slice(0, 12).map((l, i) => (
                    <li key={i} className="text-[11px] font-mono flex items-start gap-1.5 min-w-0">
                      <Link2 className={`w-3 h-3 shrink-0 mt-0.5 ${l.isMismatched ? 'text-red-400' : 'text-gray-500'}`} />
                      <span className="min-w-0 break-all">
                        <span className={l.isMismatched ? 'text-red-300' : 'text-gray-300'}>{l.text || l.href}</span>
                        {l.text && l.text !== l.href && (
                          <span className="text-gray-500"> → {l.href}</span>
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Advanced scan */}
          <div className="rounded-xl border border-blue-500/25 bg-blue-500/[0.05] p-5 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center gap-3">
              <div className="flex items-start gap-3 flex-1">
                <ShieldQuestion className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-sm font-semibold text-white">Run full AI forensic analysis</h3>
                  <p className="text-xs text-gray-300 mt-1 leading-relaxed">
                    So far this is <span className="text-blue-300 font-medium">rule-based only</span> — free and instant.
                    Advanced Scan adds header parsing, the ML model and Gemini AI verdicts, threat intelligence
                    and the origin trace with IP geolocation. This is the only step that uses a Gemini API call
                    (a few seconds).
                  </p>
                  {scanError && <p className="text-xs text-red-300 mt-2">{scanError}</p>}
                </div>
              </div>
              <button
                onClick={handleAdvancedScan}
                disabled={scanning}
                className="shrink-0 flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-60 disabled:cursor-wait text-white text-xs font-semibold border border-blue-400/30 transition cursor-pointer shadow"
              >
                {scanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Analyzing…</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    <span>Advanced Scan</span>
                  </>
                )}
              </button>
            </div>

            {scanning && (
              <div className="mt-4 text-[11px] font-mono text-blue-300/80 bg-black/40 border border-white/10 rounded-lg px-3 py-2">
                Parsing RFC 5322 headers · evaluating SPF/DKIM/DMARC · resolving Received-hop geolocation ·
                querying Gemini for phishing, urgency &amp; impersonation…
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};
