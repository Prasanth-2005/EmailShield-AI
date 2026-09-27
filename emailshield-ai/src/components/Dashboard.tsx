import React, { useMemo, useState } from 'react';
import { ParsedEmail, ThreatAnalysisResult } from '../types';
import { FraudScoreCard } from './FraudScoreCard';
import { EmailMetaPanel } from './EmailMetaPanel';
import { RedFlagsList } from './RedFlagsList';
import { RuleChecksPanel } from './RuleChecksPanel';
import { MlModelPanel } from './MlModelPanel';
import { OriginTracePanel } from './OriginTracePanel';
import { DomainIntelPanel } from './DomainIntelPanel';
import { HeaderChain } from './HeaderChain';
import { EmailPreview } from './EmailPreview';
import { EscalateBanner } from './EscalateBanner';
import { AttachmentAnalysisPanel } from './AttachmentAnalysisPanel';
import { DeepScanPanel } from './DeepScanPanel';
import { PlainSummaryCard } from './PlainSummaryCard';
import { CybercrimeReportButton } from './CybercrimeReportButton';
import {
  ShieldCheck,
  Clock,
  FileText,
  Loader2,
  MailWarning,
  Check,
  X,
  LayoutDashboard,
  Binary,
  Route,
  Radar,
  Paperclip,
} from 'lucide-react';

/** One engine's up/down state in the status bar. */
const EngineChip: React.FC<{ label: string; state: 'ok' | 'warn' | 'off'; title?: string }> = ({
  label,
  state,
  title,
}) => {
  const cls =
    state === 'ok'
      ? 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20'
      : state === 'warn'
      ? 'text-amber-300 bg-amber-400/10 border-amber-400/20'
      : 'text-gray-500 bg-white/[0.03] border-white/10';
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[11px] font-medium ${cls}`}
    >
      {state === 'off' ? <X className="w-3 h-3" /> : <Check className="w-3 h-3" />}
      <span>{label}</span>
    </span>
  );
};

type TabId = 'overview' | 'technical' | 'origin' | 'intel' | 'attachments';

interface DashboardProps {
  email: ParsedEmail;
  analysis: ThreatAnalysisResult;
  fileName?: string;
  /** Upload handler, wired for the "escalate from Gmail triage to full forensics" flow. */
  onAnalyzeEml?: (rawEml: string, fileName?: string) => void;
  /** Replace the current analysis (used when the deep scan re-scores it). */
  onAnalysisUpdate?: (analysis: ThreatAnalysisResult) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ email, analysis, fileName, onAnalyzeEml, onAnalysisUpdate }) => {
  const isLiveGemini = /^gemini/i.test(analysis.engine || '');
  const mlOnline = !!analysis.mlModel && analysis.mlScore != null;
  const bodyOnly = analysis.analysisScope === 'body-and-sender';
  const fallbackLabel =
    analysis.fallbackReason === 'gemini-quota-exceeded'
      ? 'heuristic engine (Gemini quota exceeded)'
      : analysis.fallbackReason === 'gemini-model-unavailable'
      ? 'heuristic engine (Gemini model unavailable)'
      : analysis.fallbackReason === 'no-api-key'
      ? 'heuristic engine (no Gemini API key)'
      : analysis.fallbackReason === 'gemini-error'
      ? 'heuristic engine (Gemini API error)'
      : 'heuristic engine (no live Gemini)';

  const attachments = useMemo(
    () => analysis.attachments || email.attachments || [],
    [analysis.attachments, email.attachments],
  );
  const hasAttachments = attachments.length > 0;
  const isReportable = analysis.classification !== 'Legitimate';

  const tabs = useMemo(
    () =>
      (
        [
          { id: 'overview', label: 'Overview', Icon: LayoutDashboard },
          { id: 'technical', label: 'Technical Details', Icon: Binary },
          { id: 'origin', label: 'Origin Trace', Icon: Route },
          { id: 'intel', label: 'Threat Intelligence', Icon: Radar },
          ...(hasAttachments ? [{ id: 'attachments' as const, label: 'Attachments', Icon: Paperclip }] : []),
        ] as { id: TabId; label: string; Icon: React.ElementType }[]
      ),
    [hasAttachments],
  );

  const [tab, setTab] = useState<TabId>('overview');
  // If attachments disappear on a re-analysis while that tab is open, fall back.
  const activeTab = tabs.some((t) => t.id === tab) ? tab : 'overview';

  const [reportState, setReportState] = useState<{ status: 'idle' | 'working' | 'done' | 'error'; caseId?: string }>({
    status: 'idle',
  });

  const handleGenerateReport = async () => {
    setReportState({ status: 'working' });
    try {
      // Lazy-load the PDF toolkit (jsPDF) only when a report is actually requested.
      const { generateForensicReport } = await import('../utils/forensicReport');
      const { caseId } = generateForensicReport(email, analysis, { sourceFileName: fileName });
      setReportState({ status: 'done', caseId });
    } catch (err) {
      console.error('Forensic report generation failed:', err);
      setReportState({ status: 'error' });
    }
  };

  return (
    <div className="space-y-6">
      {/* Forensic Intelligence Status Bar — applies to every tab, stays above them */}
      <div className="p-3.5 px-5 rounded-xl border border-white/10 bg-[#161616] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono shadow-xl">
        <div className="flex items-center space-x-2 text-gray-300">
          <ShieldCheck className="w-4 h-4 text-blue-500 shrink-0" />
          <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">Target File:</span>
          <span className="text-blue-400 truncate max-w-xs">{fileName || 'raw-email-stream.eml'}</span>
          {bodyOnly && (
            <span className="flex items-center gap-1 text-sky-300 bg-sky-400/10 px-2 py-0.5 rounded-full border border-sky-400/20 text-[10px] font-medium uppercase tracking-wider">
              <MailWarning className="w-3 h-3" />
              <span>Body &amp; sender only</span>
            </span>
          )}
        </div>

        <div className="flex items-center flex-wrap gap-3 text-gray-400 text-xs">
          <div className="flex items-center gap-1.5">
            <span className="text-gray-500">Engines:</span>
            <EngineChip label="Rules" state="ok" />
            <EngineChip
              label="ML"
              state={mlOnline ? 'ok' : 'off'}
              title={mlOnline ? 'bert-finetuned-phishing' : 'Python ML service offline — start ml_service/ on port 8000'}
            />
            <EngineChip
              label={isLiveGemini ? `AI · ${analysis.engine}` : 'AI · fallback'}
              state={isLiveGemini ? 'ok' : 'warn'}
              title={isLiveGemini ? undefined : fallbackLabel}
            />
          </div>

          <div className="flex items-center space-x-1.5">
            <Clock className="w-3.5 h-3.5 text-gray-500" />
            <span className="text-gray-500">Analyzed:</span>
            <span>{new Date(analysis.analyzedAt).toLocaleTimeString()}</span>
          </div>

          <button
            onClick={handleGenerateReport}
            disabled={reportState.status === 'working'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-60 disabled:cursor-wait text-white text-[11px] font-semibold border border-blue-400/30 transition cursor-pointer shadow"
            title="Export this analysis as a printable PDF report"
          >
            {reportState.status === 'working' ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Generating…</span>
              </>
            ) : (
              <>
                <FileText className="w-3.5 h-3.5" />
                <span>Generate Forensic Report</span>
              </>
            )}
          </button>
        </div>
      </div>

      {(reportState.status === 'done' || reportState.status === 'error') && (
        <div
          className={`-mt-3 px-5 py-2 rounded-lg border text-[11px] font-mono ${
            reportState.status === 'done'
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300'
              : 'bg-red-500/10 border-red-500/20 text-red-300'
          }`}
        >
          {reportState.status === 'done'
            ? `Report downloaded — case ${reportState.caseId}. Check your browser downloads.`
            : 'Report generation failed — see the browser console for details.'}
        </div>
      )}

      {/* Escalation prompt for Gmail Quick Scan triage results */}
      {bodyOnly && onAnalyzeEml && <EscalateBanner onAnalyzeEml={onAnalyzeEml} />}

      {/* Tab bar */}
      <div className="rounded-xl border border-white/10 bg-[#161616] shadow-xl overflow-x-auto">
        <div className="flex items-stretch min-w-max">
          {tabs.map(({ id, label, Icon }) => {
            const active = id === activeTab;
            return (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={`flex items-center gap-2 px-4 sm:px-5 py-3 text-xs font-semibold border-b-2 transition cursor-pointer whitespace-nowrap ${
                  active
                    ? 'border-blue-500 text-white bg-white/[0.04]'
                    : 'border-transparent text-gray-400 hover:text-gray-200 hover:bg-white/[0.02]'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${active ? 'text-blue-400' : 'text-gray-500'}`} />
                <span>{label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Every tab's content stays mounted (toggled with `hidden`) so in-flight
          state — a running deep scan, the world-map render, scroll position —
          survives switching tabs. */}

      {/* --- OVERVIEW --------------------------------------------------------- */}
      <div hidden={activeTab !== 'overview'} className="space-y-6">
        <PlainSummaryCard analysis={analysis} />
        {isReportable && <CybercrimeReportButton email={email} analysis={analysis} />}
        <FraudScoreCard analysis={analysis} bodyOnly={bodyOnly} />
      </div>

      {/* --- TECHNICAL DETAILS --------------------------------------------- */}
      <div hidden={activeTab !== 'technical'} className="space-y-6">
        <EmailMetaPanel email={email} bodyOnly={bodyOnly} />
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <RuleChecksPanel
            ruleScore={analysis.ruleScore}
            rules={analysis.triggeredRules || []}
            weight={analysis.scoreWeights?.rule ?? 0.5}
          />
          <MlModelPanel model={analysis.mlModel} mlScore={analysis.mlScore} weight={analysis.scoreWeights?.ml} />
        </div>
        <RedFlagsList
          redFlags={analysis.redFlags}
          title={isLiveGemini ? 'AI-Detected Flags (Gemini)' : 'AI-Detected Flags (Heuristic Fallback)'}
          subtitleRight={isLiveGemini ? `${analysis.engine} judgment` : 'local heuristic engine'}
        />
        <EmailPreview email={email} suspiciousPhrases={analysis.suspiciousPhrases} />
        <HeaderChain hops={email.receivedHops} bodyOnly={bodyOnly} />
      </div>

      {/* --- ORIGIN TRACE ------------------------------------------------- */}
      <div hidden={activeTab !== 'origin'} className="space-y-6">
        <OriginTracePanel trace={analysis.originTrace} bodyOnly={bodyOnly} />
      </div>

      {/* --- THREAT INTELLIGENCE ---------------------------------------- */}
      <div hidden={activeTab !== 'intel'} className="space-y-6">
        <DomainIntelPanel report={analysis.domainIntel} />
        <DeepScanPanel email={email} analysis={analysis} onAnalysisUpdate={(a) => onAnalysisUpdate?.(a)} />
      </div>

      {/* --- ATTACHMENTS (tab only shown when present) --------------------- */}
      {hasAttachments && (
        <div hidden={activeTab !== 'attachments'} className="space-y-6">
          <AttachmentAnalysisPanel attachments={attachments} />
        </div>
      )}
    </div>
  );
};
