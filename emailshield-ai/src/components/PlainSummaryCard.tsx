import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, Skull, MessageCircleQuestion } from 'lucide-react';
import type { ThreatAnalysisResult } from '../types';

interface PlainSummaryCardProps {
  analysis: ThreatAnalysisResult;
}

/** Verdict styling for the plain-English card, keyed by the final classification. */
const META: Record<
  string,
  { border: string; bg: string; accent: string; Icon: React.ElementType; word: string }
> = {
  Legitimate: {
    border: 'border-emerald-500/30',
    bg: 'bg-emerald-500/[0.06]',
    accent: 'text-emerald-300',
    Icon: ShieldCheck,
    word: 'Looks safe',
  },
  Suspicious: {
    border: 'border-amber-500/30',
    bg: 'bg-amber-500/[0.06]',
    accent: 'text-amber-300',
    Icon: AlertTriangle,
    word: 'Be careful',
  },
  Phishing: {
    border: 'border-red-500/30',
    bg: 'bg-red-500/[0.06]',
    accent: 'text-red-300',
    Icon: ShieldAlert,
    word: 'Very likely a scam',
  },
  Fraud: {
    border: 'border-red-500/30',
    bg: 'bg-red-500/[0.06]',
    accent: 'text-red-300',
    Icon: Skull,
    word: 'Very likely a scam',
  },
};

/**
 * "What does this mean?" — the plain-English verdict for a reader with no
 * technical background. Sits at the very top of the Overview tab, above the
 * numeric score. Text comes from `analysis.plainSummary` (Gemini, jargon-free
 * prompt; server synthesises one if the model didn't).
 */
export const PlainSummaryCard: React.FC<PlainSummaryCardProps> = ({ analysis }) => {
  const meta = META[analysis.classification] || META.Suspicious;
  const summary =
    analysis.plainSummary?.trim() ||
    analysis.explanation?.trim() ||
    'We could not generate a plain-English summary for this email.';

  return (
    <div className={`rounded-xl border ${meta.border} ${meta.bg} p-5 sm:p-6 shadow-xl`}>
      <div className="flex items-center gap-2.5 mb-3">
        <MessageCircleQuestion className="w-4 h-4 text-gray-400" />
        <span className="text-[11px] uppercase tracking-widest text-gray-400 font-bold">What does this mean?</span>
      </div>

      <div className="flex items-start gap-4">
        <div className={`shrink-0 mt-0.5 ${meta.accent}`}>
          <meta.Icon className="w-8 h-8" />
        </div>
        <div className="min-w-0">
          <div className={`text-sm font-bold uppercase tracking-wide ${meta.accent} mb-1.5`}>{meta.word}</div>
          <p className="text-[15px] sm:text-base text-gray-100 leading-relaxed">{summary}</p>
        </div>
      </div>
    </div>
  );
};
