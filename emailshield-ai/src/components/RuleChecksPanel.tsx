import React from 'react';
import { Binary, CheckCircle2, ShieldCheck } from 'lucide-react';
import { TriggeredRule } from '../types';

interface RuleChecksPanelProps {
  ruleScore: number;
  rules: TriggeredRule[];
  /** Fraction this engine contributes to the final score (0.5, or 0.35 with ML). */
  weight?: number;
}

/**
 * Deterministic, rule-based detections. Rendered as its own labelled section so
 * it is always clear which findings came from fixed rules vs. the AI model.
 */
export const RuleChecksPanel: React.FC<RuleChecksPanelProps> = ({ ruleScore, rules, weight = 0.5 }) => {
  const sorted = [...rules].sort((a, b) => b.points - a.points);
  const weightPct = Math.round(weight * 100);

  return (
    <div className="rounded-xl border border-white/10 bg-[#161616] p-5 shadow-xl">
      <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
        <div className="flex items-center space-x-2 text-sm font-semibold text-white">
          <Binary className="w-4 h-4 text-sky-400" />
          <span>Rule-Based Detection ({rules.length})</span>
        </div>
        <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold font-mono">
          Deterministic Engine
        </span>
      </div>

      {/* Rule sub-score */}
      <div className="mb-4 flex items-center justify-between rounded-lg bg-black/40 border border-white/10 px-4 py-3">
        <div>
          <div className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">Rule Sub-Score</div>
          <div className="text-[11px] text-gray-400 mt-0.5 font-mono">
            Contributes {weightPct}% of the final fraud score
          </div>
        </div>
        <div className="text-2xl font-bold font-mono text-sky-400">
          {ruleScore}
          <span className="text-xs text-gray-500 font-normal">/100</span>
        </div>
      </div>

      {sorted.length === 0 ? (
        <div className="p-6 text-center rounded-xl bg-black/40 border border-white/10">
          <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
          <p className="text-sm font-semibold text-gray-200">No Deterministic Rules Triggered</p>
          <p className="text-xs text-gray-400 mt-1 max-w-sm mx-auto">
            Authentication passed, sender domains are aligned and not newly registered, no lookalike brand, no
            deceptive links, and routing looks normal.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {sorted.map((rule) => (
            <div
              key={rule.id}
              className="p-3.5 rounded-lg border border-sky-500/20 bg-sky-500/[0.04] hover:bg-sky-500/[0.08] transition"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start space-x-2.5">
                  <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="flex items-center flex-wrap gap-2">
                      <h4 className="text-sm font-semibold text-gray-200">{rule.rule}</h4>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-black text-gray-400 border border-white/10">
                        {rule.category}
                      </span>
                    </div>
                    <p className="text-xs text-gray-300 mt-1.5 leading-relaxed">{rule.description}</p>
                  </div>
                </div>
                <span className="shrink-0 inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-500/10 border border-sky-500/20 text-sky-300 uppercase tracking-wider">
                  +{rule.points}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
