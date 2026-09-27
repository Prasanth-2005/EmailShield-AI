import React from 'react';
import { BrainCircuit, ShieldAlert, ShieldCheck, PlugZap } from 'lucide-react';
import type { MlModelResult } from '../types';

interface MlModelPanelProps {
  model: MlModelResult | null | undefined;
  /** Fraud-scale sub-score (0-100) that actually went into the blend. */
  mlScore: number | null | undefined;
  /** Weight the ML engine carried in the final score (e.g. 0.30), or null. */
  weight: number | null | undefined;
}

/**
 * Third detection engine — a local pretrained BERT phishing classifier. Rendered
 * as its own labelled section next to the rule engine and the AI model. When the
 * Python service is offline it shows a clear "engine unavailable" state rather
 * than disappearing, so the three-engine design stays visible.
 */
export const MlModelPanel: React.FC<MlModelPanelProps> = ({ model, mlScore, weight }) => {
  const offline = !model || mlScore == null;

  return (
    <div className="rounded-xl border border-white/10 bg-[#161616] p-5 shadow-xl">
      <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
        <div className="flex items-center space-x-2 text-sm font-semibold text-white">
          <BrainCircuit className={`w-4 h-4 ${offline ? 'text-gray-500' : 'text-fuchsia-400'}`} />
          <span>ML Model Detection</span>
        </div>
        <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold font-mono">
          Pretrained Classifier
        </span>
      </div>

      {offline ? (
        <div className="p-5 text-center rounded-xl bg-black/40 border border-white/10">
          <PlugZap className="w-8 h-8 text-gray-500 mx-auto mb-2" />
          <p className="text-sm font-semibold text-gray-300">ML engine offline</p>
          <p className="text-xs text-gray-400 mt-1 max-w-sm mx-auto leading-relaxed">
            This analysis used the rule engine and the AI model only. Start the Python service
            (<span className="font-mono text-gray-300">ml_service/</span> on port 8000) to add the
            pretrained BERT phishing classifier as a third independent signal.
          </p>
        </div>
      ) : (
        <>
          {/* ML sub-score */}
          <div className="mb-4 flex items-center justify-between rounded-lg bg-black/40 border border-white/10 px-4 py-3">
            <div>
              <div className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">ML Sub-Score</div>
              <div className="text-[11px] text-gray-400 mt-0.5 font-mono">
                Contributes {weight != null ? `${Math.round(weight * 100)}%` : '30%'} of the final fraud score
              </div>
            </div>
            <div className="text-2xl font-bold font-mono text-fuchsia-400">
              {mlScore}
              <span className="text-xs text-gray-500 font-normal">/100</span>
            </div>
          </div>

          {/* Verdict */}
          <div
            className={`p-4 rounded-lg border flex items-start gap-3 ${
              model!.label === 'phishing'
                ? 'border-red-500/30 bg-red-500/[0.06]'
                : 'border-emerald-500/25 bg-emerald-500/[0.05]'
            }`}
          >
            {model!.label === 'phishing' ? (
              <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            ) : (
              <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            )}
            <div>
              <div className="flex items-center gap-2">
                <span
                  className={`text-sm font-bold uppercase tracking-wide ${
                    model!.label === 'phishing' ? 'text-red-300' : 'text-emerald-300'
                  }`}
                >
                  {model!.label}
                </span>
                <span className="text-[11px] font-mono text-gray-400">
                  {model!.confidence}% confidence
                </span>
              </div>
              <p className="text-xs text-gray-300 mt-1.5 leading-relaxed">
                The <span className="font-mono text-gray-200">bert-finetuned-phishing</span> model, trained on
                thousands of real phishing messages, classifies this email's text as{' '}
                <span className={model!.label === 'phishing' ? 'text-red-300' : 'text-emerald-300'}>
                  {model!.label}
                </span>
                . This is an independent signal — it never sees the headers, routing or threat-intel data.
              </p>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
