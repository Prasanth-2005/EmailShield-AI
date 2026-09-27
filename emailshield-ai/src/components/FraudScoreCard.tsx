import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Skull, Info, Zap, UserX, KeyRound, DollarSign, Globe, Network } from 'lucide-react';
import { ThreatAnalysisResult } from '../types';

interface FraudScoreCardProps {
  analysis: ThreatAnalysisResult;
  /** True when the analysis came from Gmail Quick Scan (no raw headers available). */
  bodyOnly?: boolean;
}

export const FraudScoreCard: React.FC<FraudScoreCardProps> = ({ analysis, bodyOnly }) => {
  const { classification, fraudScore, confidence, explanation, indicators } = analysis;
  const ruleScore = analysis.ruleScore ?? 0;
  const geminiScore = analysis.geminiScore ?? 0;
  const isLiveGemini = /^gemini/i.test(analysis.engine || '');
  const baseScore = typeof analysis.baseFraudScore === 'number' ? analysis.baseFraudScore : fraudScore;
  const deepScanPoints = analysis.deepScan?.addedPoints ?? 0;
  const domainAgeRule = (analysis.triggeredRules || []).find((r) => r.category === 'Domain Intelligence');

  // Three-engine blend when the ML service answered; 50/50 rule+AI otherwise.
  const mlOnline = analysis.mlModel != null && analysis.mlScore != null;
  const mlScore = analysis.mlScore ?? 0;
  const w = analysis.scoreWeights ?? { rule: mlOnline ? 0.35 : 0.5, ml: mlOnline ? 0.3 : null, gemini: mlOnline ? 0.35 : 0.5 };
  const wPct = (x: number) => `× ${x.toFixed(2)}`;

  // Color mapping based on score
  let scoreColor = 'text-emerald-400';
  let badgeBg = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
  let meterBg = 'from-emerald-500 to-teal-400';
  let ringColor = 'border-emerald-500/30 border-t-emerald-500';
  let Icon = ShieldCheck;
  let statusText = 'Legitimate';
  let riskLevel = 'Low Risk';

  if (fraudScore >= 80 || classification === 'Fraud' || classification === 'Phishing') {
    scoreColor = 'text-red-500';
    badgeBg = 'bg-red-500/10 text-red-400 border-red-500/20';
    meterBg = 'from-red-600 to-rose-500';
    ringColor = 'border-red-500/30 border-t-red-500';
    Icon = classification === 'Fraud' ? Skull : ShieldAlert;
    statusText = classification;
    riskLevel = 'Critical Threat';
  } else if (fraudScore >= 45 || classification === 'Suspicious') {
    scoreColor = 'text-amber-400';
    badgeBg = 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    meterBg = 'from-amber-500 to-yellow-400';
    ringColor = 'border-amber-500/30 border-t-amber-500';
    Icon = AlertTriangle;
    statusText = 'Suspicious';
    riskLevel = 'Elevated Risk';
  }

  return (
    <div className="rounded-xl border border-white/10 bg-[#161616] p-5 sm:p-6 shadow-xl">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        {/* Left: Large Fraud Score Meter */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center p-4 rounded-xl bg-black/40 border border-white/10">
          <div className="flex items-center justify-between w-full mb-3 px-2">
            <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">
              Fraud Confidence
            </span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${badgeBg} uppercase font-bold flex items-center gap-1`}>
              <Icon className="w-3 h-3" />
              <span>{statusText}</span>
            </span>
          </div>

          {/* Circular/Hero Metric Display */}
          <div className={`relative flex flex-col items-center justify-center w-36 h-36 rounded-full border-4 ${ringColor} bg-black/70 shadow-2xl my-2`}>
            <div className="text-4xl font-bold font-mono tracking-tight flex items-baseline">
              <span className={scoreColor}>{fraudScore}</span>
              <span className="text-xs text-gray-500 font-normal">/100</span>
            </div>
            <span className="text-[10px] font-bold text-gray-400 mt-1 uppercase tracking-widest">
              {riskLevel}
            </span>
            {/* Confidence indicator below */}
            <div className="absolute -bottom-2.5 px-2.5 py-0.5 rounded-full bg-[#161616] border border-white/10 text-[10px] font-mono text-gray-300">
              {confidence}% Confidence
            </div>
          </div>

          {/* Progress bar visualizer */}
          <div className="w-full mt-4 space-y-1.5 px-2">
            <div className="h-2 w-full rounded-full bg-white/[0.05] overflow-hidden flex">
              <div
                className={`h-full rounded-full bg-gradient-to-r ${meterBg} transition-all duration-700`}
                style={{ width: `${Math.max(fraudScore, 4)}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] font-mono text-gray-500 uppercase tracking-wider">
              <span>0 (Safe)</span>
              <span>50 (Borderline)</span>
              <span>100 (Active Threat)</span>
            </div>
          </div>

          {/* Hybrid score composition: rules + ML + AI (or rules + AI when ML is offline) */}
          <div className="w-full mt-4 pt-3 border-t border-white/10 px-2">
            <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold block mb-2">
              Score Composition
            </span>
            <div className={`grid ${mlOnline ? 'grid-cols-3' : 'grid-cols-2'} gap-2 text-xs font-mono`}>
              <div className="p-2 rounded-lg bg-black/40 border border-white/10">
                <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Rule Engine</div>
                <div className="text-sky-400 font-semibold">
                  {ruleScore}<span className="text-gray-600 text-[10px]"> {wPct(w.rule)}</span>
                </div>
                {domainAgeRule && (
                  <div className="text-[9px] text-amber-300/90 mt-0.5 leading-tight normal-case font-sans">
                    incl. +{domainAgeRule.points} domain age
                  </div>
                )}
              </div>
              {mlOnline && (
                <div className="p-2 rounded-lg bg-black/40 border border-white/10">
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">ML Model</div>
                  <div className="text-fuchsia-400 font-semibold">
                    {mlScore}<span className="text-gray-600 text-[10px]"> {wPct(w.ml ?? 0.3)}</span>
                  </div>
                  <div className="text-[9px] text-gray-500 mt-0.5 leading-tight normal-case font-sans">
                    {analysis.mlModel?.label} · {analysis.mlModel?.confidence}%
                  </div>
                </div>
              )}
              <div className="p-2 rounded-lg bg-black/40 border border-white/10">
                <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">
                  {isLiveGemini ? 'Gemini AI' : 'Heuristic AI'}
                </div>
                <div className={`font-semibold ${isLiveGemini ? 'text-emerald-400' : 'text-amber-300'}`}>
                  {geminiScore}<span className="text-gray-600 text-[10px]"> {wPct(w.gemini)}</span>
                </div>
              </div>
            </div>
            {!mlOnline && (
              <div className="mt-2 text-[10px] text-gray-500 text-center normal-case font-sans">
                ML layer skipped — Python model service offline. Score used rules + AI only.
              </div>
            )}
            {deepScanPoints > 0 && (
              <div className="mt-2 p-2 rounded-lg bg-violet-500/[0.08] border border-violet-500/25 text-xs font-mono flex items-center justify-between">
                <span className="text-[10px] uppercase tracking-wider text-violet-300 font-bold">Deep Scan (Threat Intel)</span>
                <span className="text-violet-300 font-semibold">+{deepScanPoints}</span>
              </div>
            )}
            <div className="mt-2 text-[10px] font-mono text-gray-500 text-center">
              ({ruleScore} {wPct(w.rule)}){mlOnline && <> + ({mlScore} {wPct(w.ml ?? 0.3)})</>} + ({geminiScore} {wPct(w.gemini)})
              {deepScanPoints > 0 && <> = {baseScore} <span className="text-violet-300">+ {deepScanPoints}</span></>} ={' '}
              <span className={scoreColor}>{fraudScore}</span> / 100
            </div>
            {deepScanPoints > 0 && (
              <div className="mt-1.5 text-[10px] text-violet-300/90 text-center">
                Score updated after Threat Intelligence scan
              </div>
            )}
          </div>
        </div>

        {/* Right: Plain-English Explanation & Threat Vectors */}
        <div className="lg:col-span-7 space-y-4">
          {/* Plain English Verdict Explanation */}
          <div className="p-4 rounded-xl bg-black/40 border border-white/10">
            <div className="flex items-center space-x-2 text-[10px] font-bold uppercase tracking-widest text-blue-400 mb-2">
              <Info className="w-3.5 h-3.5" />
              <span>Forensic Verdict</span>
            </div>
            <p className="text-sm text-gray-300 leading-relaxed font-normal">
              {explanation}
            </p>
          </div>

          {/* Forensic Indicator Matrix */}
          <div>
            <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold block mb-2.5">
              Threat Vector Diagnostic Matrix
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
              {/* Urgency */}
              <div className="p-2.5 rounded-lg bg-black/40 border border-white/10 flex items-center space-x-2">
                <Zap className={`w-4 h-4 shrink-0 ${indicators?.urgencyScore > 50 ? 'text-red-400' : 'text-gray-500'}`} />
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Urgency Cues</div>
                  <div className={`font-mono font-semibold text-xs ${indicators?.urgencyScore > 50 ? 'text-red-400' : 'text-gray-300'}`}>
                    {indicators?.urgencyScore > 50 ? 'High Coercion' : 'Normal / None'}
                  </div>
                </div>
              </div>

              {/* Impersonation */}
              <div className="p-2.5 rounded-lg bg-black/40 border border-white/10 flex items-center space-x-2">
                <UserX className={`w-4 h-4 shrink-0 ${indicators?.impersonationScore > 50 ? 'text-red-400' : 'text-gray-500'}`} />
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Brand Impersonation</div>
                  <div className={`font-mono font-semibold text-xs ${indicators?.impersonationScore > 50 ? 'text-red-400' : 'text-gray-300'}`}>
                    {indicators?.impersonationScore > 50 ? 'Detected' : 'Verified Sender'}
                  </div>
                </div>
              </div>

              {/* Credential Harvesting */}
              <div className="p-2.5 rounded-lg bg-black/40 border border-white/10 flex items-center space-x-2">
                <KeyRound className={`w-4 h-4 shrink-0 ${indicators?.credentialHarvestingRisk ? 'text-red-400' : 'text-gray-500'}`} />
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Credential Harvest</div>
                  <div className={`font-mono font-semibold text-xs ${indicators?.credentialHarvestingRisk ? 'text-red-400' : 'text-emerald-400'}`}>
                    {indicators?.credentialHarvestingRisk ? 'Targeted Request' : 'No Harvest Detected'}
                  </div>
                </div>
              </div>

              {/* Financial Fraud */}
              <div className="p-2.5 rounded-lg bg-black/40 border border-white/10 flex items-center space-x-2">
                <DollarSign className={`w-4 h-4 shrink-0 ${indicators?.financialFraudRisk ? 'text-red-400' : 'text-gray-500'}`} />
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Financial Wire</div>
                  <div className={`font-mono font-semibold text-xs ${indicators?.financialFraudRisk ? 'text-red-400' : 'text-gray-300'}`}>
                    {indicators?.financialFraudRisk ? 'Active BEC Wire Risk' : 'None Detected'}
                  </div>
                </div>
              </div>

              {/* Domain Spoofing */}
              <div className="p-2.5 rounded-lg bg-black/40 border border-white/10 flex items-center space-x-2">
                <Globe className={`w-4 h-4 shrink-0 ${indicators?.domainSpoofingRisk ? 'text-amber-400' : 'text-gray-500'}`} />
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Domain Spoofing</div>
                  <div className={`font-mono font-semibold text-xs ${indicators?.domainSpoofingRisk ? 'text-amber-300' : 'text-emerald-400'}`}>
                    {indicators?.domainSpoofingRisk ? 'Address Mismatch' : 'Domain Aligned'}
                  </div>
                </div>
              </div>

              {/* Header Anomaly */}
              <div className="p-2.5 rounded-lg bg-black/40 border border-white/10 flex items-center space-x-2">
                <Network className={`w-4 h-4 shrink-0 ${bodyOnly ? 'text-gray-600' : indicators?.headerAnomalyRisk ? 'text-amber-400' : 'text-gray-500'}`} />
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Auth / Routing</div>
                  <div
                    className={`font-mono font-semibold text-xs ${
                      bodyOnly ? 'text-gray-500 italic' : indicators?.headerAnomalyRisk ? 'text-amber-300' : 'text-emerald-400'
                    }`}
                  >
                    {bodyOnly ? 'Not assessed (Gmail)' : indicators?.headerAnomalyRisk ? 'Auth Anomalies' : 'Valid Signatures'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
