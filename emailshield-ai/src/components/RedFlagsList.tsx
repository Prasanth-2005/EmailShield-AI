import React from 'react';
import { AlertCircle, AlertTriangle, ShieldAlert, CheckCircle2, Flag } from 'lucide-react';
import { RedFlag } from '../types';

interface RedFlagsListProps {
  redFlags: RedFlag[];
  /** Section heading. Defaults to the original generic "Red Flags Detected" label. */
  title?: string;
  /** Small right-aligned caption (e.g. which engine produced these flags). */
  subtitleRight?: string;
}

export const RedFlagsList: React.FC<RedFlagsListProps> = ({
  redFlags,
  title = 'Red Flags Detected',
  subtitleRight = 'Security Forensic Audit',
}) => {
  const getSeverityBadge = (severity: RedFlag['severity']) => {
    switch (severity) {
      case 'critical':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/10 border border-red-500/20 text-red-400 uppercase tracking-wider">
            Critical
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/10 border border-red-500/20 text-red-400 uppercase tracking-wider">
            High
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 border border-amber-500/20 text-amber-400 uppercase tracking-wider">
            Medium
          </span>
        );
      case 'low':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 border border-blue-500/20 text-blue-400 uppercase tracking-wider">
            Low
          </span>
        );
      case 'info':
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 uppercase tracking-wider">
            Verified
          </span>
        );
    }
  };

  const getSeverityIcon = (severity: RedFlag['severity']) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />;
      case 'medium':
        return <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />;
      case 'info':
        return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />;
      default:
        return <AlertCircle className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />;
    }
  };

  return (
    <div className="rounded-xl border border-white/10 bg-[#161616] p-5 shadow-xl">
      <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
        <div className="flex items-center space-x-2 text-sm font-semibold text-white">
          <Flag className="w-4 h-4 text-red-400" />
          <span>{title} ({redFlags.length})</span>
        </div>
        <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold font-mono">{subtitleRight}</span>
      </div>

      {redFlags.length === 0 ? (
        <div className="p-6 text-center rounded-xl bg-black/40 border border-white/10">
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
          <p className="text-sm font-semibold text-gray-200">No Malicious Red Flags Detected</p>
          <p className="text-xs text-gray-400 mt-1 max-w-sm mx-auto">
            This message passed cryptographic header checks without coercive urgency, brand spoofing, or deceptive links.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {redFlags.map((flag, idx) => (
            <div
              key={flag.id || idx}
              className={`p-3.5 rounded-lg border transition ${
                flag.severity === 'critical'
                  ? 'bg-red-500/[0.04] border-red-500/20 hover:bg-red-500/[0.08]'
                  : flag.severity === 'high'
                  ? 'bg-red-500/[0.03] border-red-500/20 hover:bg-red-500/[0.06]'
                  : flag.severity === 'medium'
                  ? 'bg-amber-500/[0.03] border-amber-500/20 hover:bg-amber-500/[0.06]'
                  : flag.severity === 'info'
                  ? 'bg-emerald-500/[0.03] border-emerald-500/20 hover:bg-emerald-500/[0.06]'
                  : 'bg-black/40 border border-white/10 hover:bg-black/60'
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start space-x-2.5">
                  {getSeverityIcon(flag.severity)}
                  <div>
                    <div className="flex items-center flex-wrap gap-2">
                      <h4 className="text-sm font-semibold text-gray-200 font-sans">
                        {flag.title}
                      </h4>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-black text-gray-400 border border-white/10">
                        {flag.category}
                      </span>
                    </div>
                    <p className="text-xs text-gray-300 mt-1.5 leading-relaxed font-normal">
                      {flag.description}
                    </p>
                  </div>
                </div>
                <div className="shrink-0">
                  {getSeverityBadge(flag.severity)}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
