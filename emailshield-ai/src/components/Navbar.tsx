import React from 'react';
import { ShieldCheck, RefreshCw, Terminal, Activity } from 'lucide-react';

interface NavbarProps {
  hasAnalysis: boolean;
  onReset: () => void;
  isAnalyzing: boolean;
  /** Engine that produced the current analysis, from the server response. */
  engine?: string;
}

export const Navbar: React.FC<NavbarProps> = ({ hasAnalysis, onReset, isAnalyzing, engine }) => {
  const isLiveModel = !!engine && /^gemini/i.test(engine);
  const engineLabel = !engine
    ? 'Google Gemini'
    : isLiveModel
    ? engine
    : 'heuristic fallback';
  return (
    <header className="border-b border-white/10 bg-[#0a0a0a]/90 backdrop-blur sticky top-0 z-40 px-4 sm:px-6 lg:px-8 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Brand identity */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center font-bold text-white shadow-[0_0_15px_rgba(37,99,235,0.4)] shrink-0">
            <ShieldCheck className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-semibold tracking-tight text-white flex items-center gap-1.5">
                EmailShield <span className="text-blue-500 font-mono text-sm">AI</span>
              </h1>
            </div>
            <p className="text-[11px] text-gray-500 font-mono">
              Email Threat Detection & Forensic Intelligence
            </p>
          </div>
        </div>

        {/* Status Indicators & Action */}
        <div className="flex items-center gap-3 text-xs font-medium">
          <div className="hidden md:flex items-center gap-2 text-emerald-400 bg-emerald-400/10 px-3 py-1 rounded-full border border-emerald-400/20">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>Database: Live</span>
          </div>

          <div
            className={`hidden sm:flex items-center gap-2 px-3 py-1 rounded-full border ${
              hasAnalysis && !isLiveModel
                ? 'text-amber-300 bg-amber-400/10 border-amber-400/20'
                : 'text-blue-400 bg-blue-400/10 border-blue-400/20'
            }`}
          >
            <Terminal className="w-3 h-3" />
            <span className="font-mono">Engine: {engineLabel}</span>
          </div>

          {hasAnalysis && (
            <button
              id="btn-new-analysis"
              onClick={onReset}
              disabled={isAnalyzing}
              className="flex items-center space-x-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 text-gray-200 hover:text-white transition-colors disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
              <span>New Analysis</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};

