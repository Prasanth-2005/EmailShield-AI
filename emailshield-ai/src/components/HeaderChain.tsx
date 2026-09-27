import React, { useState } from 'react';
import { Network, Server, ArrowDown, Lock, ShieldAlert, ChevronDown, ChevronUp, Copy, Check } from 'lucide-react';
import { ReceivedHop } from '../types';

interface HeaderChainProps {
  hops: ReceivedHop[];
  /** True when the analysis came from Gmail Quick Scan (no raw headers available). */
  bodyOnly?: boolean;
}

export const HeaderChain: React.FC<HeaderChainProps> = ({ hops, bodyOnly }) => {
  const [expandedHop, setExpandedHop] = useState<number | null>(null);
  const [copiedHop, setCopiedHop] = useState<number | null>(null);

  const toggleHop = (hopNumber: number) => {
    setExpandedHop(expandedHop === hopNumber ? null : hopNumber);
  };

  const copyHopRaw = (hop: ReceivedHop) => {
    navigator.clipboard.writeText(hop.rawHop);
    setCopiedHop(hop.hopNumber);
    setTimeout(() => setCopiedHop(null), 2000);
  };

  return (
    <div className="rounded-xl border border-white/10 bg-[#161616] p-5 shadow-xl">
      <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
        <div className="flex items-center space-x-2 text-sm font-semibold text-white">
          <Network className="w-4 h-4 text-blue-500" />
          <span>Received Header Routing Chain ({hops.length} Hops)</span>
        </div>
        <div className="flex items-center space-x-2 text-[10px] uppercase tracking-widest text-gray-500 font-bold font-mono">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
          <span>Chronological Origin &rarr; Destination</span>
        </div>
      </div>

      {bodyOnly ? (
        <div className="p-6 text-center rounded-lg bg-sky-500/[0.04] border border-sky-500/20">
          <p className="text-xs font-semibold text-gray-200">Not available — this analysis came from Gmail</p>
          <p className="text-[11px] text-gray-400 mt-1 max-w-md mx-auto font-sans">
            Gmail does not expose <span className="font-mono">Received:</span> headers to page scripts.
            Upload the original <span className="font-mono text-sky-300">.eml</span> file to reconstruct the
            hop-by-hop relay path.
          </p>
        </div>
      ) : hops.length === 0 ? (
        <div className="p-6 text-center text-xs text-gray-500 font-mono bg-black/40 rounded-lg border border-white/10">
          No "Received:" routing hops found in email headers.
        </div>
      ) : (
        <div className="relative space-y-3">
          {hops.map((hop, index) => {
            const isOrigin = index === 0;
            const isDestination = index === hops.length - 1;
            const isExpanded = expandedHop === hop.hopNumber;

            // Highlight suspicious or foreign relay hostnames / IPs
            const isSuspiciousHost =
              hop.fromServer.includes('.ru') ||
              hop.fromServer.includes('.xyz') ||
              hop.fromServer.includes('bulk-mailer') ||
              hop.fromServer.includes('botnet');

            return (
              <div key={hop.hopNumber} className="relative">
                {/* Visual connector line between hops */}
                {index < hops.length - 1 && (
                  <div className="absolute left-6 top-11 bottom-0 w-0.5 bg-gradient-to-b from-white/10 to-transparent -mb-3 z-0 pointer-events-none" />
                )}

                <div
                  className={`relative z-10 rounded-xl border p-4 transition ${
                    isSuspiciousHost
                      ? 'bg-red-500/[0.04] border-red-500/30'
                      : isOrigin
                      ? 'bg-black/50 border-blue-500/30 shadow-md shadow-blue-950/20'
                      : isDestination
                      ? 'bg-black/50 border-emerald-500/30'
                      : 'bg-black/40 border-white/10'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    {/* Hop Index & Icon */}
                    <div className="flex items-start space-x-3">
                      <div
                        className={`w-8 h-8 rounded-lg flex items-center justify-center font-mono text-xs font-bold shrink-0 mt-0.5 border ${
                          isSuspiciousHost
                            ? 'bg-red-500/10 border-red-500/20 text-red-400'
                            : isOrigin
                            ? 'bg-blue-500/10 border-blue-500/20 text-blue-400'
                            : isDestination
                            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                            : 'bg-white/[0.05] border-white/10 text-gray-300'
                        }`}
                      >
                        #{hop.hopNumber}
                      </div>

                      <div>
                        {/* Hop Tag */}
                        <div className="flex items-center flex-wrap gap-2 mb-1">
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold tracking-wider ${
                              isOrigin
                                ? 'bg-blue-500/10 border-blue-500/20 text-blue-400'
                                : isDestination
                                ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                                : 'bg-white/[0.05] border-white/10 text-gray-400'
                            }`}
                          >
                            {isOrigin ? 'Originating Hop' : isDestination ? 'Final MX Ingress' : `Relay Hop ${hop.hopNumber}`}
                          </span>

                          {hop.ipAddress && (
                            <span className="text-[10px] font-mono text-blue-400 bg-black px-2 py-0.5 rounded border border-white/10">
                              IP: {hop.ipAddress}
                            </span>
                          )}

                          {hop.tls && (
                            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20 flex items-center gap-1">
                              <Lock className="w-2.5 h-2.5" />
                              <span>{hop.tls}</span>
                            </span>
                          )}

                          {isSuspiciousHost && (
                            <span className="text-[10px] font-mono text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20 flex items-center gap-1 font-bold">
                              <ShieldAlert className="w-2.5 h-2.5" />
                              <span>Untrusted Relay / VPS</span>
                            </span>
                          )}
                        </div>

                        {/* Host details */}
                        <div className="text-xs space-y-1 mt-2">
                          <div className="flex items-baseline space-x-1.5">
                            <span className="text-gray-500 font-mono text-[10px] uppercase tracking-wider w-12 shrink-0">From:</span>
                            <span className={`font-mono break-all ${isSuspiciousHost ? 'text-red-400 font-semibold' : 'text-gray-200'}`}>
                              {hop.fromServer}
                            </span>
                          </div>
                          <div className="flex items-baseline space-x-1.5">
                            <span className="text-gray-500 font-mono text-[10px] uppercase tracking-wider w-12 shrink-0">By:</span>
                            <span className="font-mono text-gray-300 break-all">
                              {hop.byServer}
                            </span>
                          </div>
                          {hop.forRecipient && (
                            <div className="flex items-baseline space-x-1.5">
                              <span className="text-gray-500 font-mono text-[10px] uppercase tracking-wider w-12 shrink-0">For:</span>
                              <span className="font-mono text-blue-400 break-all">
                                {hop.forRecipient}
                              </span>
                            </div>
                          )}
                          {hop.timestamp && (
                            <div className="flex items-baseline space-x-1.5 text-gray-400 text-[11px]">
                              <span className="font-mono text-gray-500 text-[10px] uppercase tracking-wider w-12 shrink-0">Time:</span>
                              <span className="font-sans">{hop.timestamp}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Actions: Toggle details & Copy */}
                    <div className="flex items-center space-x-2 shrink-0">
                      <button
                        onClick={() => copyHopRaw(hop)}
                        className="p-1.5 rounded-lg bg-black hover:bg-white/[0.05] border border-white/10 text-gray-400 hover:text-white transition cursor-pointer"
                        title="Copy Raw Hop Header"
                      >
                        {copiedHop === hop.hopNumber ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                      <button
                        onClick={() => toggleHop(hop.hopNumber)}
                        className="p-1.5 rounded-lg bg-black hover:bg-white/[0.05] border border-white/10 text-gray-400 hover:text-white transition cursor-pointer"
                        title={isExpanded ? 'Hide Raw Details' : 'View Raw Details'}
                      >
                        {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Expanded raw header view */}
                  {isExpanded && (
                    <div className="mt-3 p-3 rounded-lg bg-black border border-white/10 font-mono text-[11px] text-gray-300 overflow-x-auto whitespace-pre-wrap break-all">
                      <span className="text-blue-400 font-bold block mb-1">Raw Received Header:</span>
                      Received: {hop.rawHop}
                    </div>
                  )}
                </div>

                {/* Downward hop flow marker */}
                {index < hops.length - 1 && (
                  <div className="flex items-center justify-center my-1">
                    <ArrowDown className="w-3.5 h-3.5 text-gray-600" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
