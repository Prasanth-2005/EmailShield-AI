import React, { useState } from 'react';
import { Mail, Calendar, UserCheck, Shield, ChevronDown, ChevronUp, Copy, Check, AlertTriangle } from 'lucide-react';
import { ParsedEmail } from '../types';

interface EmailMetaPanelProps {
  email: ParsedEmail;
  /** True when the analysis came from Gmail Quick Scan (no raw headers available). */
  bodyOnly?: boolean;
}

export const EmailMetaPanel: React.FC<EmailMetaPanelProps> = ({ email, bodyOnly }) => {
  const [showRawAuth, setShowRawAuth] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const { from, to, subject, date, returnPath, replyTo, messageId, authResults } = email;

  const copyToClipboard = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 2000);
  };

  // Check for domain spoofing hints
  const hasReplyToMismatch = replyTo && from.domain && !replyTo.toLowerCase().includes(from.domain.toLowerCase());
  const hasReturnPathMismatch = returnPath && from.domain && !returnPath.toLowerCase().includes(from.domain.toLowerCase());

  const getStatusBadge = (status?: string, type?: 'spf' | 'dkim' | 'dmarc') => {
    const s = (status || 'none').toLowerCase();
    if (s === 'pass') {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
          PASS
        </span>
      );
    }
    if (s === 'fail' || s === 'softfail' || s === 'permerror') {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/10 border border-red-500/20 text-red-400">
          {s.toUpperCase()}
        </span>
      );
    }
    if (s === 'neutral') {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 border border-amber-500/20 text-amber-400">
          NEUTRAL
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-white/[0.05] border border-white/10 text-gray-400">
        NOT FOUND
      </span>
    );
  };

  return (
    <div className="rounded-xl border border-white/10 bg-[#161616] p-5 shadow-xl">
      <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
        <div className="flex items-center space-x-2 text-sm font-semibold text-white">
          <Mail className="w-4 h-4 text-blue-500" />
          <span>Extracted Envelope & Authentication Forensics</span>
        </div>
        <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold font-mono">RFC 5322 Metadata</span>
      </div>

      {/* Grid of Key Metadata */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
        {/* Subject */}
        <div className="md:col-span-2 p-3 rounded-lg bg-black/40 border border-white/10">
          <span className="text-gray-500 block text-[10px] uppercase tracking-widest font-bold mb-1">Subject</span>
          <span className="text-gray-100 font-sans text-sm font-medium break-words">
            {subject}
          </span>
        </div>

        {/* From */}
        <div className="p-3 rounded-lg bg-black/40 border border-white/10 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-gray-500 text-[10px] uppercase tracking-widest font-bold">From (Sender)</span>
            <button
              onClick={() => copyToClipboard(from.address, 'from')}
              className="text-gray-400 hover:text-white transition cursor-pointer"
              title="Copy Address"
            >
              {copiedField === 'from' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>
          <div className="font-sans font-medium text-gray-200 truncate">{from.displayName}</div>
          <div className="text-blue-400 font-mono text-xs truncate">&lt;{from.address}&gt;</div>
          {from.domain && (
            <div className="text-[11px] text-gray-500 pt-1">
              Domain: <span className="text-gray-300 font-semibold">{from.domain}</span>
            </div>
          )}
        </div>

        {/* To */}
        <div className="p-3 rounded-lg bg-black/40 border border-white/10 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-gray-500 text-[10px] uppercase tracking-widest font-bold">To (Recipient)</span>
            <button
              onClick={() => copyToClipboard(to.address, 'to')}
              className="text-gray-400 hover:text-white transition cursor-pointer"
              title="Copy Address"
            >
              {copiedField === 'to' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>
          <div className="font-mono text-gray-200 truncate">{to.address || to.raw}</div>
          <div className="text-gray-500 text-[11px] pt-1 flex items-center space-x-1">
            <Calendar className="w-3 h-3" />
            <span>{date || 'Date not specified'}</span>
          </div>
        </div>

        {/* Return Path */}
        <div className="p-3 rounded-lg bg-black/40 border border-white/10 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-gray-500 text-[10px] uppercase tracking-widest font-bold">Return-Path</span>
            {!bodyOnly && hasReturnPathMismatch && (
              <span className="flex items-center text-[10px] text-amber-400 gap-1 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20 font-bold uppercase">
                <AlertTriangle className="w-2.5 h-2.5" /> Mismatch
              </span>
            )}
          </div>
          <div className={`font-mono truncate ${!bodyOnly && hasReturnPathMismatch ? 'text-amber-300' : bodyOnly ? 'text-gray-600 italic' : 'text-gray-300'}`}>
            {bodyOnly ? 'Not available (Gmail)' : returnPath ? `<${returnPath}>` : '<Not Specified>'}
          </div>
          <div className="text-[11px] text-gray-500">
            {bodyOnly ? 'Header not exposed by Gmail — upload the .eml' : 'Address used for bounce delivery notifications'}
          </div>
        </div>

        {/* Reply-To */}
        <div className="p-3 rounded-lg bg-black/40 border border-white/10 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-gray-500 text-[10px] uppercase tracking-widest font-bold">Reply-To</span>
            {!bodyOnly && hasReplyToMismatch && (
              <span className="flex items-center text-[10px] text-red-400 gap-1 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20 font-bold uppercase">
                <AlertTriangle className="w-2.5 h-2.5" /> Mismatch
              </span>
            )}
          </div>
          <div className={`font-mono truncate ${!bodyOnly && hasReplyToMismatch ? 'text-red-300' : bodyOnly ? 'text-gray-600 italic' : 'text-gray-300'}`}>
            {bodyOnly ? 'Not available (Gmail)' : replyTo ? `<${replyTo}>` : '<Same as From>'}
          </div>
          <div className="text-[11px] text-gray-500">
            {bodyOnly ? 'Header not exposed by Gmail — upload the .eml' : 'Where user responses are routed'}
          </div>
        </div>
      </div>

      {/* Message-ID */}
      {!bodyOnly && messageId && (
        <div className="mt-3 p-2.5 rounded-lg bg-black/40 border border-white/10 flex items-center justify-between text-xs font-mono">
          <span className="text-gray-500 shrink-0 text-[10px] uppercase tracking-widest font-bold">Message-ID:</span>
          <span className="text-gray-300 truncate mx-2 text-[11px]">&lt;{messageId}&gt;</span>
          <button
            onClick={() => copyToClipboard(messageId, 'mid')}
            className="text-gray-400 hover:text-white cursor-pointer"
          >
            {copiedField === 'mid' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          </button>
        </div>
      )}

      {/* Authentication Checks: SPF, DKIM, DMARC */}
      <div className="mt-4 p-4 rounded-xl bg-black/30 border border-white/10">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2 text-xs font-semibold uppercase tracking-wider text-gray-200">
            <Shield className="w-4 h-4 text-blue-400" />
            <span>Email Authentication Results (SPF / DKIM / DMARC)</span>
          </div>
          {!bodyOnly && authResults.rawAuthHeader && (
            <button
              onClick={() => setShowRawAuth(!showRawAuth)}
              className="text-[11px] font-mono text-blue-400 hover:text-blue-300 flex items-center gap-1 cursor-pointer"
            >
              <span>{showRawAuth ? 'Hide Raw Header' : 'View Raw Header'}</span>
              {showRawAuth ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
          )}
        </div>

        {bodyOnly ? (
          <div className="p-4 rounded-lg bg-sky-500/[0.04] border border-sky-500/20 text-center">
            <p className="text-xs font-semibold text-gray-200">Not available — this analysis came from Gmail</p>
            <p className="text-[11px] text-gray-400 mt-1 max-w-md mx-auto">
              Gmail's DOM does not expose the <span className="font-mono">Authentication-Results</span> header,
              so SPF, DKIM and DMARC could not be evaluated. Upload the original
              <span className="font-mono text-sky-300"> .eml</span> file to verify sender authentication.
            </p>
          </div>
        ) : (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {/* SPF */}
          <div className="p-3 rounded-lg bg-black/50 border border-white/10">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-gray-200">SPF</span>
              {getStatusBadge(authResults.spf?.status, 'spf')}
            </div>
            <p className="text-[11px] text-gray-400 line-clamp-2">
              {authResults.spf?.details || 'Sender Policy Framework verification for transmitting IP.'}
            </p>
          </div>

          {/* DKIM */}
          <div className="p-3 rounded-lg bg-black/50 border border-white/10">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-gray-200">DKIM</span>
              {getStatusBadge(authResults.dkim?.status, 'dkim')}
            </div>
            <p className="text-[11px] text-gray-400 line-clamp-2">
              {authResults.dkim?.details || (authResults.dkim?.domain ? `Signed by @${authResults.dkim.domain}` : 'DomainKeys Identified Mail cryptographic signature.')}
            </p>
          </div>

          {/* DMARC */}
          <div className="p-3 rounded-lg bg-black/50 border border-white/10">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-gray-200">DMARC</span>
              {getStatusBadge(authResults.dmarc?.status, 'dmarc')}
            </div>
            <p className="text-[11px] text-gray-400 line-clamp-2">
              {authResults.dmarc?.details || (authResults.dmarc?.policy ? `Policy: ${authResults.dmarc.policy}` : 'Domain-based Message Authentication alignment policy.')}
            </p>
          </div>
        </div>
        )}

        {!bodyOnly && showRawAuth && authResults.rawAuthHeader && (
          <div className="mt-3 p-3 rounded-lg bg-black border border-white/10 font-mono text-[11px] text-gray-300 overflow-x-auto whitespace-pre-wrap break-all">
            {authResults.rawAuthHeader}
          </div>
        )}
      </div>
    </div>
  );
};
