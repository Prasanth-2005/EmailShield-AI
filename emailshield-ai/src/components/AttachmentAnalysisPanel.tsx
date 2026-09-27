import React, { useState } from 'react';
import { Paperclip, AlertTriangle, FileWarning, Archive, Copy, Check } from 'lucide-react';
import type { EmailAttachment } from '../types';

interface AttachmentAnalysisPanelProps {
  attachments: EmailAttachment[];
}

function humanSize(bytes: number): string {
  if (!bytes) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${u[i]}`;
}

const RISK_META: Record<
  NonNullable<EmailAttachment['extensionRisk']>,
  { label: string; cls: string; Icon: React.ElementType }
> = {
  high: { label: 'HIGH RISK', cls: 'bg-red-500/10 text-red-400 border-red-500/30', Icon: AlertTriangle },
  macro: { label: 'MACRO', cls: 'bg-amber-500/10 text-amber-300 border-amber-500/30', Icon: FileWarning },
  'archive-exe': { label: 'ARCHIVE + EXE', cls: 'bg-amber-500/10 text-amber-300 border-amber-500/30', Icon: Archive },
};

const ShaCell: React.FC<{ sha: string }> = ({ sha }) => {
  const [copied, setCopied] = useState(false);
  if (!sha) return <span className="text-gray-600 font-mono text-[10px]">hash unavailable</span>;
  return (
    <button
      onClick={() => {
        navigator.clipboard?.writeText(sha).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
      className="inline-flex items-center gap-1 text-[10px] font-mono text-gray-400 hover:text-gray-200 transition cursor-pointer"
      title={sha}
    >
      <span>{sha.slice(0, 16)}…</span>
      {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
    </button>
  );
};

/**
 * Part 3 — static attachment analysis (metadata + SHA-256 + extension risk).
 * Renders nothing when the email has no attachments.
 */
export const AttachmentAnalysisPanel: React.FC<AttachmentAnalysisPanelProps> = ({ attachments }) => {
  if (!attachments || attachments.length === 0) return null;

  return (
    <div className="rounded-xl border border-white/10 bg-[#161616] p-5 shadow-xl">
      <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
        <div className="flex items-center space-x-2 text-sm font-semibold text-white">
          <Paperclip className="w-4 h-4 text-amber-400" />
          <span>Attachment Analysis ({attachments.length})</span>
        </div>
        <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold font-mono">Static — no upload</span>
      </div>

      <div className="space-y-2.5">
        {attachments.map((att, i) => {
          const risk = att.extensionRisk ? RISK_META[att.extensionRisk] : null;
          return (
            <div
              key={att.sha256 || i}
              className={`rounded-lg border p-3 ${
                risk ? 'border-red-500/25 bg-red-500/[0.04]' : 'border-white/10 bg-black/40'
              }`}
            >
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium text-gray-100 break-all">{att.filename}</span>
                    {risk && (
                      <span
                        className={`inline-flex items-center gap-1 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border uppercase ${risk.cls}`}
                      >
                        <risk.Icon className="w-2.5 h-2.5" />
                        {risk.label}
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-gray-500 font-mono mt-1">
                    {att.mimeType} · {humanSize(att.size)}
                  </div>
                  {att.riskReason && <div className="text-[11px] text-red-300/90 mt-1">{att.riskReason}</div>}
                  {att.archiveContents && att.archiveContents.length > 0 && (
                    <div className="text-[10px] text-gray-500 font-mono mt-1 break-all">
                      Contains: {att.archiveContents.slice(0, 6).join(', ')}
                      {att.archiveContents.length > 6 ? ` +${att.archiveContents.length - 6}` : ''}
                    </div>
                  )}
                </div>
                <div className="shrink-0 pt-0.5">
                  <div className="text-[9px] uppercase tracking-wider text-gray-600 font-bold">SHA-256</div>
                  <ShaCell sha={att.sha256} />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
