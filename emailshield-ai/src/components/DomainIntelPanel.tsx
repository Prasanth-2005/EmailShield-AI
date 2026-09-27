import React from 'react';
import { Globe, CalendarClock, Building2, ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react';
import type { DomainIntelReport, DomainIntelEntry } from '../types';

interface DomainIntelPanelProps {
  report: DomainIntelReport | null | undefined;
}

const ROLE_META: Record<DomainIntelEntry['role'], { label: string; cls: string }> = {
  'from': { label: 'FROM', cls: 'bg-blue-500/10 text-blue-300 border-blue-500/25' },
  'return-path': { label: 'RETURN-PATH', cls: 'bg-violet-500/10 text-violet-300 border-violet-500/25' },
  'deceptive-link': { label: 'DECEPTIVE LINK', cls: 'bg-red-500/10 text-red-300 border-red-500/25' },
};

function fmtDate(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

/** Age chip — red under 30 days, amber under 90, muted otherwise. */
const AgeChip: React.FC<{ ageDays?: number }> = ({ ageDays }) => {
  if (typeof ageDays !== 'number') {
    return <span className="text-[11px] font-mono text-gray-500">unknown</span>;
  }
  const cls =
    ageDays < 30
      ? 'bg-red-500/15 text-red-300 border-red-500/40'
      : ageDays < 90
      ? 'bg-amber-500/15 text-amber-300 border-amber-500/40'
      : 'bg-white/[0.04] text-gray-300 border-white/10';
  const Icon = ageDays < 30 ? ShieldAlert : ageDays < 90 ? AlertTriangle : CheckCircle2;
  return (
    <span className={`inline-flex items-center gap-1 text-[11px] font-mono font-bold px-1.5 py-0.5 rounded border ${cls}`}>
      <Icon className="w-3 h-3" />
      {ageDays.toLocaleString()} day{ageDays === 1 ? '' : 's'} old
    </span>
  );
};

/**
 * RDAP domain registration intelligence for the sender / return-path / deceptive
 * link domains. A domain registered very recently is a strong fraud signal.
 * Hidden entirely when no domains were looked up.
 */
export const DomainIntelPanel: React.FC<DomainIntelPanelProps> = ({ report }) => {
  const entries = report?.entries ?? [];
  if (entries.length === 0) return null;

  return (
    <div className="rounded-xl border border-white/10 bg-[#161616] p-5 shadow-xl">
      <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
        <div className="flex items-center space-x-2 text-sm font-semibold text-white">
          <Globe className="w-4 h-4 text-emerald-400" />
          <span>Domain Intelligence ({entries.length})</span>
        </div>
        <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold font-mono">
          RDAP registration data
        </span>
      </div>

      <div className="space-y-3">
        {entries.map((e) => {
          const unavailable = e.status !== 'ok';
          return (
            <div
              key={`${e.role}:${e.domain}`}
              className={`p-3.5 rounded-lg border ${
                typeof e.ageDays === 'number' && e.ageDays < 30
                  ? 'border-red-500/30 bg-red-500/[0.05]'
                  : 'border-white/10 bg-black/30'
              }`}
            >
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="min-w-0">
                  <div className="flex items-center flex-wrap gap-2">
                    <span
                      className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${ROLE_META[e.role].cls} uppercase tracking-wider`}
                    >
                      {ROLE_META[e.role].label}
                    </span>
                    <span className="text-sm font-mono font-semibold text-gray-100 break-all">{e.domain}</span>
                  </div>

                  {unavailable ? (
                    <div className="mt-2 text-xs text-gray-400 flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                      Registration data unavailable
                      {e.message ? <span className="text-gray-600">· {e.message}</span> : null}
                    </div>
                  ) : (
                    <div className="mt-2 grid grid-cols-1 sm:grid-cols-3 gap-x-4 gap-y-1 text-[11px] font-mono">
                      <div>
                        <span className="text-gray-500">Registered </span>
                        <span className="text-gray-200">{fmtDate(e.registeredAt)}</span>
                      </div>
                      <div>
                        <span className="text-gray-500">Updated </span>
                        <span className="text-gray-300">{fmtDate(e.updatedAt)}</span>
                      </div>
                      <div>
                        <span className="text-gray-500">Expires </span>
                        <span className="text-gray-300">{fmtDate(e.expiresAt)}</span>
                      </div>
                      <div className="sm:col-span-3 flex items-center gap-1.5 text-gray-300">
                        <Building2 className="w-3 h-3 text-gray-500 shrink-0" />
                        {e.registrar || 'Registrar not disclosed'}
                      </div>
                    </div>
                  )}
                </div>

                {!unavailable && (
                  <div className="shrink-0 flex items-center gap-1.5">
                    <CalendarClock className="w-3.5 h-3.5 text-gray-500" />
                    <AgeChip ageDays={e.ageDays} />
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <p className="mt-3 text-[11px] text-gray-500 leading-relaxed">
        Registration age is looked up automatically via RDAP (free, no API key). A sender domain under 30 days old adds
        +25 to the rule-based score; under 90 days adds +15. Some country-code registries do not answer RDAP — those show
        as unavailable and score nothing.
      </p>
    </div>
  );
};
