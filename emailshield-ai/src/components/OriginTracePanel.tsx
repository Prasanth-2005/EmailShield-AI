import React from 'react';
import { Globe2, MapPin, Server, AlertTriangle, Crosshair, ShieldAlert, ShieldCheck, Cloud, Smartphone, Flag } from 'lucide-react';
import type { GeoLocation, IpReputation, OriginTrace, OriginTraceHop } from '../types';
import { WorldTraceMap } from './WorldTraceMap';

interface OriginTracePanelProps {
  trace: OriginTrace | null | undefined;
  /** True when the analysis came from Gmail Quick Scan (no raw headers available). */
  bodyOnly?: boolean;
}

/** ISO 3166-1 alpha-2 -> flag emoji (regional indicator pair). */
function flagEmoji(cc?: string): string {
  if (!cc || cc.length !== 2 || !/^[a-zA-Z]{2}$/.test(cc)) return '🌐';
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

function locationLabel(geo: GeoLocation | null): string {
  if (!geo) return 'No IP to resolve';
  if (geo.status === 'private') return 'Private / internal hop';
  if (geo.status !== 'success') return 'Location unavailable';
  return [geo.city, geo.region, geo.country].filter(Boolean).join(', ') || geo.country || 'Unknown location';
}

const FLAG_META: Record<OriginTraceHop['flags'][number], { label: string; Icon: React.ElementType }> = {
  proxy: { label: 'PROXY / VPN / TOR', Icon: ShieldAlert },
  hosting: { label: 'HOSTING / DATACENTRE', Icon: Cloud },
  mobile: { label: 'MOBILE NETWORK', Icon: Smartphone },
};

/** AbuseIPDB reputation badge shown next to a hop's geolocation. */
const ReputationBadge: React.FC<{ reputation?: IpReputation | null }> = ({ reputation }) => {
  if (!reputation) return null;
  if (reputation.status === 'unavailable') {
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border bg-white/[0.04] border-white/10 text-gray-500">
        <AlertTriangle className="w-2.5 h-2.5" />
        Reputation check unavailable
      </span>
    );
  }
  if (reputation.status === 'clean') {
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border bg-emerald-500/10 border-emerald-500/25 text-emerald-400">
        <ShieldCheck className="w-2.5 h-2.5" />
        Clean
      </span>
    );
  }
  const high = reputation.abuseConfidenceScore >= 50 || reputation.totalReports >= 10;
  return (
    <span
      className={`inline-flex items-center gap-1 text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded border ${
        high ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
      }`}
      title={reputation.categories.length ? `AbuseIPDB categories: ${reputation.categories.join(', ')}` : undefined}
    >
      <Flag className="w-2.5 h-2.5" />
      {reputation.totalReports} report{reputation.totalReports === 1 ? '' : 's'} — Abuse Confidence {reputation.abuseConfidenceScore}%
    </span>
  );
};

const FlagBadges: React.FC<{ flags: OriginTraceHop['flags'] }> = ({ flags }) => (
  <>
    {flags.map((f) => {
      const { label, Icon } = FLAG_META[f];
      return (
        <span
          key={f}
          className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border bg-amber-500/10 border-amber-500/30 text-amber-300 uppercase tracking-wider"
        >
          <Icon className="w-2.5 h-2.5" />
          {label}
        </span>
      );
    })}
  </>
);

export const OriginTracePanel: React.FC<OriginTracePanelProps> = ({ trace, bodyOnly }) => {
  const hasHops = trace && trace.hops.length > 0;
  const origin = trace?.originGeo || null;
  const originHop = trace?.hops.find((h) => h.isProbableOrigin) || null;

  return (
    <div className="rounded-xl border border-white/10 bg-[#161616] p-5 shadow-xl">
      <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
        <div className="flex items-center space-x-2 text-sm font-semibold text-white">
          <Globe2 className="w-4 h-4 text-sky-400" />
          <span>Origin Trace &amp; Geolocation</span>
        </div>
        <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold font-mono">
          ip-api.com + AbuseIPDB &middot; {trace?.lookupCount ?? 0} IP{(trace?.lookupCount ?? 0) === 1 ? '' : 's'}
        </span>
      </div>

      {bodyOnly ? (
        <div className="p-6 text-center rounded-xl bg-sky-500/[0.04] border border-sky-500/20">
          <MapPin className="w-8 h-8 text-sky-400/70 mx-auto mb-2" />
          <p className="text-sm font-semibold text-gray-200">Not available for this analysis</p>
          <p className="text-xs text-gray-400 mt-1 max-w-md mx-auto">
            This analysis came from the Gmail Quick Scan extension, which does not expose raw headers.
            The Received relay chain, originating IP and geolocation require the original
            <span className="font-mono text-sky-300"> .eml</span> file — upload it above to run the trace.
          </p>
        </div>
      ) : !hasHops ? (
        <div className="p-6 text-center rounded-xl bg-black/40 border border-white/10">
          <MapPin className="w-8 h-8 text-gray-500 mx-auto mb-2" />
          <p className="text-sm font-semibold text-gray-200">Relay path cannot be traced</p>
          <p className="text-xs text-gray-400 mt-1 max-w-sm mx-auto">
            {trace?.note || 'No "Received:" routing headers were found in this message.'}
          </p>
        </div>
      ) : (
        <div className="space-y-5">
          {/* Probable origin summary */}
          <div
            className={`rounded-xl border p-4 ${
              origin?.status === 'success' && originHop && originHop.flags.length > 0
                ? 'border-rose-500/30 bg-rose-500/[0.05]'
                : 'border-sky-500/25 bg-sky-500/[0.04]'
            }`}
          >
            <div className="flex items-center gap-2 mb-2">
              <Crosshair className="w-4 h-4 text-rose-400" />
              <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-rose-300">
                Probable Origin
              </span>
              {originHop && <FlagBadges flags={originHop.flags} />}
            </div>

            {trace?.originIp ? (
              <div className="flex flex-wrap items-start gap-x-6 gap-y-2">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Origin IP</div>
                  <div className="font-mono text-sm text-sky-300">{trace.originIp}</div>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Location</div>
                  <div className="text-sm text-gray-200">
                    <span className="mr-1.5">{flagEmoji(origin?.countryCode)}</span>
                    {locationLabel(origin)}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Network / ISP</div>
                  <div className="text-sm text-gray-300 font-mono">
                    {origin?.status === 'success' ? origin.isp || origin.org || origin.asName || 'Unknown' : '—'}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Reputation</div>
                  <div className="mt-0.5">
                    <ReputationBadge reputation={originHop?.reputation} />
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-xs text-gray-400">{trace?.note || 'No public IP address found in the Received chain.'}</p>
            )}

            {origin && origin.status !== 'success' && origin.status !== 'private' && (
              <p className="text-[11px] text-amber-300/80 font-mono mt-2">
                <AlertTriangle className="w-3 h-3 inline mr-1 -mt-0.5" />
                Geolocation unavailable: {origin.message || 'lookup failed'}
              </p>
            )}
          </div>

          {/* World map */}
          <WorldTraceMap hops={trace!.hops} />

          {/* Vertical relay timeline */}
          <div>
            <div className="text-[10px] uppercase tracking-widest text-gray-500 font-bold mb-3">
              Relay Path ({trace!.hops.length} hop{trace!.hops.length === 1 ? '' : 's'}, earliest sender first)
            </div>
            <div className="space-y-2.5">
              {trace!.hops.map((hop, index) => {
                const isOrigin = hop.isProbableOrigin;
                const danger = hop.flags.length > 0;
                return (
                  <div key={hop.hopNumber} className="relative pl-8">
                    {/* rail */}
                    {index < trace!.hops.length - 1 && (
                      <span className="absolute left-[11px] top-6 bottom-[-14px] w-px bg-white/10" />
                    )}
                    <span
                      className={`absolute left-0 top-1 w-[22px] h-[22px] rounded-md border flex items-center justify-center text-[10px] font-mono font-bold ${
                        isOrigin
                          ? 'bg-rose-500/15 border-rose-500/40 text-rose-300'
                          : danger
                          ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                          : 'bg-white/[0.05] border-white/10 text-gray-400'
                      }`}
                    >
                      {index + 1}
                    </span>

                    <div
                      className={`rounded-lg border p-3 ${
                        isOrigin
                          ? 'border-rose-500/30 bg-rose-500/[0.04]'
                          : danger
                          ? 'border-amber-500/25 bg-amber-500/[0.03]'
                          : 'border-white/10 bg-black/40'
                      }`}
                    >
                      <div className="flex items-center flex-wrap gap-2 mb-1.5">
                        {isOrigin && (
                          <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 uppercase tracking-wider">
                            Probable Origin
                          </span>
                        )}
                        {hop.ip ? (
                          <span className="text-[10px] font-mono text-sky-300 bg-black px-1.5 py-0.5 rounded border border-white/10">
                            {hop.ip}
                            {!hop.isPublic && <span className="text-gray-500"> (private)</span>}
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono text-gray-500 bg-black px-1.5 py-0.5 rounded border border-white/10">
                            no IP logged
                          </span>
                        )}
                        <FlagBadges flags={hop.flags} />
                      </div>

                      <div className="flex items-center gap-1.5 text-xs text-gray-300 font-mono">
                        <Server className="w-3 h-3 text-gray-500 shrink-0" />
                        <span className="truncate" title={hop.fromServer}>{hop.fromServer}</span>
                        <span className="text-gray-600">&rarr;</span>
                        <span className="truncate text-gray-400" title={hop.byServer}>{hop.byServer}</span>
                      </div>

                      <div className="mt-1.5 text-xs text-gray-300 flex items-center flex-wrap gap-x-2 gap-y-1">
                        <span>
                          <span className="mr-1.5">{flagEmoji(hop.geo?.countryCode)}</span>
                          <span className={hop.geo?.status === 'success' ? '' : 'text-gray-500 italic'}>
                            {locationLabel(hop.geo)}
                          </span>
                          {hop.geo?.status === 'success' && (hop.geo.isp || hop.geo.org) && (
                            <span className="text-gray-500 font-mono"> &middot; {hop.geo.isp || hop.geo.org}</span>
                          )}
                        </span>
                        {hop.isPublic && <ReputationBadge reputation={hop.reputation} />}
                      </div>

                      {hop.timestamp && (
                        <div className="mt-1 text-[10px] text-gray-500 font-mono">{hop.timestamp}</div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
