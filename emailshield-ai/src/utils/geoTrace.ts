import type { GeoLocation, IpReputation, OriginTrace, OriginTraceHop, ParsedEmail, ReceivedHop } from '../types';
import { IPV4_RE, isPrivateOrReservedIp } from './ipUtils';
import { checkIpReputation } from './threatIntel';

export { isPrivateOrReservedIp };

/**
 * Origin Trace & Geolocation
 * --------------------------
 * Turns the parsed Received chain into an ordered relay path, finds the earliest
 * reliable (public) originating IP, and resolves every public IP to a geolocation
 * using the free, key-less ip-api.com endpoint (45 req/min). Results are cached in
 * memory for the lifetime of the server process so the same IP is never looked up
 * twice.
 *
 * Every failure mode (unresolvable IP, network error, rate limit, malformed
 * Received header) degrades to `geo: null` / `status: 'error'` for that hop — the
 * panel must never crash because a lookup failed.
 */

const IP_API_ENDPOINT = 'http://ip-api.com/json';
// Named fields kept deliberately explicit so the shape is obvious.
const IP_API_FIELDS =
  'status,message,country,countryCode,region,city,isp,org,as,asname,lat,lon,proxy,hosting,mobile,query';
const LOOKUP_TIMEOUT_MS = 6000;

/** Process-lifetime cache: IP string -> resolved geolocation. */
const geoCache = new Map<string, GeoLocation>();

/** Pull the first usable public IPv4 out of a raw hop string (fromServer etc.). */
function extractHopIp(hop: ReceivedHop): { ip?: string; isPublic: boolean } {
  const candidates: string[] = [];
  if (hop.ipAddress) candidates.push(hop.ipAddress);
  // Fall back to scanning the raw hop for any dotted-quad.
  const raw = hop.rawHop || '';
  for (const match of raw.matchAll(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g)) {
    candidates.push(match[1]);
  }

  let firstAny: string | undefined;
  for (const ip of candidates) {
    if (!IPV4_RE.test(ip)) continue;
    if (!firstAny) firstAny = ip;
    if (!isPrivateOrReservedIp(ip)) return { ip, isPublic: true };
  }
  return { ip: firstAny, isPublic: false };
}

/** Resolve a single IP to a geolocation, with caching and graceful failure. */
export async function lookupGeo(ip: string): Promise<GeoLocation> {
  const cached = geoCache.get(ip);
  if (cached) return cached;

  if (isPrivateOrReservedIp(ip)) {
    const result: GeoLocation = { ip, status: 'private', message: 'Private / reserved address — not geolocatable' };
    geoCache.set(ip, result);
    return result;
  }

  let result: GeoLocation;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LOOKUP_TIMEOUT_MS);
  try {
    const res = await fetch(`${IP_API_ENDPOINT}/${encodeURIComponent(ip)}?fields=${IP_API_FIELDS}`, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      result = { ip, status: 'error', message: `ip-api.com HTTP ${res.status}` };
    } else {
      const data: any = await res.json();
      if (data?.status === 'success') {
        result = {
          ip,
          status: 'success',
          country: data.country,
          countryCode: data.countryCode,
          region: data.region,
          city: data.city,
          isp: data.isp,
          org: data.org || data.isp,
          asName: data.asname || data.as,
          lat: typeof data.lat === 'number' ? data.lat : undefined,
          lon: typeof data.lon === 'number' ? data.lon : undefined,
          proxy: Boolean(data.proxy),
          hosting: Boolean(data.hosting),
          mobile: Boolean(data.mobile),
        };
      } else {
        result = { ip, status: 'fail', message: data?.message || 'ip-api.com could not resolve this IP' };
      }
    }
  } catch (err: any) {
    const message = err?.name === 'AbortError' ? 'Geolocation lookup timed out' : err?.message || 'Geolocation lookup failed';
    result = { ip, status: 'error', message };
  } finally {
    clearTimeout(timer);
  }

  geoCache.set(ip, result);
  return result;
}

function flagsForGeo(geo: GeoLocation | null): Array<'proxy' | 'hosting' | 'mobile'> {
  if (!geo || geo.status !== 'success') return [];
  const flags: Array<'proxy' | 'hosting' | 'mobile'> = [];
  if (geo.proxy) flags.push('proxy');
  if (geo.hosting) flags.push('hosting');
  if (geo.mobile) flags.push('mobile');
  return flags;
}

/**
 * Builds the full Origin Trace for a parsed email. Never throws — on any internal
 * error it returns an empty trace with a `note` explaining why.
 */
export async function buildOriginTrace(parsedEmail: ParsedEmail): Promise<OriginTrace> {
  try {
    const rawHops = Array.isArray(parsedEmail?.receivedHops) ? parsedEmail.receivedHops : [];

    // 1. Ordered skeleton (parser already reverses so hop 1 == earliest sender).
    const hops: OriginTraceHop[] = rawHops.map((h) => {
      const { ip, isPublic } = extractHopIp(h);
      return {
        hopNumber: h.hopNumber,
        fromServer: h.fromServer || 'unknown',
        byServer: h.byServer || 'unknown',
        ip,
        isPublic,
        timestamp: h.timestamp,
        geo: null,
        isProbableOrigin: false,
        flags: [],
      };
    });

    if (hops.length === 0) {
      return {
        hops,
        originIp: null,
        originGeo: null,
        originCountryCode: null,
        lookupCount: 0,
        note: 'No Received headers present — the relay path cannot be traced.',
      };
    }

    // 2. Earliest reliable originating IP = first public IP in the chain.
    const originHop = hops.find((h) => h.isPublic && h.ip);
    const originIp = originHop?.ip ?? null;
    if (originHop) originHop.isProbableOrigin = true;

    // 3. Resolve geolocation + AbuseIPDB reputation for every distinct public IP.
    const uniquePublicIps = Array.from(new Set(hops.filter((h) => h.isPublic && h.ip).map((h) => h.ip as string)));
    const resolved = new Map<string, GeoLocation>();
    const reputations = new Map<string, IpReputation>();
    for (const ip of uniquePublicIps) {
      resolved.set(ip, await lookupGeo(ip));
      reputations.set(ip, await checkIpReputation(ip));
    }

    for (const hop of hops) {
      if (hop.isPublic && hop.ip && resolved.has(hop.ip)) {
        hop.geo = resolved.get(hop.ip) as GeoLocation;
        hop.flags = flagsForGeo(hop.geo);
        hop.reputation = reputations.get(hop.ip) ?? null;
      }
    }

    const originGeo = originIp ? resolved.get(originIp) ?? null : null;
    const originCountryCode = originGeo && originGeo.status === 'success' ? originGeo.countryCode ?? null : null;

    // Highest AbuseIPDB confidence across all hops (drives a rule check).
    let maxAbuseScore = 0;
    let abuseFlaggedIp: string | null = null;
    for (const [ip, rep] of reputations) {
      if (rep.status !== 'unavailable' && rep.abuseConfidenceScore > maxAbuseScore) {
        maxAbuseScore = rep.abuseConfidenceScore;
        abuseFlaggedIp = ip;
      }
    }

    return {
      hops,
      originIp,
      originGeo,
      originCountryCode,
      lookupCount: uniquePublicIps.length,
      reputationLookups: uniquePublicIps.length,
      maxAbuseScore,
      abuseFlaggedIp,
      note: originIp ? undefined : 'No public IP address found in the Received chain — origin cannot be geolocated.',
    };
  } catch (err: any) {
    return {
      hops: [],
      originIp: null,
      originGeo: null,
      originCountryCode: null,
      lookupCount: 0,
      note: `Origin trace could not be built: ${err?.message || 'unknown error'}`,
    };
  }
}
