/** IPv4 dotted-quad matcher. */
export const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * True for private, loopback, link-local, CGNAT and other non-routable IPv4
 * ranges — anything that cannot meaningfully be geolocated or reputation-checked
 * as an origin.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const m = ip.match(IPV4_RE);
  if (!m) return true; // not a plain IPv4 address -> treat as unusable
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a > 255 || b > 255 || Number(m[3]) > 255 || Number(m[4]) > 255) return true;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 0) return true; // "this" network
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 169 && b === 254) return true; // link-local
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a >= 224) return true; // multicast + reserved
  return false;
}
