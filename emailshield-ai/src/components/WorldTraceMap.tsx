import React, { useMemo } from 'react';
import { feature } from 'topojson-client';
import worldTopo from 'world-atlas/countries-110m.json';
import type { OriginTraceHop } from '../types';

/**
 * Dependency-light world map: a bundled 110m country topology projected with a
 * plain equirectangular transform (no runtime fetch, no projection library).
 * Plots a marker for every hop that resolved to lat/lon and connects them with a
 * path line in relay order.
 */

// viewBox is 0 0 360 180 so the projection is just an offset: lon+180, 90-lat.
const W = 360;
const H = 180;
const project = (lon: number, lat: number): [number, number] => [lon + 180, 90 - lat];

type Ring = number[][];
type Poly = Ring[];

function ringToPath(ring: Ring): string {
  let d = '';
  ring.forEach(([lon, lat], i) => {
    const [x, y] = project(lon, lat);
    d += `${i === 0 ? 'M' : 'L'}${x.toFixed(2)} ${y.toFixed(2)}`;
  });
  return d + 'Z';
}

function geometryToPath(geometry: any): string {
  if (!geometry) return '';
  if (geometry.type === 'Polygon') {
    return (geometry.coordinates as Poly).map(ringToPath).join(' ');
  }
  if (geometry.type === 'MultiPolygon') {
    return (geometry.coordinates as Poly[]).map((poly) => poly.map(ringToPath).join(' ')).join(' ');
  }
  return '';
}

interface WorldTraceMapProps {
  hops: OriginTraceHop[];
}

export const WorldTraceMap: React.FC<WorldTraceMapProps> = ({ hops }) => {
  const countryPath = useMemo(() => {
    try {
      const fc = feature(worldTopo as any, (worldTopo as any).objects.countries) as any;
      return fc.features.map((f: any) => geometryToPath(f.geometry)).join(' ');
    } catch {
      return '';
    }
  }, []);

  const located = hops.filter(
    (h) => h.geo && h.geo.status === 'success' && typeof h.geo.lat === 'number' && typeof h.geo.lon === 'number',
  );

  const points = located.map((h) => {
    const [x, y] = project(h.geo!.lon as number, h.geo!.lat as number);
    return { hop: h, x, y };
  });

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(2)} ${p.y.toFixed(2)}`).join(' ');

  return (
    <div className="rounded-lg border border-white/10 bg-black/50 overflow-hidden">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full block" style={{ aspectRatio: '2 / 1' }} role="img" aria-label="Relay path world map">
        <rect x={0} y={0} width={W} height={H} fill="#0b1220" />
        {/* graticule */}
        {[-120, -60, 0, 60, 120].map((lon) => (
          <line key={`v${lon}`} x1={lon + 180} y1={0} x2={lon + 180} y2={H} stroke="#1e293b" strokeWidth={0.3} />
        ))}
        {[-60, -30, 0, 30, 60].map((lat) => (
          <line key={`h${lat}`} x1={0} y1={90 - lat} x2={W} y2={90 - lat} stroke="#1e293b" strokeWidth={0.3} />
        ))}
        <path d={countryPath} fill="#1f2b3e" stroke="#324155" strokeWidth={0.2} fillRule="evenodd" />

        {/* relay path line */}
        {points.length > 1 && (
          <path d={linePath} fill="none" stroke="#38bdf8" strokeWidth={0.7} strokeDasharray="2 1.5" opacity={0.9} />
        )}

        {/* markers */}
        {points.map(({ hop, x, y }, i) => {
          const danger = hop.flags.length > 0;
          const color = hop.isProbableOrigin ? '#f43f5e' : danger ? '#f59e0b' : '#38bdf8';
          return (
            <g key={hop.hopNumber}>
              <circle cx={x} cy={y} r={hop.isProbableOrigin ? 2.6 : 1.9} fill={color} opacity={0.28} />
              <circle cx={x} cy={y} r={hop.isProbableOrigin ? 1.5 : 1.1} fill={color} stroke="#0b1220" strokeWidth={0.3} />
              <text x={x + 2.4} y={y + 1} fontSize={3} fill="#cbd5e1" fontFamily="monospace">
                {i + 1}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2 text-[10px] font-mono text-gray-400 border-t border-white/10">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-rose-500" /> Probable origin</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-500" /> Proxy / hosting hop</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-sky-400" /> Relay hop</span>
        {located.length === 0 && <span className="text-gray-500">No hops could be geolocated for the map.</span>}
      </div>
    </div>
  );
};
