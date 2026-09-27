import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldX } from 'lucide-react';
import type { RiskBand } from '../services/gmailService';

const META: Record<RiskBand, { label: string; cls: string; dot: string; Icon: React.ElementType }> = {
  green: {
    label: 'Low risk',
    cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25',
    dot: 'bg-emerald-400',
    Icon: ShieldCheck,
  },
  amber: {
    label: 'Caution',
    cls: 'bg-amber-500/10 text-amber-300 border-amber-500/25',
    dot: 'bg-amber-400',
    Icon: ShieldAlert,
  },
  red: {
    label: 'High risk',
    cls: 'bg-red-500/10 text-red-400 border-red-500/25',
    dot: 'bg-red-500',
    Icon: ShieldX,
  },
};

interface RiskBadgeProps {
  band: RiskBand;
  score?: number;
  variant?: 'pill' | 'dot';
  className?: string;
}

/** Rule-based traffic-light badge (green / amber / red). No AI involved. */
export const RiskBadge: React.FC<RiskBadgeProps> = ({ band, score, variant = 'pill', className = '' }) => {
  const m = META[band];
  if (variant === 'dot') {
    return <span className={`inline-block w-2.5 h-2.5 rounded-full ${m.dot} ${className}`} title={m.label} />;
  }
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-[11px] font-semibold ${m.cls} ${className}`}
    >
      <m.Icon className="w-3 h-3" />
      <span>{m.label}</span>
      {typeof score === 'number' && <span className="font-mono opacity-70">· {score}</span>}
    </span>
  );
};
