import fs from 'fs';
import { parseRawEml } from '../src/utils/emlParser';
import { hashAndClassifyAttachments } from '../src/utils/attachments';

const BASE = 'http://localhost:3000';
const raw = fs.readFileSync(process.argv[2], 'utf8');
const parsed = parseRawEml(raw);
await hashAndClassifyAttachments(parsed);

// Mirror the client-side normalize + grouping (DeepScanPanel).
function normalizeUrl(href: string): string {
  try {
    const u = new URL(href);
    const path = u.pathname.replace(/\/+$/, '') || '/';
    return `${u.protocol}//${u.host.toLowerCase()}${path}`;
  } catch {
    return href.split('#')[0].split('?')[0];
  }
}
const groups = new Map<string, { count: number; mismatched: boolean; label?: string; hasLabel: boolean }>();
for (const l of parsed.extractedLinks) {
  const href = (l.href || '').trim();
  if (!href || /^(mailto:|tel:|#|javascript:)/i.test(href)) continue;
  const n = normalizeUrl(href);
  const text = (l.text || '').trim();
  const isLabel = !!text && text !== href && text !== n && !/^https?:\/\//i.test(text);
  const g = groups.get(n) || { count: 0, mismatched: false, hasLabel: false };
  g.count++; g.mismatched = g.mismatched || Boolean(l.isMismatched);
  if (isLabel && !g.label) g.label = text;
  g.hasLabel = g.hasLabel || isLabel;
  groups.set(n, g);
}
const sorted = [...groups.entries()]
  .map(([n, g]) => ({ n, ...g, rank: g.mismatched ? 0 : g.hasLabel ? 2 : 3 }))
  .sort((a, b) => a.rank - b.rank || b.count - a.count || a.n.localeCompare(b.n));

console.log(`raw links: ${parsed.extractedLinks.length}  ->  unique destinations: ${groups.size}\n`);
console.log('SORTED UNIQUE LIST (mismatched/labelled first):');
for (const g of sorted) {
  console.log(`  rank${g.rank}  ${g.count}x  ${g.mismatched ? '[MISMATCH] ' : ''}${g.label ? `("${g.label}") ` : ''}${g.n}`);
}

// --- analyze + deep-scan the fresh unknown URL to exercise the poll loop --
const res = await fetch(`${BASE}/api/analyze-email`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ parsedEmail: parsed }),
});
const analysis: any = await res.json();
console.log(`\ncaseId ${analysis.caseId} | fraudScore ${analysis.fraudScore}`);

const unknown = sorted.find((g) => g.n.includes('claude-emailshield-ti-test'))!;
console.log(`\n=== scan-item (unknown URL, normalized): ${unknown.n}`);
const s1 = await (await fetch(`${BASE}/api/deep-scan/${analysis.caseId}/scan-item`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ item: { kind: 'url', url: unknown.n, mismatched: unknown.mismatched, appearsCount: unknown.count } }),
})).json();
console.log('  result:', JSON.stringify(s1.result));

let analysisId = s1.result.analysisId;
for (let i = 1; i <= 6; i++) {
  await new Promise((r) => setTimeout(r, 5000));
  const p = await (await fetch(`${BASE}/api/deep-scan/${analysis.caseId}/poll-item`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analysisId, url: unknown.n, appearsCount: unknown.count }),
  })).json();
  console.log(`  poll ${i}/6: status=${p.result.status} ${p.result.status === 'done' ? `${p.result.malicious}/${p.result.total} malicious` : (p.result.message || '')}`);
  analysisId = p.result.analysisId || analysisId;
  if (p.result.status !== 'pending') { console.log(`  -> resolved. fraudScore now ${p.analysis.fraudScore}`); break; }
}

// deep-scan the deceptive medium.com/account link too
const deceptive = sorted.find((g) => g.mismatched)!;
console.log(`\n=== scan-item (deceptive mismatched link): ${deceptive.n}`);
const s2 = await (await fetch(`${BASE}/api/deep-scan/${analysis.caseId}/scan-item`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ item: { kind: 'url', url: deceptive.n, mismatched: true, appearsCount: deceptive.count } }),
})).json();
console.log('  result:', JSON.stringify(s2.result), '| fraudScore', s2.analysis.fraudScore);
