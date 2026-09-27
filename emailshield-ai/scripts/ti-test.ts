import fs from 'fs';
import { parseRawEml } from '../src/utils/emlParser';
import { hashAndClassifyAttachments } from '../src/utils/attachments';
import { buildForensicReportDoc } from '../src/utils/forensicReport';

const BASE = 'http://localhost:3000';
const emlPath = process.argv[2];
const outDir = process.argv[3] || '.';

const raw = fs.readFileSync(emlPath, 'utf8');
const parsed = parseRawEml(raw);
await hashAndClassifyAttachments(parsed);

console.log('=== PARSED ATTACHMENTS ===');
for (const a of parsed.attachments) {
  console.log(`  ${a.filename}  ${a.mimeType}  ${a.size}B  risk=${a.extensionRisk}  sha256=${a.sha256.slice(0, 20)}…`);
}
console.log('links:', parsed.extractedLinks.map((l) => `${l.text} -> ${l.href}${l.isMismatched ? ' [MISMATCH]' : ''}`));

// --- 1. full analysis (simulates the .eml upload path) --------------------
const res = await fetch(`${BASE}/api/analyze-email`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ parsedEmail: parsed }),
});
const analysis: any = await res.json();
console.log('\n=== ANALYSIS ===');
console.log('caseId       :', analysis.caseId);
console.log('engine       :', analysis.engine);
console.log('ruleScore    :', analysis.ruleScore, '| geminiScore:', analysis.geminiScore);
console.log('baseFraudScore:', analysis.baseFraudScore, '| fraudScore:', analysis.fraudScore, `[${analysis.classification}]`);
console.log('triggered rules:');
for (const r of analysis.triggeredRules || []) console.log(`  +${r.points} [${r.category}] ${r.rule}`);
console.log('origin trace hops + reputation:');
for (const h of analysis.originTrace?.hops || []) {
  const rep = h.reputation;
  console.log(
    `  hop${h.hopNumber} ${h.ip || '-'} public=${h.isPublic} geo=${h.geo?.status} ` +
      `rep=${rep ? `${rep.status}/${rep.abuseConfidenceScore}%/${rep.totalReports}rpts` : 'none'}`,
  );
}
console.log('maxAbuseScore:', analysis.originTrace?.maxAbuseScore, '| flaggedIp:', analysis.originTrace?.abuseFlaggedIp);
console.log('analysis.attachments:', (analysis.attachments || []).map((a: any) => `${a.filename}(risk=${a.extensionRisk})`));

// --- 2. PDF BEFORE deep scan --------------------------------------------
{
  const { doc } = buildForensicReportDoc(parsed as any, analysis, { sourceFileName: 'ti-test.eml (pre-deepscan)' });
  fs.writeFileSync(`${outDir}/ti-report-BEFORE.pdf`, Buffer.from(doc.output('arraybuffer')));
  console.log('\nwrote ti-report-BEFORE.pdf');
}

// --- 3. deep scan each URL + the attachment sequentially -----------------
const items = [
  ...parsed.extractedLinks
    .filter((l) => l.href && !/^(mailto:|#)/i.test(l.href))
    .map((l) => ({ kind: 'url' as const, url: l.href, displayText: l.text, mismatched: Boolean(l.isMismatched) })),
  ...parsed.attachments
    .filter((a) => a.sha256)
    .map((a) => ({ kind: 'file' as const, sha256: a.sha256, filename: a.filename, size: a.size, mimeType: a.mimeType })),
];
console.log('\n=== DEEP SCAN', items.length, 'items ===');
let last: any = analysis;
for (const item of items) {
  const t0 = Date.now();
  const r = await fetch(`${BASE}/api/deep-scan/${analysis.caseId}/scan-item`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ item }),
  });
  const j: any = await r.json();
  if (!r.ok) {
    console.log(`  ${item.kind} ${('url' in item ? item.url : item.filename)} -> HTTP ${r.status}: ${j.error}`);
    continue;
  }
  last = j.analysis;
  const res2 = j.result;
  console.log(
    `  [${Math.round((Date.now() - t0) / 1000)}s] ${item.kind} ${'url' in item ? item.url : item.filename} => ` +
      `status=${res2.status} ${res2.malicious}/${res2.total} malicious (+${res2.suspicious} susp) ` +
      `| addedPts=${j.analysis.deepScan.addedPoints} fraudScore=${j.analysis.fraudScore} [${j.analysis.classification}]`,
  );
}

// --- 4. PDF AFTER deep scan (reads current state) -----------------------
{
  const { doc } = buildForensicReportDoc(parsed as any, last, { sourceFileName: 'ti-test.eml (post-deepscan)' });
  fs.writeFileSync(`${outDir}/ti-report-AFTER.pdf`, Buffer.from(doc.output('arraybuffer')));
  console.log('\nwrote ti-report-AFTER.pdf');
}
console.log('\nFINAL: base', last.baseFraudScore, '+ deepScan', last.deepScan?.addedPoints, '=> fraudScore', last.fraudScore, `[${last.classification}]`);
