import fs from 'fs';
import path from 'path';
import { parseRawEml } from '../src/utils/emlParser';
import { buildForensicReportDoc } from '../src/utils/forensicReport';

const emlPath = process.argv[2];
const outDir = process.argv[3] || '.';
if (!emlPath) {
  console.error('usage: tsx scripts/report-test.ts <path-to-eml> [outDir]');
  process.exit(1);
}

const parsed = parseRawEml(fs.readFileSync(emlPath, 'utf8'));
const res = await fetch('http://localhost:3000/api/analyze-email', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ parsedEmail: parsed }),
});
const analysis: any = await res.json();

const { doc, caseId, fileName } = buildForensicReportDoc(parsed, analysis, {
  sourceFileName: path.basename(emlPath),
});

const bytes = Buffer.from(doc.output('arraybuffer'));
const outPath = path.join(outDir, fileName);
fs.writeFileSync(outPath, bytes);

console.log('case id      :', caseId);
console.log('file name    :', fileName);
console.log('pages        :', doc.getNumberOfPages());
console.log('size (bytes) :', bytes.length);
console.log('written to   :', outPath);
console.log('verdict      :', analysis.classification, analysis.fraudScore, `(rule ${analysis.ruleScore} / ai ${analysis.geminiScore})`);
