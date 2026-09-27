/** End-to-end: parse an HTML-only .eml and run it through /api/analyze-email. */
import fs from 'fs';
import { parseRawEml } from '../src/utils/emlParser';
import { hashAndClassifyAttachments } from '../src/utils/attachments';

const raw = fs.readFileSync(process.argv[2], 'utf8');
const parsed = parseRawEml(raw);
await hashAndClassifyAttachments(parsed);

const res = await fetch('http://localhost:3000/api/analyze-email', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ parsedEmail: parsed }),
});
const a: any = await res.json();
console.log('caseId              :', a.caseId);
console.log('classification      :', a.classification);
console.log('fraudScore          :', a.fraudScore, '(rule', a.ruleScore, '/ gemini', a.geminiScore, ')');
console.log('engine              :', a.engine, a.fallbackReason ? `(${a.fallbackReason})` : '');
console.log('triggered rules     :', (a.triggeredRules || []).map((r: any) => `${r.rule} +${r.points}`));
console.log('suspiciousPhrases   :', (a.suspiciousPhrases || []).map((p: any) => p.phrase));
console.log('redFlags            :', (a.redFlags || []).map((f: any) => f.title));
console.log('AI explanation      :', a.explanation);
