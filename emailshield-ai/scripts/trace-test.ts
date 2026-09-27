import fs from 'fs';
import { parseRawEml } from '../src/utils/emlParser';

const file = process.argv[2];
if (!file) {
  console.error('usage: tsx scripts/trace-test.ts <path-to-eml>');
  process.exit(1);
}

const raw = fs.readFileSync(file, 'utf8');
const parsed = parseRawEml(raw);

const res = await fetch('http://localhost:3000/api/analyze-email', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ parsedEmail: parsed }),
});

const data: any = await res.json();

console.log('\n================ ORIGIN TRACE ================');
const t = data.originTrace;
if (!t) {
  console.log('(no originTrace in response)');
} else {
  console.log('originIp        :', t.originIp);
  console.log('originCountry   :', t.originGeo?.country, `(${t.originGeo?.countryCode})`, '-', t.originGeo?.city);
  console.log('originISP       :', t.originGeo?.isp);
  console.log('proxy/hosting   :', t.originGeo?.proxy, '/', t.originGeo?.hosting);
  console.log('lookupCount     :', t.lookupCount, '| note:', t.note || '(none)');
  console.log('\nHOP  IP                PUBLIC ORIGIN  LOCATION / ISP                         FLAGS');
  for (const h of t.hops) {
    const loc =
      h.geo?.status === 'success'
        ? `${h.geo.city || '?'}, ${h.geo.country || '?'} / ${h.geo.isp || '?'}`
        : h.geo
        ? `[${h.geo.status}] ${h.geo.message || ''}`
        : '(no lookup)';
    console.log(
      String(h.hopNumber).padEnd(4),
      (h.ip || '-').padEnd(17),
      String(h.isPublic).padEnd(6),
      (h.isProbableOrigin ? 'YES' : ' - ').padEnd(6),
      loc.slice(0, 38).padEnd(38),
      h.flags.join(',') || '-',
    );
  }
}

console.log('\n================ HYBRID SCORE ================');
console.log('ruleScore   :', data.ruleScore);
console.log('geminiScore :', data.geminiScore, '| engine:', data.engine);
console.log('fraudScore  :', data.fraudScore, '|', data.classification);
console.log('\nTRIGGERED RULES:');
for (const r of data.triggeredRules || []) {
  console.log(`  +${String(r.points).padEnd(3)} [${r.category}] ${r.rule}`);
}
