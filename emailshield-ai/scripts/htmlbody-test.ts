/**
 * Before/after check: confirm HTML-only mail (including nested multipart) now
 * yields a non-empty bodyText for the rule engine + AI, and that link context
 * survives. Run: npx tsx scripts/htmlbody-test.ts <file.eml>
 */
import fs from 'fs';
import { parseRawEml } from '../src/utils/emlParser';
import { runRuleChecks } from '../src/utils/ruleChecks';

const raw = fs.readFileSync(process.argv[2], 'utf8');
const parsed = parseRawEml(raw);

console.log('=== Subject:', parsed.subject);
console.log('=== bodyHtml present:', !!parsed.bodyHtml, `(${(parsed.bodyHtml || '').length} chars)`);
console.log('=== bodyText length:', parsed.bodyText.length);
console.log('--- bodyText sent to AI + rule keyword checks -------------------');
console.log(parsed.bodyText);
console.log('---------------------------------------------------------------');
console.log('=== extractedLinks:');
for (const l of parsed.extractedLinks) {
  console.log(`   text="${l.text}"  href=${l.href}${l.isMismatched ? '  [MISMATCH]' : ''}`);
}

const { ruleScore, triggeredRules } = runRuleChecks(parsed, undefined, {});
console.log(`\n=== ruleScore ${ruleScore} | ${triggeredRules.length} rule(s):`);
for (const t of triggeredRules) console.log(`   +${t.points}  ${t.rule}`);

const kw = ['verify', 'password', 'suspended', 'urgent', '24 hours', 'account will be'];
console.log('\n=== keyword presence in bodyText:');
for (const k of kw) console.log(`   "${k}": ${parsed.bodyText.toLowerCase().includes(k)}`);
