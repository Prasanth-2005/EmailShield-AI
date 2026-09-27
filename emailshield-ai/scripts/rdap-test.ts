/**
 * Domain-intel checks. Direct RDAP probe for a set of domains, then the full
 * pipeline on a synthetic phish whose From domain is passed on argv[2].
 * Run: npx tsx scripts/rdap-test.ts [freshDomain]
 */
import { checkDomainIntel, buildDomainIntelReport } from '../src/utils/threatIntel';
import { runRuleChecks } from '../src/utils/ruleChecks';

const probe = [
  'google.com',
  'github.com',
  'sbi.co.in',
  'nic.in',
  'this-domain-almost-certainly-does-not-exist-9x7q2.com',
];
if (process.argv[2]) probe.push(process.argv[2]);

console.log('=== Direct checkDomainIntel ===');
for (const d of probe) {
  const r = await checkDomainIntel(d);
  console.log(
    `  ${d.padEnd(52)} status=${r.status}` +
      (r.status === 'ok'
        ? `  age=${r.ageDays}d  registered=${r.registeredAt?.slice(0, 10)}  expires=${r.expiresAt?.slice(0, 10) || '-'}  registrar=${r.registrar || '-'}`
        : `  (${r.message})`),
  );
}

// --- rule behaviour for a few synthetic ages ---
console.log('\n=== Rule behaviour by domain age ===');
for (const age of [5, 45, 200, undefined]) {
  const parsed: any = {
    from: { domain: 'example.test', address: 'x@example.test', displayName: 'X', raw: '' },
    to: { address: '' }, subject: 'hi', date: '', returnPath: '', replyTo: '', messageId: '',
    receivedHops: [], authResults: {}, bodyText: '', extractedLinks: [], attachments: [],
    rawHeaders: {}, rawSource: '',
  };
  const { ruleScore, triggeredRules } = runRuleChecks(parsed, {
    originGeo: null, originCountryCode: null,
    domainMinAgeDays: age as any, domainAgeDomain: 'example.test',
  });
  const di = triggeredRules.filter((r) => r.category === 'Domain Intelligence');
  console.log(`  age=${String(age).padEnd(9)} ruleScore=${ruleScore}  domain-rules=[${di.map((r) => `${r.rule} +${r.points}`).join(', ') || 'none'}]`);
}

// --- full report builder on a synthetic phish ---
console.log('\n=== buildDomainIntelReport (From + Return-Path + deceptive link) ===');
const email: any = {
  from: { domain: process.argv[2] || 'paypal-account-verify.com', address: `alerts@${process.argv[2] || 'paypal-account-verify.com'}` },
  returnPath: `bounce@${process.argv[2] || 'mailer-x9.net'}`,
  extractedLinks: [
    { text: 'https://paypal.com/login', href: 'https://secure-paypal-login.top/verify', isMismatched: true },
    { text: 'unsubscribe', href: 'https://paypal-account-verify.com/u', isMismatched: false },
  ],
};
const report = await buildDomainIntelReport(email);
console.log(JSON.stringify(report, null, 2));
