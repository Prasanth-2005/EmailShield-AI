/**
 * Simulates the Chrome extension -> web app handoff end to end:
 *   1. POST a scraped (body-only) email to /api/analyze-email
 *   2. read the returned caseId
 *   3. GET /api/analysis/:caseId and confirm the stored result round-trips
 *   4. GET a bogus caseId and confirm 404
 */

const BASE = 'http://localhost:3000';

const scraped = {
  from: {
    raw: 'PayPal Service <service@paypal-account-alert.com>',
    displayName: 'PayPal Service',
    address: 'service@paypal-account-alert.com',
    domain: 'paypal-account-alert.com',
  },
  to: { raw: '', address: '' },
  subject: 'Confirm your account information',
  date: '',
  returnPath: '',
  replyTo: '',
  messageId: '',
  receivedHops: [],
  authResults: {},
  bodyText:
    'Dear customer, we noticed unusual activity. Please verify your account and confirm your password within 24 hours or it will be suspended.',
  bodyHtml: '',
  extractedLinks: [
    { text: 'https://paypal.com/verify', href: 'https://paypal-account-alert.ru/verify', isMismatched: true, mismatchReason: 'text vs href' },
  ],
  rawHeaders: {},
  rawSource: '',
};

const post = await fetch(`${BASE}/api/analyze-email`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Origin: 'https://mail.google.com' },
  body: JSON.stringify({ parsedEmail: scraped, bodyOnly: true }),
});
const analysis: any = await post.json();
console.log('POST  status        :', post.status);
console.log('      caseId        :', analysis.caseId);
console.log('      classification:', analysis.classification, analysis.fraudScore);
console.log('      analysisScope :', analysis.analysisScope);

const get = await fetch(`${BASE}/api/analysis/${analysis.caseId}`);
const stored: any = await get.json();
console.log('\nGET   status        :', get.status);
console.log('      caseId match  :', stored.caseId === analysis.caseId);
console.log('      has parsedEmail:', !!stored.parsedEmail, '| subject:', stored.parsedEmail?.subject);
console.log('      has analysis   :', !!stored.analysis, '| scope:', stored.analysis?.analysisScope);
console.log('      score matches  :', stored.analysis?.fraudScore === analysis.fraudScore);

const bogus = await fetch(`${BASE}/api/analysis/EMS-000000`);
console.log('\nGET bogus status    :', bogus.status, '(expect 404)');
console.log('    body             :', JSON.stringify(await bogus.json()));
