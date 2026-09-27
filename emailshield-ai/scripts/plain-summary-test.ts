/**
 * Checks the plain-English "What does this mean?" summary on a clear phishing
 * email and a clear legitimate email. Flags any jargon that slipped through.
 * Run: npx tsx scripts/plain-summary-test.ts
 */
import { parseRawEml } from '../src/utils/emlParser';

const BASE = 'http://localhost:3000';

const phish = `Return-Path: <bounce@paypal-account-verify.com>
Received: from mail.paypal-account-verify.com (mail.paypal-account-verify.com [203.0.113.9])
	by mx.example.com (Postfix) with ESMTPS id 11AA22BB
	for <victim@example.com>; Tue, 9 Sep 2026 09:00:00 +0000 (UTC)
Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail
From: "PayPal Security" <alerts@paypal-account-verify.com>
To: victim@example.com
Subject: URGENT: Your account has been limited - verify within 24 hours
Date: Tue, 9 Sep 2026 09:00:00 +0000
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body><p>We detected unusual activity. You must <b>verify your identity</b> and
confirm your password immediately or your account will be permanently suspended.</p>
<p><a href="https://paypal-account-verify.com/login">https://www.paypal.com/signin</a></p>
<p>Failure to act within 24 hours will result in termination.</p></body></html>
`;

const legit = `Return-Path: <bounce@github.com>
Received: from out-1.smtp.github.com (out-1.smtp.github.com [140.82.112.3])
	by mx.example.com (Postfix) with ESMTPS id 55DD66EE
	for <dev@example.com>; Tue, 9 Sep 2026 09:05:00 +0000 (UTC)
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
From: "GitHub" <noreply@github.com>
To: dev@example.com
Subject: [GitHub] A third-party OAuth application has been added to your account
Date: Tue, 9 Sep 2026 09:05:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hey there! A third-party OAuth application (Vercel) with read:user and repo scopes
was recently authorized to access your account. Visit your account settings to review.
If this was you, no action is needed.
`;

const JARGON = [
  'spf', 'dkim', 'dmarc', 'spoof', 'phishing', 'header', 'authentication', 'domain',
  ' ip ', 'payload', 'credential', 'mime', 'received chain', 'relay', 'tls',
];

async function run(name: string, raw: string) {
  const parsed = parseRawEml(raw);
  const res = await fetch(`${BASE}/api/analyze-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ parsedEmail: parsed }),
  });
  const a: any = await res.json();
  console.log(`\n================  ${name}  ================`);
  console.log(`classification : ${a.classification}   fraudScore ${a.fraudScore}   engine ${a.engine}`);
  console.log(`plainSummary   :\n  ${a.plainSummary}`);
  const lower = ` ${String(a.plainSummary || '').toLowerCase()} `;
  const hits = JARGON.filter((j) => lower.includes(j));
  console.log(`jargon check   : ${hits.length ? 'FOUND -> ' + hits.join(', ') : 'clean (no jargon)'}`);
  const sentences = String(a.plainSummary || '').split(/(?<=[.!?])\s+/).filter(Boolean).length;
  console.log(`sentence count : ${sentences}  (target 2-4)`);
}

await run('CLEAR PHISHING', phish);
await run('CLEAR LEGITIMATE', legit);
