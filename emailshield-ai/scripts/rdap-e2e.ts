/**
 * End-to-end: run two emails through /api/analyze-email and show the domain-intel
 * block, the triggered rules and the score composition.
 * Run: npx tsx scripts/rdap-e2e.ts
 */
import { parseRawEml } from '../src/utils/emlParser';

const BASE = 'http://localhost:3000';

const phish = `Return-Path: <bounce@paypal-account-verify.com>
Received: from mail.paypal-account-verify.com (mail.paypal-account-verify.com [203.0.113.9])
	by mx.example.com (Postfix) with ESMTPS id 11AA22BB
	for <victim@example.com>; Mon, 8 Sep 2026 12:00:00 +0000 (UTC)
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
From: "PayPal Service" <alerts@paypal-account-verify.com>
To: victim@example.com
Subject: Confirm your account details
Date: Mon, 8 Sep 2026 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body><p>Please <a href="https://paypal-account-verify.com/login">confirm your account</a> now.</p></body></html>
`;

const legit = `Return-Path: <noreply@google.com>
Received: from mail-sor.google.com (mail-sor.google.com [209.85.220.41])
	by mx.example.com (Postfix) with ESMTPS id 33CC44DD
	for <user@example.com>; Mon, 8 Sep 2026 12:05:00 +0000 (UTC)
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
From: "Google" <no-reply@google.com>
To: user@example.com
Subject: Security alert
Date: Mon, 8 Sep 2026 12:05:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

A new sign-in to your Google Account. If this was you, no action is needed.
`;

async function run(name: string, raw: string) {
  const parsed = parseRawEml(raw);
  const res = await fetch(`${BASE}/api/analyze-email`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ parsedEmail: parsed }),
  });
  const a: any = await res.json();
  console.log(`\n================  ${name}  ================`);
  console.log(`classification     : ${a.classification}   fraudScore ${a.fraudScore}  (rule ${a.ruleScore} / gemini ${a.geminiScore})`);
  console.log(`engine             : ${a.engine}`);
  console.log('domainIntel        :');
  for (const e of a.domainIntel?.entries || []) {
    console.log(
      `   [${e.role}] ${e.domain} -> ${e.status}` +
        (e.status === 'ok'
          ? `  age ${e.ageDays}d  registered ${e.registeredAt?.slice(0, 10)}  expires ${e.expiresAt?.slice(0, 10) || '-'}  registrar "${e.registrar || '-'}"`
          : `  (${e.message})`),
    );
  }
  console.log(`   sendingMinAgeDays=${a.domainIntel?.sendingMinAgeDays}  youngest=${a.domainIntel?.sendingYoungestDomain}`);
  console.log('triggered rules    :');
  for (const r of a.triggeredRules || []) console.log(`   +${r.points}  [${r.category}]  ${r.rule}`);
}

await run('PHISH  (From = paypal-account-verify.com)', phish);
await run('LEGIT  (From = google.com)', legit);
