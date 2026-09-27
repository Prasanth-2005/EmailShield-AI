/**
 * Three-engine end-to-end. Runs a clear phishing and a clear legitimate email
 * through /api/analyze-email and prints all three sub-scores + the final score.
 * (The Gmail Advanced Scan path calls the same analyzeEmailWithGemini, so this
 * covers both — the Gmail run is done separately in the browser.)
 * Run: npx tsx scripts/ml-e2e.ts
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

async function run(name: string, raw: string) {
  const parsed = parseRawEml(raw);
  const res = await fetch(`${BASE}/api/analyze-email`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ parsedEmail: parsed }),
  });
  const a: any = await res.json();
  const w = a.scoreWeights || {};
  console.log(`\n================  ${name}  ================`);
  console.log(`  Rule engine : ${String(a.ruleScore).padStart(3)}   × ${w.rule}`);
  console.log(`  ML model    : ${a.mlScore == null ? '  – (skipped)' : String(a.mlScore).padStart(3)}   × ${w.ml}` +
    (a.mlModel ? `   [${a.mlModel.label} ${a.mlModel.confidence}%]` : ''));
  console.log(`  Gemini AI   : ${String(a.geminiScore).padStart(3)}   × ${w.gemini}   [engine ${a.engine}]`);
  console.log(`  ---------------------------------`);
  console.log(`  FINAL SCORE : ${a.fraudScore} / 100   =>  ${a.classification}`);
  console.log(`  mlSkipped=${a.mlSkipped}`);
}

await run('CLEAR PHISHING  (.eml upload path)', phish);
await run('CLEAR LEGITIMATE  (.eml upload path)', legit);
