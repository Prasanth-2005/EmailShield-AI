/**
 * EmailShield AI — background service worker
 *
 * The only job here is to relay the scraped email from the content script to the
 * local backend and hand the result back. Doing the fetch from the worker (which
 * holds the `http://localhost:3000/*` host permission) keeps it clear of the
 * Gmail page's own network restrictions.
 *
 * No detection logic lives in the extension — POST to /api/analyze-email and
 * return whatever it says.
 */

const BACKEND = 'http://localhost:3000';

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'EMAILSHIELD_ANALYZE') {
    analyze(message.parsedEmail).then(sendResponse);
    return true; // keep the message channel open for the async response
  }
  if (message?.type === 'EMAILSHIELD_HEALTH') {
    health().then(sendResponse);
    return true;
  }
  return false;
});

async function analyze(parsedEmail) {
  try {
    const res = await fetch(`${BACKEND}/api/analyze-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ parsedEmail, bodyOnly: true }),
    });

    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try {
        const body = await res.json();
        if (body?.error) detail = body.error;
      } catch {
        /* ignore parse error */
      }
      return { ok: false, reason: 'backend-error', message: detail };
    }

    const data = await res.json();
    return { ok: true, data };
  } catch (err) {
    // TypeError: Failed to fetch  ->  server not running / not reachable
    return { ok: false, reason: 'unreachable', message: String(err && err.message ? err.message : err) };
  }
}

async function health() {
  try {
    const res = await fetch(`${BACKEND}/api/health`, { method: 'GET' });
    return { ok: res.ok };
  } catch {
    return { ok: false };
  }
}
