/**
 * EmailShield AI — Gmail content script
 *
 * Scope (deliberately small):
 *  - Only acts when a single email/thread is OPEN in Gmail.
 *  - Injects one floating "Analyze with EmailShield" button.
 *  - On click: scrapes sender + subject + body + links from the rendered DOM,
 *    sends them to the local backend via the background worker, and shows a
 *    compact result overlay.
 *  - Never touches the inbox list view. No detection logic — the backend decides.
 *
 * Gmail exposes only the rendered message, not raw headers, so this is a
 * body-and-sender scan. The overlay says so explicitly.
 */

(() => {
  'use strict';

  const WEB_APP_URL = 'http://localhost:3000';
  const FAB_ID = 'emailshield-fab';
  const OVERLAY_ID = 'emailshield-overlay';

  // ---------------------------------------------------------------------------
  // Detect whether an email is currently open
  // ---------------------------------------------------------------------------
  function openEmailRoot() {
    // h2.hP = the conversation subject heading, only rendered in the open view.
    const subject = document.querySelector('h2.hP');
    const body = document.querySelector('.a3s');
    if (subject && body) return document.querySelector('div[role="main"]') || document.body;
    return null;
  }

  // ---------------------------------------------------------------------------
  // Floating action button
  // ---------------------------------------------------------------------------
  function ensureFab() {
    let fab = document.getElementById(FAB_ID);
    if (!fab) {
      fab = document.createElement('button');
      fab.id = FAB_ID;
      fab.type = 'button';
      fab.innerHTML =
        '<span class="es-fab-dot"></span><span class="es-fab-label">Analyze with EmailShield</span>';
      fab.addEventListener('click', onAnalyzeClick);
      document.body.appendChild(fab);
    }
    return fab;
  }

  function syncFab() {
    try {
      const fab = ensureFab();
      fab.classList.toggle('es-hidden', !openEmailRoot());
    } catch (err) {
      // Never let a DOM race in Gmail's SPA crash the observer/interval loop.
      console.warn('[EmailShield] syncFab skipped:', err);
    }
  }

  // ---------------------------------------------------------------------------
  // Scraping
  // ---------------------------------------------------------------------------
  function unwrapGoogleRedirect(href) {
    try {
      const u = new URL(href, location.href);
      if (u.hostname === 'www.google.com' && u.pathname === '/url') {
        return u.searchParams.get('q') || u.searchParams.get('url') || href;
      }
      return href;
    } catch {
      return href;
    }
  }

  function domainOf(url) {
    try {
      return new URL(url).hostname.replace(/^www\./, '').toLowerCase();
    } catch {
      return '';
    }
  }

  function looksMismatched(text, href) {
    const t = (text.match(/https?:\/\/[^\s)]+/i) || [])[0];
    if (!t) return { mismatched: false };
    const shown = domainOf(t);
    const real = domainOf(href);
    if (!shown || !real) return { mismatched: false };
    if (real === shown || real.endsWith('.' + shown) || shown.endsWith('.' + real)) {
      return { mismatched: false };
    }
    return {
      mismatched: true,
      reason: `Link text shows "${shown}" but the actual destination is "${real}".`,
    };
  }

  /** Resolve the sender of the message currently being read — null-safe. */
  function scrapeSender() {
    // span.gD carries the sender's name/email in the message header. In a thread
    // the last one is the message on screen. Recipients use different classes.
    const gd = document.querySelectorAll('span.gD');
    for (let i = gd.length - 1; i >= 0; i--) {
      const email = (gd[i].getAttribute('email') || '').trim().toLowerCase();
      if (email.includes('@')) {
        return { address: email, displayName: (gd[i].getAttribute('name') || gd[i].textContent || '').trim() };
      }
    }
    // Fallbacks: any element carrying an [email] attr, then a raw address in the header.
    const anyEmail = document.querySelector('.gE [email], [email]');
    const attr = (anyEmail && anyEmail.getAttribute('email') || '').trim().toLowerCase();
    if (attr.includes('@')) {
      return { address: attr, displayName: (anyEmail.getAttribute('name') || anyEmail.textContent || '').trim() };
    }
    const headerScope = document.querySelector('.gE') || document.querySelector('.ha') || document.body;
    const m = (headerScope.textContent || '').match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
    return { address: m ? m[0].toLowerCase() : '', displayName: '' };
  }

  function scrapeOpenEmail() {
    const subjectEl = document.querySelector('h2.hP');
    const subject = (subjectEl && subjectEl.textContent || '').trim() || '(no subject)';

    const { address, displayName } = scrapeSender();

    const bodies = document.querySelectorAll('.a3s, .ii .a3s, div[data-message-id] .a3s');
    const bodyEl = bodies[bodies.length - 1] || null;
    const bodyText = bodyEl ? (bodyEl.innerText || bodyEl.textContent || '').trim().slice(0, 20000) : '';

    if (!address && !bodyText) {
      throw new Error('Could not read the open message — open a single email fully, then try again.');
    }

    const extractedLinks = [];
    const seen = new Set();
    if (bodyEl) {
      bodyEl.querySelectorAll('a[href]').forEach((a) => {
        let href = unwrapGoogleRedirect(a.getAttribute('href') || a.href || '');
        if (!href || href.startsWith('#') || /^(mailto:|javascript:|tel:)/i.test(href)) return;
        const text = (a.textContent || '').trim() || href;
        const key = text + '|' + href;
        if (seen.has(key)) return;
        seen.add(key);
        const m = looksMismatched(text, href);
        extractedLinks.push({
          text,
          href,
          isMismatched: m.mismatched,
          mismatchReason: m.reason,
        });
      });
    }

    return {
      // Partial ParsedEmail — headers are intentionally empty (see note in overlay).
      from: {
        raw: displayName ? `${displayName} <${address}>` : address,
        displayName: displayName || address || '(unknown sender)',
        address,
        domain: address.includes('@') ? address.split('@')[1] : '',
      },
      to: { raw: '', address: '' },
      subject,
      date: '',
      returnPath: '',
      replyTo: '',
      messageId: '',
      receivedHops: [],
      authResults: {},
      bodyText,
      bodyHtml: '',
      extractedLinks,
      rawHeaders: {},
      rawSource: '',
    };
  }

  // ---------------------------------------------------------------------------
  // Overlay
  // ---------------------------------------------------------------------------
  function ensureOverlay() {
    let el = document.getElementById(OVERLAY_ID);
    if (!el) {
      el = document.createElement('div');
      el.id = OVERLAY_ID;
      document.body.appendChild(el);
    }
    el.classList.remove('es-hidden');
    return el;
  }

  function closeOverlay() {
    const el = document.getElementById(OVERLAY_ID);
    if (el) el.classList.add('es-hidden');
  }

  function shell(innerHtml, fullLinkUrl) {
    const el = ensureOverlay();
    el.innerHTML = `
      <div class="es-head">
        <div class="es-brand">EmailShield&nbsp;AI <span class="es-tag">Quick Scan</span></div>
        <button type="button" class="es-close" aria-label="Close">&times;</button>
      </div>
      <div class="es-body">${innerHtml}</div>
      <div class="es-foot">
        Body &amp; sender analysis only — SPF/DKIM/DMARC and routing forensics are
        not available from Gmail. <a class="es-link" href="${escapeAttr2(fullLinkUrl || WEB_APP_URL)}" target="_blank" rel="noopener">View Full Forensic Analysis &#8599;</a>
      </div>`;
    el.querySelector('.es-close').addEventListener('click', closeOverlay);
    return el;
  }

  function renderLoading() {
    shell('<div class="es-loading"><span class="es-spinner"></span> Analyzing this message…</div>');
  }

  function renderError(reason, message) {
    let headline = 'EmailShield could not analyze this message';
    let hint = 'The backend responded with an error.';
    if (reason === 'unreachable') {
      headline = 'EmailShield backend not running';
      hint = 'Start it with <code>npm run dev</code> in the <code>emailshield-ai</code> folder, then try again.';
    } else if (reason === 'scrape') {
      headline = 'Could not read this email';
      hint = 'Open a single email fully (not the list view), wait for it to load, then click again.';
    } else if (reason === 'render') {
      headline = 'EmailShield hit an error showing the result';
      hint = 'The analysis ran but the overlay could not render it. Details below.';
    }
    shell(
      `<div class="es-error">
         <div class="es-error-title">${headline}</div>
         <div class="es-error-hint">${hint}</div>
         ${message ? `<div class="es-error-detail">${escapeHtml(message)}</div>` : ''}
       </div>`,
    );
  }

  const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function renderResult(data) {
    const score = clampInt(data.fraudScore);
    const band = score > 70 ? 'red' : score >= 40 ? 'amber' : 'green';
    const classification = data.classification || '—';
    const engine = data.engine || 'unknown';
    const scopeNote =
      data.analysisScope === 'body-and-sender' || data.analysisScope === undefined
        ? 'Scored without header/auth signals.'
        : '';

    const flags = Array.isArray(data.redFlags) ? [...data.redFlags] : [];
    flags.sort((a, b) => (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5));
    const top = flags.slice(0, 3);

    const flagsHtml = top.length
      ? top
          .map(
            (f) => `
        <li class="es-flag es-flag-${escapeAttr(f.severity || 'info')}">
          <div class="es-flag-title">${escapeHtml(f.title || 'Flag')}</div>
          <div class="es-flag-desc">${escapeHtml(truncate(f.description || '', 160))}</div>
        </li>`,
          )
          .join('')
      : '<li class="es-flag es-flag-info"><div class="es-flag-title">No specific red flags returned</div></li>';

    const fullLink = data.caseId
      ? `${WEB_APP_URL}/?case=${encodeURIComponent(data.caseId)}`
      : WEB_APP_URL;

    shell(
      `
      <div class="es-score-row es-${band}">
        <div class="es-score">${score}<span>/100</span></div>
        <div class="es-verdict">
          <div class="es-class">${escapeHtml(classification)}</div>
          <div class="es-engine">engine: ${escapeHtml(engine)}${scopeNote ? ' · ' + scopeNote : ''}</div>
        </div>
      </div>
      <div class="es-flags-label">Top red flags</div>
      <ul class="es-flags">${flagsHtml}</ul>
    `,
      fullLink,
    );
  }

  // ---------------------------------------------------------------------------
  // Click handler
  // ---------------------------------------------------------------------------
  let inFlight = false;
  function onAnalyzeClick() {
    if (inFlight) return;
    if (!openEmailRoot()) return;
    inFlight = true;
    renderLoading();

    let parsedEmail;
    try {
      parsedEmail = scrapeOpenEmail();
    } catch (err) {
      inFlight = false;
      console.warn('[EmailShield] scrape failed:', err);
      renderError('scrape', String(err && err.message ? err.message : err));
      return;
    }

    try {
      chrome.runtime.sendMessage({ type: 'EMAILSHIELD_ANALYZE', parsedEmail }, (resp) => {
        inFlight = false;
        try {
          if (chrome.runtime.lastError || !resp) {
            renderError('unreachable', chrome.runtime.lastError && chrome.runtime.lastError.message);
            return;
          }
          if (!resp.ok) {
            renderError(resp.reason || 'backend-error', resp.message);
            return;
          }
          renderResult(resp.data || {});
        } catch (err) {
          console.warn('[EmailShield] render failed:', err);
          renderError('render', String(err && err.message ? err.message : err));
        }
      });
    } catch (err) {
      inFlight = false;
      console.warn('[EmailShield] sendMessage failed:', err);
      renderError('unreachable', String(err && err.message ? err.message : err));
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------
  function clampInt(n) {
    const v = Number(n);
    if (!isFinite(v)) return 0;
    return Math.max(0, Math.min(100, Math.round(v)));
  }
  function truncate(s, n) {
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function escapeAttr(s) {
    return String(s).replace(/[^a-z0-9_-]/gi, '');
  }
  function escapeAttr2(s) {
    // for URLs placed in an href attribute
    return String(s).replace(/"/g, '%22').replace(/</g, '%3C').replace(/>/g, '%3E');
  }

  // ---------------------------------------------------------------------------
  // Lifecycle — keep the button in sync with Gmail's SPA navigation
  // ---------------------------------------------------------------------------
  let debounce;
  function scheduleSync() {
    clearTimeout(debounce);
    debounce = setTimeout(syncFab, 250);
  }

  const observer = new MutationObserver(scheduleSync);
  observer.observe(document.body, { childList: true, subtree: true });
  window.addEventListener('hashchange', scheduleSync);
  setInterval(syncFab, 1500);
  syncFab();
})();
