# EmailShield AI — Gmail Quick Scan (Chrome extension)

A deliberately small Manifest V3 extension. When an email is open in Gmail it
injects a floating **Analyze with EmailShield** button; clicking it scrapes the
rendered message (sender, display name, subject, body text, links with both the
shown text and the real `href`) and POSTs it to the existing local backend at
`http://localhost:3000/api/analyze-email` with `bodyOnly: true`. The result is
shown as a compact overlay: fraud score, classification, and the top 3 red flags,
colour-coded green / amber / red.

**View Full Forensic Analysis.** Each analysis is cached server-side under a short
case ID (`EMS-XXXXXX`, 50 most recent). The overlay's link opens
`http://localhost:3000/?case=<id>`; the web app loads that stored result and shows
the full dashboard — with the header-dependent panels (auth results, Received
chain, Origin Trace) in a clear *"Not available — this analysis came from Gmail"*
state, plus a prompt to upload the original `.eml` for full header forensics.

**Scope.** Gmail's DOM exposes only the rendered email, not raw headers, so this
is a *body-and-sender* scan. SPF/DKIM/DMARC and Received-chain forensics stay in
the web app — the overlay says so, and the backend skips the header-dependent
rules for these requests. The extension contains **no detection logic**; it only
scrapes and displays. It never touches the inbox list view.

## Files

| File | Purpose |
|---|---|
| `manifest.json` | MV3 manifest — content script on `mail.google.com`, `localhost:3000` host permission |
| `content.js` / `content.css` | Button injection, DOM scrape, result overlay |
| `background.js` | Service worker — relays the scrape to the backend, returns the verdict (incl. `caseId`) |
| `popup.html` / `popup.js` | Toolbar popup — backend health check + link to the web app |
| `icons/` | Toolbar icons |

## Load it unpacked (for testing)

1. Start the backend: in `emailshield-ai/`, run `npm run dev` (serves on
   `http://localhost:3000`).
2. Open **`chrome://extensions`** in Chrome.
3. Turn on **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select this `extension/` folder.
5. Open **Gmail** (`https://mail.google.com`) and open any email.
6. Click the blue **Analyze with EmailShield** button (bottom-right).
7. In the overlay, click **View Full Forensic Analysis** — the web app opens with
   that analysis populated.
8. If you change any extension file, click the **↻ reload** icon on the
   extension's card in `chrome://extensions`, then reload the Gmail tab.

If the backend is not running, the overlay shows **"EmailShield backend not
running"** with a hint to start it — it never fails silently.
