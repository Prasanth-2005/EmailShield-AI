# EmailShield AI — app

React 19 + Vite 6 frontend and an Express 4 / TypeScript backend (`server.ts`, run directly via `tsx`), plus an optional Python ML microservice (`ml_service/`). See the [repo root README](../README.md) for the full project overview, screenshots, and architecture.

## Prerequisites

- Node.js 18+
- Python 3.10+ (only if you want the local ML engine — the app runs fine without it, just with a 2-engine score blend instead of 3)

## 1. Main app

```
npm install
```

Create `.env` (copy from `.env.example`) and set at minimum:

```
GEMINI_API_KEY=your_key_here
```

Optional environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `GEMINI_MODELS` | Comma-separated Gemini model fallback chain | `gemini-flash-latest,gemini-flash-lite-latest,gemini-3.6-flash` |
| `GEMINI_TIMEOUT_MS` | Per-model request timeout | `45000` |
| `ML_SERVICE_URL` | Where to reach the ML microservice | `http://localhost:8000` |
| `ML_TIMEOUT_MS` | ML request timeout before skipping that engine | `8000` |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_REDIRECT_URI` | Gmail OAuth (Sign in with Google) | — |
| `ABUSEIPDB_API_KEY` | IP reputation lookups | — |
| `VIRUSTOTAL_API_KEY` | On-demand Deep Scan (URLs/attachments) | — |
| `VT_MIN_INTERVAL_MS` | VirusTotal request pacing | `16000` |

RDAP domain-registration lookups and ip-api.com geolocation need no key.

Run it:

```
npm run dev
```

Opens on `http://localhost:3000`.

## 2. ML microservice (optional third engine)

```
cd ml_service
python -m venv .venv
.venv\Scripts\activate      # or: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --port 8000
```

First run downloads the model to the Hugging Face cache. If this service isn't running, the main app detects it (fast timeout, never a crash) and blends `rule × 0.5 + gemini × 0.5` instead of the 3-engine weighting, with a clear "ML layer skipped" note in the UI.

## 3. Chrome extension (optional)

See [`../extension/README.md`](../extension/README.md). Load `../extension/` as an unpacked extension in Chrome for an in-Gmail quick-scan button.

## Production build

```
npm run build
```

Builds the frontend (Vite) and bundles the server (`esbuild server.ts --bundle --platform=node --format=cjs --packages=external`).

## Dev scripts

`scripts/` contains standalone test helpers used during development (RDAP lookups, ML engine e2e, IMAP capability probing, plain-summary jargon checks, etc.) — run any of them with `npx tsx scripts/<name>.ts`.
