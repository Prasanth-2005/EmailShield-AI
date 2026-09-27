# EmailShield AI — ML detection microservice

The **third detection engine**. A pretrained BERT phishing classifier
([`ealvaradob/bert-finetuned-phishing`](https://huggingface.co/ealvaradob/bert-finetuned-phishing))
served over HTTP so the Node/Express pipeline can blend it with the rule engine
and Gemini. Independent of both — it never talks to any external API and needs no
key.

## Install & run

```bash
cd ml_service

# 1. create + activate a virtualenv
python -m venv .venv
.venv\Scripts\activate            # Windows PowerShell / cmd
# source .venv/bin/activate       # macOS / Linux

# 2. install (torch is CPU-only by default from PyPI — that is fine)
pip install -r requirements.txt

# 3. run — first launch downloads the model (~440 MB) to the HF cache
uvicorn main:app --host 0.0.0.0 --port 8000
```

The service is ready when the log prints `model ready - id2label=...`.

## Endpoints

| Method | Path        | Body                | Response |
|--------|-------------|---------------------|----------|
| `GET`  | `/health`   | —                   | `{ status, model, id2label }` |
| `POST` | `/classify` | `{ "text": "..." }` | `{ label: "phishing"\|"legitimate", confidence: 0-100, phishing_probability: 0-100 }` |

## How the main app uses it

`server.ts` → `callMlModel(subject + body)` POSTs to `http://localhost:8000/classify`
with an 8 s timeout. If this service is not running the call returns `null`, the
analysis logs `ML layer skipped` and the score falls back to the 50/50
rule + Gemini blend. When the ML result is present the final score is
`ruleScore·0.35 + mlScore·0.30 + geminiScore·0.35`.

Override the URL/timeout with `ML_SERVICE_URL` / `ML_TIMEOUT_MS` in the app `.env`.
