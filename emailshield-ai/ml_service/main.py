"""
EmailShield AI - local ML detection microservice.

The third detection engine. Serves a pretrained BERT phishing classifier
(``ealvaradob/bert-finetuned-phishing``) over one HTTP endpoint so the
Node / Express analysis pipeline can blend its verdict with the deterministic
rule engine and the Gemini judgment.

The model is downloaded from the Hugging Face Hub on first run (~440 MB) and is
loaded into memory once, at startup - never per request.

Run:
    python -m venv .venv
    .venv\\Scripts\\activate        # Windows      (source .venv/bin/activate on macOS/Linux)
    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import torch
from fastapi import FastAPI
from pydantic import BaseModel, Field
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_ID = "ealvaradob/bert-finetuned-phishing"
MAX_TOKENS = 512

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("emailshield-ml")

# Loaded once in the lifespan handler below and read on every request.
STATE: dict = {}


def _phishing_index(id2label: dict) -> int:
    """Index of the 'phishing' class, robust to how the model names its labels."""
    for idx, label in (id2label or {}).items():
        name = str(label).lower()
        if "phish" in name or "malicious" in name or "spam" in name:
            return int(idx)
    # Binary phishing classifiers conventionally use index 1 as the positive class.
    return 1 if len(id2label or {}) > 1 else 0


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("loading model %s ...", MODEL_ID)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)
    model.eval()
    id2label = getattr(model.config, "id2label", {}) or {}
    STATE.update(
        tokenizer=tokenizer,
        model=model,
        id2label=id2label,
        phishing_index=_phishing_index(id2label),
    )
    log.info("model ready - id2label=%s  phishing_index=%s", id2label, STATE["phishing_index"])
    yield
    STATE.clear()


app = FastAPI(title="EmailShield ML Service", version="1.0.0", lifespan=lifespan)


class ClassifyRequest(BaseModel):
    text: str = Field(default="", description="Email subject + body to classify")


class ClassifyResponse(BaseModel):
    label: str  # "phishing" | "legitimate"
    confidence: float  # 0-100, confidence in `label`
    phishing_probability: float  # 0-100, P(phishing) - convenience for the caller


@app.get("/health")
def health():
    return {
        "status": "ok" if STATE.get("model") is not None else "loading",
        "model": MODEL_ID,
        "id2label": STATE.get("id2label", {}),
    }


@app.post("/classify", response_model=ClassifyResponse)
def classify(req: ClassifyRequest) -> ClassifyResponse:
    text = (req.text or "").strip()
    if not text or STATE.get("model") is None:
        return ClassifyResponse(label="legitimate", confidence=0.0, phishing_probability=0.0)

    tokenizer = STATE["tokenizer"]
    model = STATE["model"]
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=MAX_TOKENS)
    with torch.no_grad():
        logits = model(**inputs).logits
    probs = torch.softmax(logits, dim=-1)[0]
    phishing_prob = float(probs[STATE["phishing_index"]])

    label = "phishing" if phishing_prob >= 0.5 else "legitimate"
    confidence = phishing_prob if label == "phishing" else 1.0 - phishing_prob
    return ClassifyResponse(
        label=label,
        confidence=round(confidence * 100, 1),
        phishing_probability=round(phishing_prob * 100, 1),
    )
