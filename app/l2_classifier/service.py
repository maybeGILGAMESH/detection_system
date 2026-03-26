"""L2 Classifier — DistilBERT-based phishing/safe email classifier."""

import asyncio
import logging
from pathlib import Path

import torch
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification

from app.config import settings
from app.schemas import L2Result, Label
from app.l2_classifier.preprocess import combine_subject_body

logger = logging.getLogger(__name__)

# Module-level model cache (loaded once)
_tokenizer = None
_model = None
_device = None


def load_model() -> None:
    """Load the DistilBERT model and tokenizer into GPU memory."""
    global _tokenizer, _model, _device

    if _model is not None:
        return

    # Prefer fine-tuned model; fall back to base
    model_path = settings.l2_finetuned_model_path
    if not Path(model_path).exists():
        model_path = settings.distilbert_model_path
        logger.warning(
            "Fine-tuned model not found at %s, using base model from %s. "
            "Run training first for accurate results.",
            settings.l2_finetuned_model_path,
            model_path,
        )

    _device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info("Loading L2 DistilBERT from %s on %s", model_path, _device)

    _tokenizer = DistilBertTokenizer.from_pretrained(model_path)
    _model = DistilBertForSequenceClassification.from_pretrained(
        model_path,
        num_labels=2,
        ignore_mismatched_sizes=True,
    )
    _model.to(_device)
    _model.eval()
    logger.info("L2 model loaded. VRAM ≈ %.1f MB", torch.cuda.memory_allocated() / 1e6 if torch.cuda.is_available() else 0)


def _classify_sync(text: str) -> L2Result:
    """Run torch inference (blocking) — called via asyncio.to_thread."""
    inputs = _tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True,
    )
    inputs = {k: v.to(_device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = _model(**inputs)
        logits = outputs.logits

        temperature = settings.l2_temperature
        scaled_logits = logits / temperature if temperature != 1.0 else logits
        probs = torch.softmax(scaled_logits, dim=-1)

    safe_prob = probs[0][0].item()
    phish_prob = probs[0][1].item()

    raw_probs = torch.softmax(logits, dim=-1)
    raw_safe = raw_probs[0][0].item()

    label = Label.SAFE if safe_prob >= 0.5 else Label.PHISHING
    confidence = safe_prob

    logger.info(
        "L2 classify: safe=%.3f, phish=%.3f (raw_safe=%.3f, T=%.1f) → %s",
        safe_prob, phish_prob, raw_safe, temperature, label,
    )
    return L2Result(confidence=confidence, label=label)


async def classify(body: str, subject: str = "") -> L2Result:
    """Classify an email as phishing or safe.

    Returns:
        L2Result with confidence (0.0=phishing, 1.0=safe) and label.
    """
    if _model is None:
        load_model()

    text = combine_subject_body(subject, body)
    if not text.strip():
        return L2Result(confidence=0.5, label=Label.SAFE)

    return await asyncio.to_thread(_classify_sync, text)

