"""L2 Classifier — DistilBERT-based email phishing/safe classification.

Components:
  - service    : model loading + async classify(body, subject) → L2Result
  - preprocess : email text cleaning and tokenizer-friendly formatting
  - train      : fine-tuning script (run as `python -m app.l2_classifier.train`)

VRAM: ~500 MB (DistilBERT 66M params, FP16)
"""

from app.l2_classifier.service import classify, load_model
from app.l2_classifier.preprocess import clean_email_text, combine_subject_body

__all__ = ["classify", "load_model", "clean_email_text", "combine_subject_body"]

