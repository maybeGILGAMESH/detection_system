"""Training script for L2 DistilBERT classifier.

Fine-tunes distilbert-base-multilingual-cased on phishing email dataset.
Run standalone:
    python -m app.l2_classifier.train
"""

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

import pandas as pd
import torch
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset
from transformers import (
    DistilBertForSequenceClassification,
    DistilBertTokenizer,
    Trainer,
    TrainingArguments,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RANDOM_STATE = 42


# Dataset

class EmailDataset(Dataset):
    """PyTorch Dataset for email classification."""

    def __init__(self, texts: list[str], labels: list[int], tokenizer, max_length: int = 512):
        self.encodings = tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=max_length,
            return_tensors="pt",
        )
        self.labels = torch.tensor(labels, dtype=torch.long)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        item = {k: v[idx] for k, v in self.encodings.items()}
        item["labels"] = self.labels[idx]
        return item


# Data Loading

def load_data(dataset_path: str) -> tuple[list[str], list[int]]:
    """Load and merge all available text datasets.

    Loads (when present):
      1. phishing_emails/Phishing_Email.csv  (EN phishing + safe)
      2. enron/emails.csv                    (EN safe, max 10K)
      3. russian-spam-detection/processed_combined.parquet  (RU, sampled 30K)
      4. telegram_spam_cleaned.csv           (RU spam supplement)

    Labels: 0 = safe, 1 = phishing/spam
    """
    dataset_dir = Path(dataset_path)
    texts = []
    labels = []

    # --- 1. Kaggle Phishing Email Dataset ---
    phish_csv = dataset_dir / "phishing_emails" / "Phishing_Email.csv"
    if phish_csv.exists():
        logger.info("Loading phishing dataset from %s", phish_csv)
        df = pd.read_csv(phish_csv)

        text_col = None
        label_col = None
        for col in df.columns:
            cl = col.lower().strip()
            if cl in ("email_text", "text", "body", "email text", "email"):
                text_col = col
            if cl in ("email_type", "label", "class", "email type"):
                label_col = col

        if text_col and label_col:
            before = len(texts)
            for _, row in df.iterrows():
                text = str(row[text_col]).strip()
                raw_label = str(row[label_col]).strip().lower()

                if not text or text == "nan":
                    continue

                if raw_label in ("phishing email", "phishing", "1", "spam", "phish"):
                    labels.append(1)
                    texts.append(text[:2000])
                elif raw_label in ("safe email", "safe", "0", "ham", "legitimate"):
                    labels.append(0)
                    texts.append(text[:2000])
            logger.info("  -> %d samples from phishing CSV", len(texts) - before)
        else:
            logger.warning("Could not identify columns in %s: %s", phish_csv, list(df.columns))

    # --- 2. Enron Dataset (legitimate emails) ---
    enron_csv = dataset_dir / "enron" / "emails.csv"
    if enron_csv.exists():
        logger.info("Loading Enron dataset from %s", enron_csv)
        enron_df = pd.read_csv(enron_csv, nrows=10_000)

        msg_col = None
        for col in enron_df.columns:
            if col.lower() in ("message", "content", "body", "text", "email"):
                msg_col = col
                break

        if msg_col:
            count = 0
            for _, row in enron_df.iterrows():
                text = str(row[msg_col]).strip()
                if not text or text == "nan" or len(text) < 20:
                    continue
                texts.append(text[:2000])
                labels.append(0)
                count += 1
            logger.info("  -> %d Enron samples (safe)", count)

    # --- 3. Russian Spam Detection (HuggingFace, parquet) ---
    ru_parquet = dataset_dir / "russian-spam-detection" / "processed_combined.parquet"
    if ru_parquet.exists():
        logger.info("Loading Russian Spam Detection from %s", ru_parquet)
        rdf = pd.read_parquet(ru_parquet)
        spam = rdf[rdf["label"] == 1].sample(
            n=min(15_000, len(rdf[rdf["label"] == 1])), random_state=RANDOM_STATE,
        )
        ham = rdf[rdf["label"] == 0].sample(
            n=min(15_000, len(rdf[rdf["label"] == 0])), random_state=RANDOM_STATE,
        )
        count = 0
        for _, row in pd.concat([spam, ham]).iterrows():
            text = str(row["message"]).strip()
            if not text or text == "nan" or len(text) < 10:
                continue
            texts.append(text[:2000])
            labels.append(int(row["label"]))
            count += 1
        logger.info("  -> %d RU spam samples (15K spam + 15K safe sampled)", count)

    # --- 4. Telegram Spam ---
    tg_csv = dataset_dir / "telegram_spam_cleaned.csv"
    if tg_csv.exists():
        logger.info("Loading Telegram spam from %s", tg_csv)
        tdf = pd.read_csv(tg_csv)
        count = 0
        for _, row in tdf.iterrows():
            text = str(row.get("text", "")).strip()
            raw_label = str(row.get("label", "")).strip().lower()
            if not text or text == "nan":
                continue
            lbl = 1 if raw_label in ("spam", "1") else 0
            texts.append(text[:2000])
            labels.append(lbl)
            count += 1
        logger.info("  -> %d Telegram samples", count)

    if not texts:
        raise ValueError(
            f"No data loaded from {dataset_dir}. "
            "Expected at least one of: phishing_emails/, enron/, "
            "russian-spam-detection/, telegram_spam_cleaned.csv"
        )

    # --- Deduplication ---
    seen = set()
    dedup_texts = []
    dedup_labels = []
    for t, l in zip(texts, labels):
        h = hashlib.md5(t.encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            dedup_texts.append(t)
            dedup_labels.append(l)

    dupes = len(texts) - len(dedup_texts)
    if dupes:
        logger.info("Removed %d duplicate texts", dupes)
    texts, labels = dedup_texts, dedup_labels

    logger.info("Total dataset: %d samples (safe=%d, phishing=%d)",
                len(texts), labels.count(0), labels.count(1))
    return texts, labels


def _save_split_manifest(output_dir: str, train_texts: list[str], val_texts: list[str],
                         train_labels: list[int], val_labels: list[int]):
    """Save train/eval split hashes so eval_l2.py can reproduce the exact held-out set."""
    manifest = {
        "train_hashes": [hashlib.md5(t.encode()).hexdigest() for t in train_texts],
        "val_hashes": [hashlib.md5(t.encode()).hexdigest() for t in val_texts],
        "train_labels": train_labels,
        "val_labels": val_labels,
        "train_size": len(train_texts),
        "val_size": len(val_texts),
    }
    path = Path(output_dir) / "split_manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    logger.info("Split manifest saved to %s (%d train, %d val)",
                path, len(train_texts), len(val_texts))


# Training

def train(
    dataset_path: str = "./datasets",
    model_name: str = "./models/distilbert-base-multilingual-cased",
    output_dir: str = "./models/l2_finetuned",
    epochs: int = 3,
    batch_size: int = 16,
    learning_rate: float = 2e-5,
    test_size: float = 0.15,
):
    """Fine-tune DistilBERT for binary phishing classification."""

    logger.info("L2 DistilBERT Training")
    logger.info("Base model: %s", model_name)
    logger.info("Output: %s", output_dir)

    # Load data
    texts, labels = load_data(dataset_path)

    # Split
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=test_size, random_state=RANDOM_STATE, stratify=labels,
    )
    logger.info("Train: %d, Val: %d", len(train_texts), len(val_texts))

    _save_split_manifest(output_dir, train_texts, val_texts, train_labels, val_labels)

    # Tokenizer & model
    tokenizer = DistilBertTokenizer.from_pretrained(model_name)
    model = DistilBertForSequenceClassification.from_pretrained(
        model_name,
        num_labels=2,
        ignore_mismatched_sizes=True,
    )

    # Datasets
    train_ds = EmailDataset(train_texts, train_labels, tokenizer)
    val_ds = EmailDataset(val_texts, val_labels, tokenizer)

    # Training args
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_steps=50,
        learning_rate=learning_rate,
        weight_decay=0.01,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        fp16=torch.cuda.is_available(),
        report_to="none",
    )

    # Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
    )

    # Train!
    logger.info("Starting training...")
    trainer.train()

    # Save
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    logger.info("Model saved to %s", output_dir)

    # Evaluate
    metrics = trainer.evaluate()
    logger.info("Final eval metrics: %s", metrics)

    return metrics


# CLI

def incremental_train(csv_path: str, output_dir: str = "./models/l2_finetuned"):
    """Incrementally fine-tune L2 model on operator-labeled data.

    Args:
        csv_path: Path to CSV with columns: text, label (0=safe, 1=phishing).
        output_dir: Output directory (overwrites existing finetuned model).
    """
    logger.info("Incremental retraining from %s", csv_path)

    df = pd.read_csv(csv_path)
    if len(df) < 3:
        logger.error("Not enough data for retraining (need at least 3 samples)")
        return

    texts = df["text"].tolist()
    labels = df["label"].tolist()

    # Load the existing fine-tuned model (not base)
    model_path = output_dir if Path(output_dir).exists() else "./models/distilbert-base-multilingual-cased"
    logger.info("Loading model from %s for incremental training", model_path)

    tokenizer = DistilBertTokenizer.from_pretrained(model_path)
    model = DistilBertForSequenceClassification.from_pretrained(
        model_path,
        num_labels=2,
        ignore_mismatched_sizes=True,
    )

    # Split (80/20)
    from sklearn.model_selection import train_test_split as split_fn
    if len(texts) > 5:
        train_texts, val_texts, train_labels, val_labels = split_fn(
            texts, labels, test_size=0.2, random_state=42
        )
    else:
        train_texts, val_texts = texts, texts
        train_labels, val_labels = labels, labels

    train_ds = EmailDataset(train_texts, train_labels, tokenizer)
    val_ds = EmailDataset(val_texts, val_labels, tokenizer)

    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=2,  # Fewer epochs for incremental
        per_device_train_batch_size=4,
        per_device_eval_batch_size=4,
        learning_rate=1e-5,  # Lower LR for fine-tuning
        warmup_steps=10,
        logging_steps=5,
        eval_strategy="epoch",
        save_strategy="epoch",
        weight_decay=0.01,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        fp16=torch.cuda.is_available(),
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
    )

    logger.info("Starting incremental training with %d samples...", len(train_texts))
    trainer.train()

    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    logger.info("Incremental retraining complete! Model saved to %s", output_dir)

    metrics = trainer.evaluate()
    logger.info("Eval metrics: %s", metrics)
    return metrics


def main():
    parser = argparse.ArgumentParser(description="Train L2 DistilBERT phishing classifier")
    parser.add_argument("--dataset_path", default="./datasets", help="Path to datasets directory")
    parser.add_argument("--model_name", default="./models/distilbert-base-multilingual-cased", help="Base model path")
    parser.add_argument("--output_dir", default="./models/l2_finetuned", help="Output directory")
    parser.add_argument("--epochs", type=int, default=3, help="Number of epochs")
    parser.add_argument("--batch_size", type=int, default=16, help="Batch size")
    parser.add_argument("--learning_rate", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--incremental", type=str, default=None,
                        help="Path to CSV for incremental retraining (operator decisions)")
    args = parser.parse_args()

    if args.incremental:
        incremental_train(args.incremental, args.output_dir)
    else:
        train(
            dataset_path=args.dataset_path,
            model_name=args.model_name,
            output_dir=args.output_dir,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
        )


if __name__ == "__main__":
    main()

