# Detect Email -- AI Phishing Defense System

Multi-layer AI cascade for detecting phishing emails in real time.
The system combines threat intelligence, a fine-tuned multilingual
DistilBERT classifier, and a DeepSeek-R1 14B large language model
to analyse incoming mail (English and Russian), escalating uncertain
cases to a human operator.

## Architecture

```
Incoming email (SMTP, port 1025)
        |
    [Gateway]  ── API key auth, email size validation
        |
   L1  Threat Intel  ── URL / IP / domain reputation
   |                     VirusTotal, PhishTank, OpenPhish,
   |                     AbuseIPDB, local blacklist
   |                     (shared httpx client, TTL cache)
   |   REJECT if known malicious
   |
   L2  Classifier    ── DistilBERT multilingual classifier (safe / phishing)
   |                     temperature-scaled confidence, thread-offloaded
   |   DELIVER if safe  |  REJECT if phishing
   |
   L3  Orchestrator  ── async sequential pipeline
   |   ├─ QR Scanner       decode QR codes from embedded base64 images
   |   ├─ Evidence Agent   screenshots + thumbnails (Playwright),
   |   │                   DOM analysis, WHOIS, SSL, Tranco rank
   |   └─ DeepSeek Judge   Chain-of-Thought reasoning on all evidence
   |
   v
 RELEASE / DELETE / OPERATOR_REVIEW
```

Each layer can be independently enabled or disabled via the dashboard
or the `/api/v1/layers` endpoint, allowing any combination (L1 only,
L2+L3, all three, etc.).

## Requirements

- Python 3.10+
- NVIDIA GPU with at least 16 GB VRAM (RTX 3090 recommended, 24 GB)
- CUDA 12.x toolkit
- `libzbar0` (system package for QR code decoding)
- conda environment (recommended)

### VRAM budget (approximate)

| Component             | VRAM             |
| --------------------- | ---------------- |
| L2 DistilBERT (multilingual) | ~500 MB   |
| L3 DeepSeek-R1 14B Q8 | ~14.2 GB         |
| KV cache (4096 ctx)   | ~384 MB          |
| Playwright / other    | ~200 MB          |
| **Total**             | **~15.3 GB**     |

## Project structure

```
detect_email/
    app/
        __init__.py          -- Package version (1.1.0)
        main.py              -- FastAPI entry point, lifespan, dashboard
        config.py            -- pydantic-settings based configuration
        schemas.py           -- Pydantic models and enums
        events.py            -- WebSocket event bus (deque-backed history)
        auth.py              -- API key authentication dependency
        utils.py             -- Shared domain/host extraction helpers
        layer_toggle.py      -- Runtime L1/L2/L3 enable/disable
        operator_store.py    -- Pending reviews, decisions, user inbox
        static/
            dashboard.html   -- Web UI (monitor, operator, inbox tabs)
        gateway/
            smtp_handler.py  -- aiosmtpd SMTP server + size validation
            email_parser.py  -- Raw email -> ParsedEmail
            router.py        -- /api/v1/process cascade logic
        l1_threat_intel/
            service.py       -- Aggregates all checkers
            local_blacklist.py
            checkers/
                http_client.py  -- Shared httpx.AsyncClient
                cache.py        -- In-memory TTL cache
                virustotal.py
                phishtank.py
                openphish.py
                abuseipdb.py
        l2_classifier/
            service.py       -- DistilBERT inference (thread-offloaded)
            preprocess.py    -- Text cleaning
            train.py         -- Fine-tuning and incremental retraining
        l3_evidence/
            service.py       -- Orchestrates evidence collection
            screenshot.py    -- Playwright screenshots + JPEG thumbnails
            dom_analyzer.py  -- Form/password/iframe detection
            qr_scanner.py    -- QR code extraction from HTML (pyzbar)
            whois_lookup.py  -- WHOIS (thread-offloaded)
            ssl_checker.py   -- SSL cert check (thread-offloaded)
            tranco_check.py
        l3_orchestrator/
            graph.py         -- Async sequential investigation pipeline
            state.py         -- InvestigationState dataclass
        l3_judge/
            service.py       -- DeepSeek-R1 inference (llama-cpp-python)
            prompts.py       -- System prompt + CoT template (incl. QR)
            router.py
    models/
        distilbert-base-multilingual-cased/  -- Base multilingual DistilBERT
        l2_finetuned/                        -- Fine-tuned L2 checkpoint
        deepseek-r1-14b-gguf/                -- GGUF quantised DeepSeek-R1 14B Q8_0
    datasets/
        phishtank.csv                        -- PhishTank URL feed (L1)
        top-1m.csv                           -- Tranco Top 1M domains (L1)
        dataset_full.csv                     -- URL features dataset (L1)
        enron/emails.csv                     -- Safe email corpus (L2 train)
        phishing_emails/Phishing_Email.csv   -- Phishing corpus (L2 train)
        russian-spam-detection/              -- RU spam/ham parquet (L2 train)
        telegram_spam_cleaned.csv            -- RU Telegram spam (L2 train)
    tests/
        test_app_endpoints.py    -- FastAPI TestClient (main.py, 20 tests)
        test_auth.py             -- API key auth (5 tests)
        test_events_toggle.py    -- Event bus + layer toggle (14 tests)
        test_l2_service_mocked.py -- L2 DistilBERT with mocked torch (7 tests)
        test_l3_judge_prompts.py -- Judge verdict parsing + prompts (27 tests)
        test_l3_evidence_mocked.py -- SSL/WHOIS/QR/DOM/screenshot mocked (28 tests)
        test_l3_graph.py         -- L3 investigation pipeline (14 tests)
        test_gateway_smtp_full.py -- SMTP handler + cascade paths (22 tests)
        test_utils.py            -- Domain/host extraction (6 tests)
        ...                      -- + existing test files
    metrics/                     -- Standalone diploma metrics (Chapter 3)
        eval_l2.py               -- L2 model evaluation (ROC, F1, histograms)
        cascade_benchmark.py     -- 12-email cascade benchmark
        cascade_benchmark_big.py -- 1000-email generated benchmark
        run_tests.sh             -- pytest + coverage report generator
        outputs/                 -- Generated tables, charts, JSON
    results_new/                 -- Training loss/LR/gradient plots
    debug_screenshots/           -- Full PNG captures saved during L3
    requirements.txt
```

## Datasets

### Text datasets (L2 -- DistilBERT training)

Used to fine-tune `distilbert-base-multilingual-cased` for binary
classification: 0 = safe, 1 = phishing/spam.

| Dataset | File | Size | Rows | Lang | Labels |
| ------- | ---- | ---- | ---- | ---- | ------ |
| Phishing Email (Kaggle) | `phishing_emails/Phishing_Email.csv` | 50 MB | 18 650 | EN | safe 11 322 / phishing 7 328 |
| Enron Emails (Kaggle/CMU) | `enron/emails.csv` | 1.4 GB | ~500K (10K used) | EN | all safe |
| Russian Spam Detection (HF, gated) | `russian-spam-detection/processed_combined.parquet` | 458 MB | 4.5M (30K sampled) | RU | ham 4.16M / spam 347K |
| Telegram Spam | `telegram_spam_cleaned.csv` | 77 KB | 199 | RU | spam only (supplement) |

All four datasets are loaded automatically by `train.py`.
Russian Spam Detection is sampled to 30 000 (15K spam + 15K safe) for
class balance. Enron is limited to 10 000 rows.

### URL / reputation datasets (L1 -- Threat Intel)

| Dataset | File | Size | Rows | Used for |
| ------- | ---- | ---- | ---- | -------- |
| URL Features | `dataset_full.csv` | 24 MB | 88 647 | URL scoring (111 numeric features) |
| PhishTank | `phishtank.csv` | 11 MB | 56 052 | URL blocklist |
| Tranco Top-1M | `top-1m.csv` | 22 MB | 1 000 000 | URL whitelist |

## Setup

1. Create and activate a conda environment:

```bash
conda create -n sysdet python=3.10 -y
conda activate sysdet
```

2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

3. Install llama-cpp-python with CUDA support (critical for L3 speed):

```bash
pip install llama-cpp-python \
    --force-reinstall --no-cache-dir \
    --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu124
```

4. Install system dependencies for QR code scanning:

```bash
sudo apt install -y libzbar0
```

5. Install Playwright browsers:

```bash
playwright install chromium
```

6. Download models:

```bash
# DistilBERT base (multilingual)
huggingface-cli download distilbert/distilbert-base-multilingual-cased \
    --local-dir ./models/distilbert-base-multilingual-cased

# DeepSeek-R1 14B GGUF (Q8_0 quantisation)
huggingface-cli download bartowski/DeepSeek-R1-Distill-Qwen-14B-GGUF \
    DeepSeek-R1-Distill-Qwen-14B-Q8_0.gguf \
    --local-dir ./models/deepseek-r1-14b-gguf
```

7. Download datasets:

```bash
# Phishing Email (Kaggle)
kaggle datasets download -d subhajournal/phishingemails \
    -p ./datasets/phishing_emails --unzip

# Enron Emails (Kaggle)
kaggle datasets download -d wcukierski/enron-email-dataset \
    -p ./datasets/enron --unzip

# Russian Spam Detection (HuggingFace, gated -- requires HF_TOKEN)
export HF_TOKEN=<your_token>
huggingface-cli download ruSpamModels/russian-spam-detection \
    --repo-type dataset \
    --local-dir ./datasets/russian-spam-detection

# PhishTank (requires free API key)
wget -O datasets/phishtank.csv \
    "http://data.phishtank.com/data/<YOUR_KEY>/online-valid.csv"

# Tranco Top 1M
wget -O datasets/top-1m.csv https://tranco-list.eu/top-1m.csv.zip
unzip datasets/top-1m.csv.zip -d datasets/
```

8. Create a `.env` file in the project root:

```
VIRUSTOTAL_API_KEY=<your key>
ABUSEIPDB_API_KEY=<your key>
OPERATOR_API_KEY=<any secret string for API auth>
```

9. Fine-tune L2 classifier (first time only):

```bash
python -m app.l2_classifier.train \
    --dataset_path ./datasets \
    --output_dir ./models/l2_finetuned \
    --epochs 3
```

## Running

```bash
conda activate sysdet
python -m app.main
```

The system starts:

- SMTP server on port 1025
- HTTP API on port 8000
- Web dashboard at http://localhost:8000/
- Swagger docs at http://localhost:8000/docs

If the conda environment has a newer libstdc++ than the system
(needed for llama-cpp-python and Playwright), the application
sets `LD_LIBRARY_PATH` automatically on startup.

## Unit tests

191 unit tests with **76% code coverage** (84% excluding `train.py`).
All heavy dependencies (torch, Playwright, llama-cpp, SMTP, WHOIS) are
mocked so tests run in ~5 seconds without GPU.

```bash
# Run full test suite
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ --cov=app --cov-report=term-missing
```

### Coverage by module

| Module          | Coverage |
| --------------- | -------- |
| main.py         | 92%      |
| auth / events / layer_toggle | 100% |
| schemas / config | 100%    |
| gateway         | 87%      |
| l1_threat_intel | 75%      |
| l2_classifier   | 100% (excl. train.py) |
| l3_evidence     | 76%      |
| l3_judge        | 66%      |
| l3_orchestrator | 98%      |
| operator_store  | 94%      |

## Training results

Fine-tuning `distilbert-base-multilingual-cased` on 57 334 samples
(4 datasets, 1 236 duplicates removed) for 3 epochs:

| Metric | Epoch 1 | Epoch 2 | Epoch 3 |
| ------ | ------- | ------- | ------- |
| Train loss (avg) | 0.095 | 0.034 | 0.010 |
| Eval loss | **0.068** | 0.069 | 0.074 |

Best checkpoint: **epoch 1** (eval_loss=0.06829), saved automatically
via `load_best_model_at_end=True`. Mild overfitting visible from epoch 2.

Training plots are generated by `results_new/plot_training.py` (EN + RU):
loss curves, learning rate schedule, gradient norms, epoch comparison.

### Data integrity

- Text deduplication via MD5 hashes (1 236 duplicates removed)
- Train/validation split manifest saved to `split_manifest.json`
- Evaluation uses the exact held-out set from training (no leakage)

## Integration testing (bombardier)

The bombardier script (`smtp_bombardier.py`) contains **48 test emails**
across 9 levels covering every detection layer and attack type.

### Basic levels

```bash
# L1 -- known blacklisted domains (should be rejected)
python smtp_bombardier.py --http --level l1 --delay 1

# L2 -- obvious phishing text patterns (should be rejected)
python smtp_bombardier.py --http --level l2_phish --delay 1

# L2 -- clearly safe emails (should be delivered)
python smtp_bombardier.py --http --level safe --delay 1

# Grey zone -- ambiguous emails forwarded to L3 Judge
python smtp_bombardier.py --http --level grey --delay 5

# Uncertain -- L3 can't decide, escalated to operator
python smtp_bombardier.py --http --level uncertain --delay 5
```

### Artifact levels (rich HTML / embedded QR codes)

```bash
# QR code phishing: fake payment, crypto airdrop, tax refund, 2FA, etc.
python smtp_bombardier.py --http --level artifact_qr --delay 5

# HTML phishing: fake login forms, iframes, JS redirects,
#   DHL package scam, "vote for me", Telegram/WhatsApp social engineering
python smtp_bombardier.py --http --level artifact_html --delay 5

# Safe QR codes: GitHub, Zoom, LinkedIn (should be delivered)
python smtp_bombardier.py --http --level artifact_safe_qr --delay 5

# All artifact levels at once
python smtp_bombardier.py --http --level artifacts --delay 5
```

### Full test suite

```bash
# All 48 emails (all 9 levels in sequence)
python smtp_bombardier.py --http --level all --delay 3
```

Debug screenshots captured during L3 investigation are saved to `debug_screenshots/`.

### Test email categories

| Level             | Count | Description                                              |
| ----------------- | ----- | -------------------------------------------------------- |
| `l1`              | 10    | Known blacklisted domains (L1 reject)                    |
| `l2_phish`        | 5     | Obvious phishing text (L2 reject)                        |
| `safe`            | 5     | Legitimate business emails (L2 deliver)                  |
| `grey`            | 4     | Ambiguous -> L3 -> phishing                              |
| `grey_safe`       | 2     | Ambiguous -> L3 -> safe                                  |
| `uncertain`       | 6     | L3 uncertain -> operator review                          |
| `artifact_qr`    | 6     | QR phishing: 2FA, parking fine, invoice, crypto, tax     |
| `artifact_html`  | 7     | HTML phishing: forms, iframes, DHL, vote, Telegram, WhatsApp |
| `artifact_safe_qr`| 3    | Safe QR: GitHub, Zoom, LinkedIn                          |

Or run the HTTP integration tests:

```bash
python test_all_levels.py
```

## API overview

| Method | Endpoint                 | Description                       |
| ------ | ------------------------ | --------------------------------- |
| GET    | /                        | Web dashboard                     |
| GET    | /health                  | System health and model status    |
| POST   | /api/v1/process          | Submit an email for analysis      |
| GET    | /api/v1/layers           | Current layer toggle states       |
| POST   | /api/v1/layers           | Enable/disable a layer            |
| GET    | /api/v1/operator/pending | Emails awaiting operator review   |
| POST   | /api/v1/operator/decide  | Submit operator classification    |
| POST   | /api/v1/operator/retrain | Trigger incremental L2 retraining |
| GET    | /api/v1/inbox            | User inbox with AI summaries      |
| GET    | /api/events/history      | Recent processing events          |
| WS     | /ws                      | Real-time event stream            |

Full interactive documentation is available at `/docs` (Swagger UI).

## Operator workflow

When the L3 Judge cannot reach a confident verdict, the email is
placed in the operator review queue. The operator can:

1. Open the Operator tab on the dashboard.
2. Review the email body, L2 confidence, judge reasoning, and evidence.
3. Classify the email as "safe" or "phishing".
4. Once enough decisions accumulate (default: 10), trigger incremental
   retraining of the L2 DistilBERT model via the dashboard or API.

## Layer toggle combinations

| L1  | L2  | L3  | Behaviour                                             |
| --- | --- | --- | ----------------------------------------------------- |
| on  | on  | on  | Full cascade (normal operation)                       |
| off | on  | on  | Skip reputation check, classifier + judge only        |
| on  | off | on  | Reputation check, then straight to deep investigation |
| on  | on  | off | Reputation + classifier only, grey zone delivered     |
| off | off | on  | Judge analyses everything                             |
| off | off | off | All emails delivered without analysis                 |

## Technologies

- **Web**: FastAPI, uvicorn, aiosmtpd, pydantic-settings
- **ML**: PyTorch, HuggingFace Transformers (DistilBERT multilingual-cased)
- **LLM**: llama-cpp-python with CUDA (DeepSeek-R1 14B GGUF Q8_0)
- **Browser**: Playwright (headless Chromium) -- screenshots, DOM analysis
- **QR**: Pillow, pyzbar (libzbar0), qrcode
- **Threat Intel**: httpx, python-whois, Tranco, PhishTank, OpenPhish, VirusTotal, AbuseIPDB
- **Async**: asyncio, asyncio.to_thread for blocking I/O offloading

## Metrics (diploma Chapter 3)

The `metrics/` folder is fully standalone — it can be deleted without
affecting the running system. It generates all figures and tables for
Chapter 3 of the diploma.

| Script / File | Output |
| ------------- | ------ |
| `eval_l2.py` | Table 3.2 (L2 metrics), Fig 3.6 (ROC), Fig 3.7 (confidence histogram) |
| `cascade_benchmark.py` | Table 3.3 (cascade distribution), Table 3.4 (latency) — 12 emails |
| `cascade_benchmark_big.py` | Same tables — 1000 generated emails (30+ sender/domain/body combos) |
| `run_tests.sh` | Table 3.1 (coverage), Fig 3.5 (pytest output) |
| `fig_3_1_*.md` | Project structure tree |
| `fig_3_2_*.md` | Module dependency Mermaid diagram |
| `fig_3_3_*.md` | Test bench schema |
| `tab_3_5_*.md` | Comparison with analogous systems |
| `economics.md` | Tables 3.6–3.8 (hardware cost, man-hours, TCO) |

```bash
# Generate L2 metrics + plots
cd metrics && python eval_l2.py

# Run cascade benchmark (system must be running)
python cascade_benchmark.py

# Large-scale benchmark (1000 emails)
python cascade_benchmark_big.py --count 100   # quick test
python cascade_benchmark_big.py               # full 1000

# Coverage table
bash run_tests.sh
```

## License

Educational project (diploma work).
