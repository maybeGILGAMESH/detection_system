# Detect Email -- AI Phishing Defense System

Multi-layer AI cascade for detecting phishing emails in real time.
The system combines threat intelligence, a fine-tuned DistilBERT classifier,
and a DeepSeek-R1 14B large language model to analyse incoming mail,
escalating uncertain cases to a human operator.

## Architecture

```
Incoming email (SMTP, port 1025)
        |
    [Gateway]
        |
   L1  Threat Intel  -- URL / IP / domain reputation (VirusTotal, PhishTank,
   |                      OpenPhish, AbuseIPDB, local blacklist)
   |   REJECT if known malicious
   |
   L2  Classifier    -- DistilBERT binary classifier (safe / phishing)
   |                      with temperature-scaled confidence
   |   DELIVER if safe  |  REJECT if phishing
   |
   L3  Orchestrator   -- LangGraph state machine
   |    Evidence Agent   screenshots (Playwright), DOM analysis,
   |                      WHOIS, SSL, Tranco rank
   |    DeepSeek Judge   Chain-of-Thought reasoning on evidence
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
- conda environment (recommended)

### VRAM budget (approximate)

| Component            | VRAM     |
|----------------------|----------|
| L2 DistilBERT        | ~270 MB  |
| L3 DeepSeek-R1 14B Q8| ~14.2 GB |
| KV cache (4096 ctx)  | ~384 MB  |
| Playwright / other   | ~200 MB  |
| **Total**            | **~15 GB** |

## Project structure

```
detect_email/
    app/
        main.py              -- FastAPI entry point, lifespan, dashboard
        config.py            -- Settings loaded from .env
        schemas.py           -- Pydantic models and enums
        events.py            -- WebSocket event bus
        layer_toggle.py      -- Runtime L1/L2/L3 enable/disable
        operator_store.py    -- Pending reviews, decisions, user inbox
        static/
            dashboard.html   -- Web UI (monitor, operator, inbox tabs)
        gateway/
            smtp_handler.py  -- aiosmtpd SMTP server
            email_parser.py  -- Raw email -> ParsedEmail
            router.py        -- /api/v1/process cascade logic
        l1_threat_intel/
            service.py       -- Aggregates all checkers
            local_blacklist.py
            checkers/
                virustotal.py
                phishtank.py
                openphish.py
                abuseipdb.py
        l2_classifier/
            service.py       -- DistilBERT inference with temperature scaling
            preprocess.py    -- Text cleaning
            train.py         -- Fine-tuning and incremental retraining
        l3_evidence/
            service.py       -- Orchestrates evidence collection
            screenshot.py    -- Playwright screenshots
            dom_analyzer.py  -- Form/password/iframe detection
            whois_lookup.py
            ssl_checker.py
            tranco_check.py
        l3_orchestrator/
            graph.py         -- LangGraph state machine
            state.py         -- InvestigationState dataclass
        l3_judge/
            service.py       -- DeepSeek-R1 inference (llama-cpp-python)
            prompts.py       -- System prompt and CoT template
            router.py
    models/
        distilbert-base/     -- Base DistilBERT (HuggingFace)
        l2_finetuned/        -- Fine-tuned L2 checkpoint
        deepseek-r1-14b-gguf/-- GGUF quantised DeepSeek-R1 14B Q8_0
    datasets/
        phishtank.csv        -- PhishTank URL feed
        top-1m.csv           -- Tranco Top 1M domains
        enron/emails.csv     -- Safe email corpus (training)
        phishing_emails/     -- Phishing corpus (training)
    tests/
    smtp_bombardier.py       -- Test email sender (L1/L2/L3 scenarios)
    test_all_levels.py       -- HTTP-based integration tests
    requirements.txt
    PLAN.md
```

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

4. Install Playwright browsers:

```bash
playwright install chromium
```

5. Download models:

```bash
# DistilBERT base
huggingface-cli download distilbert-base-uncased --local-dir ./models/distilbert-base

# DeepSeek-R1 14B GGUF (Q8_0 quantisation)
huggingface-cli download bartowski/DeepSeek-R1-Distill-Qwen-14B-GGUF \
    DeepSeek-R1-Distill-Qwen-14B-Q8_0.gguf \
    --local-dir ./models/deepseek-r1-14b-gguf
```

6. Download datasets:

```bash
# PhishTank (requires free API key)
wget -O datasets/phishtank.csv \
    "http://data.phishtank.com/data/<YOUR_KEY>/online-valid.csv"

# Tranco Top 1M
wget -O datasets/top-1m.csv https://tranco-list.eu/top-1m.csv.zip
unzip datasets/top-1m.csv.zip -d datasets/
```

7. Create a `.env` file in the project root:

```
VIRUSTOTAL_API_KEY=<your key>
ABUSEIPDB_API_KEY=<your key>
```

8. Fine-tune L2 classifier (first time only):

```bash
python -m app.l2_classifier.train
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

## Testing

Send test emails with the bombardier script:

```bash
# L1 -- known blacklisted domains (should be rejected)
python smtp_bombardier.py --http --level l1 --delay 1

# L2 -- obvious phishing text patterns (should be rejected)
python smtp_bombardier.py --http --level l2_phish --delay 1

# L2 -- clearly safe emails (should be delivered)
python smtp_bombardier.py --http --level l2_safe --delay 1

# Grey zone -- ambiguous emails forwarded to L3 Judge
python smtp_bombardier.py --http --level grey --delay 5

# All standard levels in sequence
python smtp_bombardier.py --http --delay 3
```

Or run the HTTP integration tests:

```bash
python test_all_levels.py
```

## API overview

| Method | Endpoint                    | Description                        |
|--------|-----------------------------|------------------------------------|
| GET    | /                           | Web dashboard                      |
| GET    | /health                     | System health and model status     |
| POST   | /api/v1/process             | Submit an email for analysis       |
| GET    | /api/v1/layers              | Current layer toggle states        |
| POST   | /api/v1/layers              | Enable/disable a layer             |
| GET    | /api/v1/operator/pending    | Emails awaiting operator review    |
| POST   | /api/v1/operator/decide     | Submit operator classification     |
| POST   | /api/v1/operator/retrain    | Trigger incremental L2 retraining  |
| GET    | /api/v1/inbox               | User inbox with AI summaries       |
| GET    | /api/events/history         | Recent processing events           |
| WS     | /ws                         | Real-time event stream             |

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

| L1 | L2 | L3 | Behaviour                                          |
|----|----|----|-----------------------------------------------------|
| on | on | on | Full cascade (normal operation)                     |
| off| on | on | Skip reputation check, classifier + judge only      |
| on | off| on | Reputation check, then straight to deep investigation|
| on | on | off| Reputation + classifier only, grey zone delivered   |
| off| off| on | Judge analyses everything                           |
| off| off| off| All emails delivered without analysis               |

## Technologies

- FastAPI, uvicorn, aiosmtpd
- PyTorch, HuggingFace Transformers (DistilBERT)
- llama-cpp-python with CUDA (DeepSeek-R1 14B GGUF Q8_0)
- LangGraph (agent orchestration)
- Playwright (headless Chromium)
- httpx (async HTTP for threat intel APIs)
- python-whois, Tranco, PhishTank, OpenPhish, VirusTotal, AbuseIPDB

## License

Educational project (diploma work).

