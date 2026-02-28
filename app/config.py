"""Application configuration loaded from .env file."""

import os
from pathlib import Path
from dataclasses import dataclass, field

from dotenv import load_dotenv

# Load .env from project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


@dataclass
class Settings:
    # API Keys
    virustotal_api_key: str = field(default_factory=lambda: _env("VIRUSTOTAL_API_KEY"))
    abuseipdb_api_key: str = field(default_factory=lambda: _env("ABUSEIPDB_API_KEY"))

    # Model paths
    distilbert_model_path: str = field(
        default_factory=lambda: _env("DISTILBERT_MODEL_PATH", "./models/distilbert-base")
    )
    l2_finetuned_model_path: str = field(
        default_factory=lambda: _env("L2_FINETUNED_MODEL_PATH", "./models/l2_finetuned")
    )
    deepseek_model_path: str = field(
        default_factory=lambda: _env("DEEPSEEK_MODEL_PATH", "./models/deepseek-r1-14b")
    )
    deepseek_gguf_path: str = field(
        default_factory=lambda: _env(
            "DEEPSEEK_GGUF_PATH",
            "./models/deepseek-r1-14b-gguf/DeepSeek-R1-Distill-Qwen-14B-Q8_0.gguf",
        )
    )

    # Dataset paths
    phishtank_csv_path: str = field(
        default_factory=lambda: _env("PHISHTANK_CSV_PATH", "./datasets/phishtank.csv")
    )
    tranco_csv_path: str = field(
        default_factory=lambda: _env("TRANCO_CSV_PATH", "./datasets/top-1m.csv")
    )

    # Service settings
    smtp_host: str = field(default_factory=lambda: _env("SMTP_HOST", "0.0.0.0"))
    smtp_port: int = field(default_factory=lambda: int(_env("SMTP_PORT", "1025")))
    api_host: str = field(default_factory=lambda: _env("API_HOST", "0.0.0.0"))
    api_port: int = field(default_factory=lambda: int(_env("API_PORT", "8000")))

    # Thresholds (applied AFTER temperature scaling)
    l2_safe_threshold: float = field(
        default_factory=lambda: float(_env("L2_SAFE_THRESHOLD", "0.7"))
    )
    l2_phish_threshold: float = field(
        default_factory=lambda: float(_env("L2_PHISH_THRESHOLD", "0.3"))
    )

    # Temperature scaling for L2 calibration (>1.0 = softer probabilities)
    l2_temperature: float = field(
        default_factory=lambda: float(_env("L2_TEMPERATURE", "2.5"))
    )

    # Judge backend
    judge_backend: str = field(
        default_factory=lambda: _env("JUDGE_BACKEND", "llama_cpp")
    )


settings = Settings()

