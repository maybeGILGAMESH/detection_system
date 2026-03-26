"""Application configuration loaded from .env file using Pydantic BaseSettings."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # API Keys
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    # Model paths
    distilbert_model_path: str = "./models/distilbert-base"
    l2_finetuned_model_path: str = "./models/l2_finetuned"
    deepseek_model_path: str = "./models/deepseek-r1-14b"
    deepseek_gguf_path: str = (
        "./models/deepseek-r1-14b-gguf/DeepSeek-R1-Distill-Qwen-14B-Q8_0.gguf"
    )

    # Dataset paths
    phishtank_csv_path: str = "./datasets/phishtank.csv"
    tranco_csv_path: str = "./datasets/top-1m.csv"

    # Service settings
    smtp_host: str = "0.0.0.0"
    smtp_port: int = 1025
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Thresholds (applied AFTER temperature scaling)
    l2_safe_threshold: float = 0.7
    l2_phish_threshold: float = 0.3

    # Temperature scaling for L2 calibration (>1.0 = softer probabilities)
    l2_temperature: float = 2.5

    # Judge backend
    judge_backend: str = "llama_cpp"

    # Operator authentication (empty = disabled)
    operator_api_key: str = ""

    # Max email size accepted via SMTP / API (bytes, default 10 MB)
    max_email_size: int = 10 * 1024 * 1024


settings = Settings()
