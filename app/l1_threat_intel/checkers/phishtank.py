"""PhishTank local CSV lookup for known phishing URLs."""

import csv
import logging
from pathlib import Path

from app.config import settings
from app.schemas import CheckerResult

logger = logging.getLogger(__name__)

# In-memory set of known phishing URLs (loaded once)
_phishing_urls: set[str] | None = None


def _load_phishtank_db() -> set[str]:
    """Load PhishTank CSV into a set of URLs."""
    global _phishing_urls
    if _phishing_urls is not None:
        return _phishing_urls

    csv_path = Path(settings.phishtank_csv_path)
    _phishing_urls = set()

    if not csv_path.exists():
        logger.warning("PhishTank CSV not found at %s", csv_path)
        return _phishing_urls

    try:
        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = row.get("url", "").strip()
                if url:
                    _phishing_urls.add(url.lower())
        logger.info("Loaded %d URLs from PhishTank", len(_phishing_urls))
    except Exception as e:
        logger.error("Failed to load PhishTank CSV: %s", e)

    return _phishing_urls


async def check_url(url: str) -> CheckerResult:
    """Check a URL against the local PhishTank database."""
    db = _load_phishtank_db()
    normalized = url.lower().strip()

    is_found = normalized in db
    return CheckerResult(
        source="phishtank",
        is_malicious=is_found,
        detail=f"Found in PhishTank DB" if is_found else "Not in PhishTank DB",
    )

