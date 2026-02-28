"""Tranco Top 1M domain whitelist checker."""

import csv
import logging
from pathlib import Path
from urllib.parse import urlparse

from app.config import settings

logger = logging.getLogger(__name__)

# In-memory domain → rank mapping (loaded once)
_tranco_db: dict[str, int] | None = None


def _load_tranco() -> dict[str, int]:
    """Load Tranco CSV into a dict: domain → rank."""
    global _tranco_db
    if _tranco_db is not None:
        return _tranco_db

    csv_path = Path(settings.tranco_csv_path)
    _tranco_db = {}

    if not csv_path.exists():
        logger.warning("Tranco CSV not found at %s", csv_path)
        return _tranco_db

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    rank = int(row[0])
                    domain = row[1].strip().lower()
                    _tranco_db[domain] = rank
        logger.info("Loaded %d domains from Tranco Top 1M", len(_tranco_db))
    except Exception as e:
        logger.error("Failed to load Tranco CSV: %s", e)

    return _tranco_db


def _extract_domain(url: str) -> str:
    """Extract the registrable domain from a URL."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.netloc or parsed.path.split("/")[0]).lower()
    # Remove www. prefix
    if host.startswith("www."):
        host = host[4:]
    return host


async def check(url: str) -> int | None:
    """Check if the URL's domain is in Tranco Top 1M.

    Returns:
        Rank (1-1000000) if found, None if not in the list.
    """
    db = _load_tranco()
    domain = _extract_domain(url)

    # Try exact match, then parent domain
    if domain in db:
        return db[domain]

    # Try parent domain (e.g., sub.example.com → example.com)
    parts = domain.split(".")
    if len(parts) > 2:
        parent = ".".join(parts[-2:])
        if parent in db:
            return db[parent]

    return None

