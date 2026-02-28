"""L1 Threat Intel — reputation-based filtering layer.

Checks URLs, IPs, and domains against multiple threat intelligence sources
running in parallel:
  - VirusTotal  (API v3)
  - PhishTank   (local CSV)
  - OpenPhish   (live feed)
  - AbuseIPDB   (IP reputation)

Verdict: REJECT if any source flags as malicious, PROCEED otherwise.
"""

from app.l1_threat_intel.service import check

__all__ = ["check"]

