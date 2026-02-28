"""L1 Threat Intel — aggregate checker that runs all sources in parallel.

Sources: VirusTotal, PhishTank, OpenPhish, AbuseIPDB, Local Blacklist.
"""

import asyncio
import logging

from app.schemas import L1CheckRequest, L1Result, CheckerResult, Verdict
from app.l1_threat_intel.checkers import virustotal, phishtank, openphish, abuseipdb
from app.l1_threat_intel import local_blacklist

logger = logging.getLogger(__name__)


async def check(request: L1CheckRequest) -> L1Result:
    """
    Run all threat-intel checkers in parallel.
    If ANY source flags something as malicious → REJECT.
    Otherwise → PROCEED.
    """
    tasks: list = []

    # Check each URL against all URL-based sources
    for url in request.urls:
        tasks.append(local_blacklist.check_url(url))  # Local blacklist first
        tasks.append(virustotal.check_url(url))
        tasks.append(phishtank.check_url(url))
        tasks.append(openphish.check_url(url))

    # Check each domain against local blacklist + VirusTotal
    for domain in request.domains:
        tasks.append(local_blacklist.check_domain(domain))
        tasks.append(virustotal.check_domain(domain))

    # Check each IP against AbuseIPDB
    for ip in request.ips:
        tasks.append(abuseipdb.check_ip(ip))

    if not tasks:
        return L1Result(verdict=Verdict.PROCEED, results=[])

    results: list[CheckerResult] = await asyncio.gather(*tasks, return_exceptions=False)

    # If at least one source says malicious → REJECT
    any_malicious = any(r.is_malicious for r in results if isinstance(r, CheckerResult))
    verdict = Verdict.REJECT if any_malicious else Verdict.PROCEED

    valid_results = [r for r in results if isinstance(r, CheckerResult)]
    logger.info(
        "L1 check: %d URLs, %d domains, %d IPs → %s (results: %d, malicious: %d)",
        len(request.urls), len(request.domains), len(request.ips),
        verdict, len(valid_results),
        sum(1 for r in valid_results if r.is_malicious),
    )

    return L1Result(verdict=verdict, results=valid_results)
