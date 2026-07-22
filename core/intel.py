from __future__ import annotations

import hashlib
import logging
import os
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

LOGGER = logging.getLogger(__name__)

try:
    import requests
except Exception:  # pragma: no cover - optional dependency
    requests = None


@dataclass(slots=True)
class ReputationResult:
    indicator: str
    indicator_type: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    score: float
    source: str
    details: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "score": self.score,
            "source": self.source,
            "details": self.details,
        }


@dataclass(slots=True)
class CVERecord:
    cve_id: str
    description: str
    severity: str
    cvss: float
    published: str
    source: str
    url: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss": self.cvss,
            "published": self.published,
            "source": self.source,
            "url": self.url,
        }


class VirusTotalClient:
    def __init__(self, api_key: str | None = None, timeout: float = 8.0) -> None:
        self.api_key = api_key or os.getenv("VT_API_KEY", "")
        self.timeout = timeout

    def check_ip(self, ip: str) -> ReputationResult:
        if not self.api_key or requests is None:
            return self._simulated(ip, "ip-address")
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.api_key},
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            attrs = payload.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            total = max(1, malicious + suspicious + harmless + undetected)
            score = min(1.0, (malicious * 1.0 + suspicious * 0.5) / total * 4)
            return ReputationResult(
                indicator=ip,
                indicator_type="ip-address",
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                undetected=undetected,
                score=score,
                source="VirusTotal",
                details={
                    "asn": attrs.get("asn"),
                    "network": attrs.get("network"),
                    "country": attrs.get("country"),
                    "last_analysis_date": attrs.get("last_analysis_date"),
                },
            )
        except Exception:
            LOGGER.warning("VirusTotal lookup failed; returning deterministic simulated result", exc_info=True)
            return self._simulated(ip, "ip-address")

    @staticmethod
    def _simulated(indicator: str, indicator_type: str) -> ReputationResult:
        seed = int(hashlib.sha1(indicator.encode("utf-8")).hexdigest()[:8], 16)
        rng = random.Random(seed)
        suspicious = rng.choice([0, 0, 1, 2, 3])
        malicious = rng.choice([0, 0, 0, 1, 2]) if suspicious else rng.choice([0, 0, 0, 1])
        harmless = rng.randint(42, 76)
        undetected = rng.randint(5, 24)
        score = min(1.0, (malicious * 0.34) + (suspicious * 0.13))
        return ReputationResult(
            indicator=indicator,
            indicator_type=indicator_type,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            score=score,
            source="Simulated offline intelligence",
            details={"note": "No VirusTotal API key or network connectivity was available."},
        )


class NVDClient:
    def __init__(self, api_key: str | None = None, timeout: float = 10.0) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY", "")
        self.timeout = timeout

    def search(self, query: str, limit: int = 8) -> list[CVERecord]:
        query = query.strip()
        if not query:
            return []
        if requests is None:
            return self._simulated(query, limit)
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": query, "resultsPerPage": min(limit, 20)},
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            records: list[CVERecord] = []
            for item in data.get("vulnerabilities", [])[:limit]:
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                severity, cvss = self._extract_cvss(metrics)
                descriptions = cve.get("descriptions", [])
                desc = next((entry.get("value") for entry in descriptions if entry.get("lang") == "en"), "")
                cve_id = cve.get("id", "CVE-UNKNOWN")
                records.append(
                    CVERecord(
                        cve_id=cve_id,
                        description=desc[:420],
                        severity=severity,
                        cvss=cvss,
                        published=cve.get("published", ""),
                        source="NVD",
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    )
                )
            return records or self._simulated(query, limit)
        except Exception:
            LOGGER.warning("NVD lookup failed; returning deterministic simulated result", exc_info=True)
            return self._simulated(query, limit)

    @staticmethod
    def _extract_cvss(metrics: dict[str, Any]) -> tuple[str, float]:
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            values = metrics.get(key)
            if values:
                metric = values[0]
                data = metric.get("cvssData", {})
                severity = metric.get("baseSeverity") or data.get("baseSeverity") or "UNKNOWN"
                score = float(data.get("baseScore") or 0)
                return severity, score
        return "UNKNOWN", 0.0

    @staticmethod
    def _simulated(query: str, limit: int) -> list[CVERecord]:
        year = datetime.now(timezone.utc).year
        seed = int(hashlib.sha1(query.encode("utf-8")).hexdigest()[:8], 16)
        rng = random.Random(seed)
        severities = [("LOW", 3.1), ("MEDIUM", 5.8), ("HIGH", 8.1), ("CRITICAL", 9.6)]
        records: list[CVERecord] = []
        for index in range(min(limit, 5)):
            severity, base = rng.choice(severities)
            cve_id = f"CVE-{year - rng.randint(0, 5)}-{rng.randint(1000, 99999)}"
            records.append(
                CVERecord(
                    cve_id=cve_id,
                    description=(
                        f"Offline simulated CVE result for '{query}'. This entry models a realistic service/version "
                        "risk so investigations can continue without NVD connectivity."
                    ),
                    severity=severity,
                    cvss=min(10.0, round(base + rng.random(), 1)),
                    published=f"{year - rng.randint(0, 5)}-0{rng.randint(1, 9)}-{rng.randint(10, 28)}T00:00:00.000",
                    source="Simulated offline NVD",
                    url="https://nvd.nist.gov/",
                )
            )
        return records

