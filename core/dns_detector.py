from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict, deque
from typing import Any

from core.analyzer import PacketRecord

LOGGER = logging.getLogger(__name__)


class DNSPoisoningDetector:
    """Flags inconsistent DNS answers and suspicious answer destinations."""

    def __init__(self) -> None:
        self.domain_answers: dict[str, set[str]] = defaultdict(set)
        self.answer_history: dict[str, deque[tuple[float, set[str]]]] = defaultdict(lambda: deque(maxlen=12))
        self.suspicious_tlds = {".zip", ".mov", ".tk", ".gq", ".ml", ".cf"}

    def inspect(self, packet: PacketRecord) -> list[dict[str, Any]]:
        if packet.protocol != "DNS" or not packet.dns_query:
            return []

        domain = packet.dns_query.rstrip(".").lower()
        answers = {str(answer) for answer in packet.extra.get("dns_answers", []) if answer}
        alerts: list[dict[str, Any]] = []

        if not answers:
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                alerts.append(
                    {
                        "title": "Suspicious DNS Query",
                        "description": f"Query for high-risk domain suffix: {domain}",
                        "severity": "LOW",
                        "score": 0.42,
                        "category": "DNS",
                        "domain": domain,
                    }
                )
            return alerts

        known = self.domain_answers[domain]
        if known and not answers.issubset(known):
            overlap = known.intersection(answers)
            if not overlap:
                alerts.append(
                    {
                        "title": "DNS Poisoning Suspected",
                        "description": f"{domain} resolved to a completely new answer set within this session.",
                        "severity": "HIGH",
                        "score": 0.84,
                        "category": "DNS Poisoning",
                        "domain": domain,
                        "previous_answers": sorted(known),
                        "new_answers": sorted(answers),
                        "recommended_action": "Compare with a trusted resolver, inspect local DNS cache, and verify DHCP/DNS server configuration.",
                    }
                )
        known.update(answers)

        self.answer_history[domain].append((packet.timestamp, answers))
        recent_sets = [items for ts, items in self.answer_history[domain] if packet.timestamp - ts < 45]
        unique_sets = {tuple(sorted(item)) for item in recent_sets}
        if len(unique_sets) >= 4:
            alerts.append(
                {
                    "title": "DNS Flux Behavior",
                    "description": f"{domain} rotated through {len(unique_sets)} answer sets in under 45 seconds.",
                    "severity": "MEDIUM",
                    "score": 0.67,
                    "category": "DNS",
                    "domain": domain,
                    "answer_sets": [list(item) for item in unique_sets][:8],
                }
            )

        for answer in answers:
            if self._public_domain_to_private_ip(domain, answer):
                alerts.append(
                    {
                        "title": "DNS Answer Points To Private Address",
                        "description": f"Public-looking domain {domain} resolved to private IP {answer}.",
                        "severity": "HIGH",
                        "score": 0.8,
                        "category": "DNS Poisoning",
                        "domain": domain,
                        "answer": answer,
                        "recommended_action": "Validate split-horizon DNS policy and rule out resolver manipulation.",
                    }
                )
        return alerts

    @staticmethod
    def _public_domain_to_private_ip(domain: str, answer: str) -> bool:
        if domain.endswith((".local", ".lan", ".home", ".corp", ".internal")):
            return False
        try:
            ip = ipaddress.ip_address(answer)
        except ValueError:
            return False
        return ip.is_private or ip.is_loopback or ip.is_link_local

