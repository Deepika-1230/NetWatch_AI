from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from core.analyzer import PacketRecord

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ArpObservation:
    mac: str
    first_seen: float
    last_seen: float
    count: int = 1


class ARPSpoofDetector:
    """Detects MAC/IP mapping conflicts that often indicate MITM activity."""

    def __init__(self) -> None:
        self.ip_to_mac: dict[str, ArpObservation] = {}
        self.gateway_ips: set[str] = set()

    def set_gateway_ips(self, gateways: list[str]) -> None:
        self.gateway_ips = {gateway for gateway in gateways if gateway}

    def inspect(self, packet: PacketRecord) -> list[dict[str, Any]]:
        if packet.protocol != "ARP":
            return []
        sender_ip = str(packet.extra.get("arp_psrc") or packet.src_ip)
        sender_mac = str(packet.extra.get("arp_hwsrc") or packet.extra.get("src_mac") or "").lower()
        operation = str(packet.extra.get("arp_op") or "")
        if not sender_ip or not sender_mac:
            return []

        alerts: list[dict[str, Any]] = []
        previous = self.ip_to_mac.get(sender_ip)
        if previous and previous.mac != sender_mac:
            alerts.append(
                {
                    "title": "ARP Spoofing Suspected",
                    "description": f"{sender_ip} changed MAC mapping from {previous.mac} to {sender_mac}.",
                    "severity": "CRITICAL" if sender_ip in self.gateway_ips else "HIGH",
                    "score": 0.94 if sender_ip in self.gateway_ips else 0.82,
                    "category": "ARP Spoofing",
                    "old_mac": previous.mac,
                    "new_mac": sender_mac,
                    "operation": operation,
                    "recommended_action": "Freeze ARP cache evidence, verify switch CAM tables, and isolate the conflicting host.",
                }
            )
            LOGGER.warning("ARP mapping changed for %s: %s -> %s", sender_ip, previous.mac, sender_mac)
        else:
            self.ip_to_mac[sender_ip] = ArpObservation(sender_mac, packet.timestamp, packet.timestamp)

        current = self.ip_to_mac[sender_ip]
        current.last_seen = packet.timestamp
        current.count += 1

        if operation in {"is-at", "2"} and packet.extra.get("gratuitous"):
            alerts.append(
                {
                    "title": "Gratuitous ARP Announcement",
                    "description": f"{sender_ip} broadcast an unsolicited ARP mapping for {sender_mac}.",
                    "severity": "MEDIUM",
                    "score": 0.58,
                    "category": "ARP Monitoring",
                    "sender_mac": sender_mac,
                    "recommended_action": "Confirm whether the host recently joined, failed over, or is asserting a forged mapping.",
                }
            )
        return alerts

