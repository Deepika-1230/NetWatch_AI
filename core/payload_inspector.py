from __future__ import annotations

import base64
import binascii
import logging
import re
from dataclasses import dataclass
from typing import Any

from core.analyzer import payload_entropy

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class PayloadFinding:
    title: str
    description: str
    severity: str
    score: float
    offset: int
    matched: str
    rule: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "score": self.score,
            "offset": self.offset,
            "matched": self.matched,
            "rule": self.rule,
        }


class PayloadInspector:
    """Highlights suspicious strings and produces a hex/ASCII forensic view."""

    RULES: list[tuple[str, bytes, str, float, str]] = [
        (
            "SQL Injection Pattern",
            rb"(?i)(union\s+select|or\s+1=1|drop\s+table|sleep\(\d+\)|information_schema)",
            "HIGH",
            0.82,
            "Payload contains classic SQL injection syntax.",
        ),
        (
            "Shell Command Pattern",
            rb"(?i)(/bin/sh|cmd\.exe|powershell|wget\s+http|curl\s+http|nc\s+-e|bash\s+-i)",
            "HIGH",
            0.84,
            "Payload contains shell command execution indicators.",
        ),
        (
            "Credential Material",
            rb"(?i)(password=|passwd=|authorization:\s*basic|api[_-]?key=|secret=)",
            "MEDIUM",
            0.68,
            "Payload may expose credentials or API secrets.",
        ),
        (
            "Path Traversal",
            rb"(?i)(\.\./\.\./|/etc/passwd|boot\.ini|windows/system32)",
            "HIGH",
            0.78,
            "Payload includes filesystem traversal indicators.",
        ),
        (
            "Encoded PowerShell",
            rb"(?i)(-enc(odedcommand)?\s+[a-z0-9+/=]{40,})",
            "CRITICAL",
            0.93,
            "Encoded PowerShell execution is often used by post-exploitation tooling.",
        ),
    ]

    def inspect(self, payload: bytes | str) -> list[dict[str, Any]]:
        if isinstance(payload, str):
            data = payload.encode("utf-8", errors="ignore")
        else:
            data = payload
        if not data:
            return []

        findings: list[PayloadFinding] = []
        for rule_name, pattern, severity, score, description in self.RULES:
            for match in re.finditer(pattern, data[:8192]):
                matched = match.group(0)[:80].decode("utf-8", errors="replace")
                findings.append(
                    PayloadFinding(
                        title=rule_name,
                        description=description,
                        severity=severity,
                        score=score,
                        offset=match.start(),
                        matched=matched,
                        rule=rule_name,
                    )
                )

        entropy = payload_entropy(data)
        if entropy > 6.7 and len(data) >= 220:
            findings.append(
                PayloadFinding(
                    title="High Entropy Payload",
                    description="Payload entropy suggests compressed, encrypted, or packed content.",
                    severity="MEDIUM",
                    score=0.64,
                    offset=0,
                    matched=f"entropy={entropy:.2f}",
                    rule="Entropy",
                )
            )

        if self._looks_like_large_base64(data):
            findings.append(
                PayloadFinding(
                    title="Large Base64 Blob",
                    description="Payload contains a decodable Base64 blob often seen in staging or exfiltration.",
                    severity="MEDIUM",
                    score=0.7,
                    offset=0,
                    matched="base64 blob",
                    rule="Base64",
                )
            )

        return [finding.as_dict() for finding in findings]

    @staticmethod
    def hexdump(payload: bytes | str, width: int = 16, limit: int = 1024) -> str:
        if isinstance(payload, str):
            data = payload.encode("utf-8", errors="ignore")
        else:
            data = payload
        data = data[:limit]
        rows: list[str] = []
        for offset in range(0, len(data), width):
            chunk = data[offset : offset + width]
            hex_part = " ".join(f"{byte:02x}" for byte in chunk).ljust(width * 3)
            ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
            rows.append(f"{offset:08x}  {hex_part} |{ascii_part}|")
        return "\n".join(rows) if rows else "<empty payload>"

    @staticmethod
    def _looks_like_large_base64(data: bytes) -> bool:
        matches = re.findall(rb"[A-Za-z0-9+/]{96,}={0,2}", data)
        for item in matches[:4]:
            try:
                decoded = base64.b64decode(item, validate=True)
            except (binascii.Error, ValueError):
                continue
            if len(decoded) >= 64:
                return True
        return False

