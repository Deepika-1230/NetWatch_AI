from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Iterable


SEVERITY_BASE = {
    "CRITICAL": 82,
    "HIGH": 68,
    "MEDIUM": 46,
    "LOW": 24,
}

SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP proxy",
}


def normalize_trusted_devices(value: Any) -> list[str]:
    """Accepts a list or comma/newline text and returns clean trusted identifiers."""
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = value.replace(",", "\n").splitlines()
    elif isinstance(value, Iterable):
        raw_items = [str(item) for item in value]
    else:
        raw_items = [str(value)]
    return sorted({item.strip() for item in raw_items if item and item.strip()})


def enrich_alert(alert: dict[str, Any], trusted_devices: Iterable[str] | None = None) -> dict[str, Any]:
    trusted = normalize_trusted_devices(trusted_devices)
    item = dict(alert)
    trusted_match = trusted_device_match(item, trusted)
    item["trusted_device"] = trusted_match
    item["risk_score"] = calculate_risk_score(item, trusted_match)
    item["ai_explanation"] = explain_alert(item, trusted_match)
    item["remediation_steps"] = remediation_steps(item, trusted_match)
    item["remediation_text"] = " ".join(item["remediation_steps"])
    item["timeline_time"] = datetime.fromtimestamp(float(item.get("timestamp") or 0)).strftime("%Y-%m-%d %H:%M:%S")
    return item


def build_incident_timeline(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    for alert in sorted(alerts, key=lambda item: float(item.get("timestamp") or 0)):
        when = datetime.fromtimestamp(float(alert.get("timestamp") or 0)).strftime("%H:%M:%S")
        source = alert.get("src_ip") or "unknown source"
        target = alert.get("dst_ip") or "unknown target"
        protocol = alert.get("protocol") or "network"
        timeline.append(
            {
                "timestamp": alert.get("timestamp"),
                "time": when,
                "severity": alert.get("severity", "LOW"),
                "risk_score": int(alert.get("risk_score") or 0),
                "title": alert.get("title", "Threat alert"),
                "src_ip": source,
                "dst_ip": target,
                "phase": "Traffic observed",
                "detail": f"{source} communicated with {target} using {protocol}.",
            }
        )
        timeline.append(
            {
                "timestamp": alert.get("timestamp"),
                "time": when,
                "severity": alert.get("severity", "LOW"),
                "risk_score": int(alert.get("risk_score") or 0),
                "title": alert.get("title", "Threat alert"),
                "src_ip": source,
                "dst_ip": target,
                "phase": "Threat detected",
                "detail": alert.get("ai_explanation") or alert.get("description") or "The activity matched a detection rule.",
            }
        )
        timeline.append(
            {
                "timestamp": alert.get("timestamp"),
                "time": when,
                "severity": alert.get("severity", "LOW"),
                "risk_score": int(alert.get("risk_score") or 0),
                "title": alert.get("title", "Threat alert"),
                "src_ip": source,
                "dst_ip": target,
                "phase": "Response suggested",
                "detail": alert.get("remediation_text") or alert.get("recommended_action") or "Investigate and preserve evidence.",
            }
        )
    return timeline


def trusted_device_match(alert: dict[str, Any], trusted_devices: Iterable[str]) -> str:
    trusted = set(normalize_trusted_devices(trusted_devices))
    for field in ("src_ip", "dst_ip"):
        value = str(alert.get(field) or "").strip()
        if value and value in trusted:
            return value
    evidence = alert.get("evidence") or {}
    if isinstance(evidence, dict):
        for key in ("mac", "source_mac", "gateway_mac", "hostname"):
            value = str(evidence.get(key) or "").strip()
            if value and value in trusted:
                return value
    return ""


def calculate_risk_score(alert: dict[str, Any], trusted_match: str = "") -> int:
    severity = str(alert.get("severity") or "LOW").upper()
    risk = SEVERITY_BASE.get(severity, 28)
    risk += int(float(alert.get("score") or 0) * 18)

    category = str(alert.get("category") or "").lower()
    title = str(alert.get("title") or "").lower()
    if "arp" in title or "dns" in title or "mitm" in category:
        risk += 12
    if "payload" in title or "payload" in category:
        risk += 9
    if "scan" in title or "recon" in category:
        risk += 8
    if "ml" in title or "anomaly" in category:
        risk += 7

    port = _alert_port(alert)
    if port in SENSITIVE_PORTS:
        risk += 8

    if _public_ip(str(alert.get("src_ip") or "")):
        risk += 8

    if trusted_match:
        risk -= 32

    return max(1, min(100, risk))


def explain_alert(alert: dict[str, Any], trusted_match: str = "") -> str:
    title = str(alert.get("title") or "").lower()
    category = str(alert.get("category") or "").lower()
    source = alert.get("src_ip") or "this source"
    target = alert.get("dst_ip") or "the target device"

    if "arp" in title:
        reason = "ARP spoofing can redirect local traffic through an attacker, which may allow password theft or session hijacking."
    elif "dns" in title:
        reason = "DNS poisoning can send users to fake websites even when they typed the correct domain name."
    elif "payload" in title or "payload" in category:
        reason = "The packet content contains suspicious text patterns often seen in web attacks, command injection, or encoded payloads."
    elif "scan" in title or "recon" in category:
        reason = "Port scanning is usually a reconnaissance step used to discover open services before launching an attack."
    elif "ml" in title or "anomaly" in category:
        reason = "The traffic behavior is different from the normal baseline learned by the anomaly model."
    elif "volume" in title or "traffic behavior" in category:
        reason = "The device moved an unusual amount of data in a short time, which can indicate exfiltration or an infected host."
    elif "exposure" in category:
        reason = "A public source touched a sensitive service, which may expose the device to brute-force or exploit attempts."
    else:
        reason = str(alert.get("description") or "The activity matched one or more suspicious network detection rules.")

    trust_note = f" {trusted_match} is on the trusted-device list, so review before taking a blocking action." if trusted_match else ""
    return f"{source} triggered this alert against {target}. {reason}{trust_note}"


def remediation_steps(alert: dict[str, Any], trusted_match: str = "") -> list[str]:
    title = str(alert.get("title") or "").lower()
    category = str(alert.get("category") or "").lower()
    source = alert.get("src_ip") or "source"

    if trusted_match:
        return [
            f"Verify why trusted device {trusted_match} generated this alert.",
            "Do not block immediately unless the device is compromised.",
            "Compare with recent user activity and device logs.",
        ]
    if "arp" in title:
        return [
            "Check the router/gateway MAC address.",
            f"Disconnect or isolate {source} if the MAC conflict is confirmed.",
            "Reset ARP cache after confirming the correct gateway.",
        ]
    if "dns" in title:
        return [
            "Compare DNS answers with a trusted resolver.",
            "Flush DNS cache on affected devices.",
            "Inspect router DNS settings for unauthorized changes.",
        ]
    if "payload" in title or "payload" in category:
        return [
            "Preserve the payload evidence.",
            "Check the destination web/application logs at the same time.",
            f"Block or rate-limit {source} if the request is not expected.",
        ]
    if "scan" in title or "recon" in category:
        return [
            f"Block or rate-limit {source} if it is not an approved scanner.",
            "Review firewall logs for repeated connection attempts.",
            "Check exposed services on the target device.",
        ]
    if "ml" in title or "anomaly" in category:
        return [
            "Review the packet details and payload.",
            "Compare this device against its normal traffic behavior.",
            "Investigate endpoint logs if the anomaly repeats.",
        ]
    return [
        str(alert.get("recommended_action") or "Investigate the source and preserve network evidence."),
        "Review related packets in the timeline.",
        "Use VirusTotal or CVE lookup if the source or service is suspicious.",
    ]


def _alert_port(alert: dict[str, Any]) -> int:
    for key in ("dst_port", "src_port"):
        try:
            value = int(alert.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value:
            return value
    evidence = alert.get("evidence") or {}
    if isinstance(evidence, dict):
        try:
            return int(evidence.get("dst_port") or evidence.get("port") or 0)
        except (TypeError, ValueError):
            return 0
    return 0


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
