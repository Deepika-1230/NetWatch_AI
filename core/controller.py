from __future__ import annotations

import json
import logging
import queue
import threading
import time
from pathlib import Path
from typing import Any

from core.auth import AuthManager
from core.blocker import FirewallBlocker
from core.analyzer import PacketRecord, ThreatAlert, ThreatAnalyzer
from core.arp_detector import ARPSpoofDetector
from core.dns_detector import DNSPoisoningDetector
from core.geolocator import GeoLocator
from core.intel import NVDClient, VirusTotalClient
from core.ml_engine import IsolationForestEngine
from core.notifier import DesktopNotifier
from core.payload_inspector import PayloadInspector
from core.sniffer import PacketSniffer
from core.threat_enrichment import build_incident_timeline, enrich_alert, normalize_trusted_devices, trusted_device_match
from core.topology_mapper import NetworkTopology
from database.threat_store import ThreatStore
from reports.report_generator import ForensicReportGenerator

LOGGER = logging.getLogger(__name__)


class NetWatchController:
    """Application service layer shared by all GUI pages."""

    def __init__(self, app_root: Path) -> None:
        self.app_root = app_root
        self.config_path = app_root / "database" / "settings.json"
        self.settings = self._load_settings()
        self.auth = AuthManager(app_root)

        self.events: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=8000)
        self.store = ThreatStore(app_root / "database" / "netwatch_ai.db")
        self.ml_engine = IsolationForestEngine(app_root / "models" / "trained_model.joblib")
        self.payload_inspector = PayloadInspector()
        self.arp_detector = ARPSpoofDetector()
        self.dns_detector = DNSPoisoningDetector()
        self.analyzer = ThreatAnalyzer()
        self.topology = NetworkTopology()
        self.geolocator = GeoLocator()
        self.notifier = DesktopNotifier(enabled=bool(self.settings.get("notifications", True)))
        self.reporter = ForensicReportGenerator(app_root / "reports")
        self.vt_client = VirusTotalClient(api_key=self.settings.get("virustotal_api_key", ""))
        self.nvd_client = NVDClient(api_key=self.settings.get("nvd_api_key", ""))
        self.blocker = FirewallBlocker(app_root / "logs" / "firewall_blocks.log")
        self.sniffer: PacketSniffer | None = None
        self.processing_lock = threading.RLock()

    @property
    def capture_running(self) -> bool:
        return bool(self.sniffer and self.sniffer.running)

    def start_capture(self) -> None:
        if self.capture_running:
            return
        self.sniffer = PacketSniffer(
            packet_callback=self.process_packet,
            error_callback=lambda message: self._put_event({"type": "status", "message": message}),
            interface=self.settings.get("interface", ""),
            mode=self.settings.get("capture_mode", "simulated"),
        )
        self.sniffer.start()
        self._put_event({"type": "status", "message": f"Capture started in {self.settings.get('capture_mode', 'simulated')} mode"})

    def stop_capture(self) -> None:
        if self.sniffer:
            self.sniffer.stop()
        self._put_event({"type": "status", "message": "Capture stopped"})

    def process_packet(self, packet: PacketRecord, source: str = "live") -> None:
        with self.processing_lock:
            anomaly = self.ml_engine.update(packet)
            payload_findings = self.payload_inspector.inspect(packet.payload)
            arp_findings = self.arp_detector.inspect(packet)
            dns_findings = self.dns_detector.inspect(packet)
            alerts = self.analyzer.analyze(
                packet,
                anomaly.score,
                payload_findings=payload_findings,
                arp_findings=arp_findings,
                dns_findings=dns_findings,
            )
            self.topology.observe(packet)
            try:
                self.store.add_packet(packet, anomaly.score)
                for alert in alerts:
                    self._apply_trust_policy(alert)
                    self.store.add_alert(alert)
                    self.notifier.notify(alert)
            except Exception:
                LOGGER.exception("Could not persist packet analysis")

        self._put_event(
            {
                "type": "packet",
                "packet": packet,
                "anomaly": anomaly,
                "alerts": alerts,
                "payload_findings": payload_findings,
                "source": source,
            }
        )

    def poll_events(self, limit: int = 250) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for _ in range(limit):
            try:
                items.append(self.events.get_nowait())
            except queue.Empty:
                break
        return items

    def analyze_pcap(self, path: Path) -> dict[str, Any]:
        started = time.time()
        sniffer = PacketSniffer(packet_callback=lambda _: None, mode="simulated")
        previous_alerts = int(self.store.summary().get("alert_count", 0))
        records = sniffer.read_pcap(path)
        for record in records:
            self.process_packet(record, source="pcap")
        current_alerts = int(self.store.summary().get("alert_count", previous_alerts))
        return {
            "path": str(path),
            "packets": len(records),
            "elapsed_seconds": round(time.time() - started, 2),
            "alerts": max(0, current_alerts - previous_alerts),
        }

    def check_reputation(self, indicator: str) -> dict[str, Any]:
        result = self.vt_client.check_ip(indicator.strip()).as_dict()
        self.store.add_reputation(result)
        self._put_event({"type": "intel", "result": result})
        return result

    def check_alert_reputation(self, alert: dict[str, Any]) -> dict[str, Any]:
        return self.check_reputation(str(alert.get("src_ip", "")).strip())

    def lookup_cves(self, query: str) -> list[dict[str, Any]]:
        records = [record.as_dict() for record in self.nvd_client.search(query)]
        self.store.add_cves(query, records)
        self._put_event({"type": "cves", "query": query, "records": records})
        return records

    def lookup_alert_cves(self, alert: dict[str, Any]) -> list[dict[str, Any]]:
        service = self._service_query_for_alert(alert)
        return self.lookup_cves(service)

    def block_alert_source(self, alert: dict[str, Any]) -> dict[str, Any]:
        source_ip = str(alert.get("src_ip", "")).strip()
        result = self.blocker.block(source_ip, execute=bool(self.settings.get("firewall_execute", False)))
        response = {
            "ip": result.ip,
            "command": result.command,
            "executed": result.executed,
            "success": result.success,
            "message": result.message,
        }
        self._put_event({"type": "block", "result": response})
        return response

    def geo_threat_points(self, limit: int = 160) -> list[dict[str, Any]]:
        points: list[dict[str, Any]] = []
        for alert in self.latest_alerts(limit):
            geo = self.geolocator.lookup(str(alert.get("src_ip", ""))).as_dict()
            points.append(
                {
                    **geo,
                    "severity": alert.get("severity"),
                    "title": alert.get("title"),
                    "timestamp": alert.get("timestamp"),
                    "src_ip": alert.get("src_ip"),
                }
            )
        return points

    def export_report(self) -> Path:
        topology_path = self.app_root / "reports" / "topology_snapshot.png"
        rendered_topology = self.topology.render(topology_path)
        alerts = self.store.latest_alerts(80)
        metrics = self.metrics()
        report_path = self.reporter.create_report(alerts, metrics, rendered_topology)
        self._put_event({"type": "report", "path": str(report_path)})
        return report_path

    def inspect_payload_text(self, text: str) -> dict[str, Any]:
        payload = text.encode("utf-8", errors="ignore")
        findings = self.payload_inspector.inspect(payload)
        return {
            "findings": findings,
            "hexdump": self.payload_inspector.hexdump(payload, limit=2048),
        }

    def metrics(self) -> dict[str, Any]:
        live = self.analyzer.metrics()
        persisted = self.store.summary()
        return {**persisted, **live, "capture_running": self.capture_running}

    def latest_alerts(self, limit: int = 80) -> list[dict[str, Any]]:
        return [self.enrich_alert(alert) for alert in self.store.latest_alerts(limit)]

    def enrich_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        return enrich_alert(alert, trusted_devices=self.trusted_devices())

    def trusted_devices(self) -> list[str]:
        return normalize_trusted_devices(
            [
                *normalize_trusted_devices(self.settings.get("trusted_devices", [])),
                *self.store.trusted_device_identifiers(),
            ]
        )

    def incident_timeline(self, limit: int = 40) -> list[dict[str, Any]]:
        return build_incident_timeline(self.latest_alerts(limit))

    def latest_packets(self, limit: int = 80) -> list[dict[str, Any]]:
        return self.store.latest_packets(limit)

    def clear_history(self) -> None:
        self.store.clear_history()
        self._put_event({"type": "history_cleared", "message": "Saved packet and threat history cleared"})

    def create_device(self, device: dict[str, Any]) -> int:
        device_id = self.store.create_device(**self._clean_device_payload(device))
        self._put_event({"type": "device_inventory", "message": "Device created"})
        return device_id

    def list_devices(self) -> list[dict[str, Any]]:
        return self.store.list_devices()

    def update_device(self, device_id: int, device: dict[str, Any]) -> None:
        self.store.update_device(device_id, **self._clean_device_payload(device))
        self._put_event({"type": "device_inventory", "message": "Device updated"})

    def delete_device(self, device_id: int) -> None:
        self.store.delete_device(device_id)
        self._put_event({"type": "device_inventory", "message": "Device deleted"})

    def topology_rows(self) -> list[dict[str, Any]]:
        return self.topology.as_table()

    def save_settings(self, settings: dict[str, Any]) -> None:
        if "trusted_devices" in settings:
            settings["trusted_devices"] = normalize_trusted_devices(settings["trusted_devices"])
        self.settings.update(settings)
        self.notifier.enabled = bool(self.settings.get("notifications", True))
        self.vt_client.api_key = self.settings.get("virustotal_api_key", "")
        self.nvd_client.api_key = self.settings.get("nvd_api_key", "")
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(self.settings, indent=2), encoding="utf-8")
        self._put_event({"type": "status", "message": "Settings saved"})

    def change_login_password(self, current_password: str, new_password: str, confirm_password: str) -> tuple[bool, str]:
        if new_password != confirm_password:
            return False, "New password and confirmation do not match."
        success, message = self.auth.change_password(current_password, new_password)
        self._put_event({"type": "status", "message": message})
        return success, message

    def close(self) -> None:
        self.stop_capture()
        self.store.close()

    def _load_settings(self) -> dict[str, Any]:
        defaults = {
            "capture_mode": "simulated",
            "interface": "",
            "notifications": True,
            "virustotal_api_key": "",
            "nvd_api_key": "",
            "dashboard_refresh_ms": 650,
            "firewall_execute": False,
            "trusted_devices": [],
        }
        if not self.config_path.exists():
            return defaults
        try:
            loaded = json.loads(self.config_path.read_text(encoding="utf-8"))
            return {**defaults, **loaded}
        except Exception:
            LOGGER.warning("Could not load settings, using defaults", exc_info=True)
            return defaults

    def _put_event(self, event: dict[str, Any]) -> None:
        try:
            self.events.put_nowait(event)
        except queue.Full:
            try:
                self.events.get_nowait()
                self.events.put_nowait(event)
            except queue.Empty:
                pass

    @staticmethod
    def _clean_device_payload(device: dict[str, Any]) -> dict[str, str]:
        return {
            "name": str(device.get("name") or "Unnamed device").strip() or "Unnamed device",
            "ip_address": str(device.get("ip_address") or "").strip(),
            "mac_address": str(device.get("mac_address") or "").strip(),
            "device_type": str(device.get("device_type") or "").strip(),
            "owner": str(device.get("owner") or "").strip(),
            "trust_level": str(device.get("trust_level") or "Unknown").strip() or "Unknown",
            "notes": str(device.get("notes") or "").strip(),
        }

    def _apply_trust_policy(self, alert: ThreatAlert) -> None:
        trusted_match = trusted_device_match(alert.as_dict(), self.trusted_devices())
        if not trusted_match:
            return
        alert.evidence = {**alert.evidence, "trusted_device": trusted_match}
        alert.recommended_action = (
            f"Trusted device match ({trusted_match}). Review context before blocking. "
            f"{alert.recommended_action}"
        )
        if alert.severity in {"LOW", "MEDIUM"}:
            alert.severity = "LOW"
            alert.score = min(alert.score, 0.34)
            alert.description = (
                f"{alert.description} The source or destination is trusted, so this alert is downgraded for review."
            )

    @staticmethod
    def _service_query_for_alert(alert: dict[str, Any]) -> str:
        evidence = alert.get("evidence") or {}
        service = evidence.get("service") if isinstance(evidence, dict) else None
        if service:
            return str(service)
        port = int(alert.get("dst_port") or 0)
        protocol = str(alert.get("protocol") or "TCP")
        port_map = {
            21: "FTP",
            22: "OpenSSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS server",
            80: "HTTP server",
            443: "HTTPS server",
            445: "SMB",
            3306: "MySQL",
            3389: "Remote Desktop",
            8080: "HTTP proxy",
        }
        return port_map.get(port, f"{protocol} port {port}" if port else protocol)
