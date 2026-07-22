from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from core.analyzer import PacketRecord, ThreatAlert

LOGGER = logging.getLogger(__name__)


class ThreatStore:
    """Thread-safe SQLite repository for packets, alerts, and intelligence lookups."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def add_packet(self, packet: PacketRecord, anomaly_score: float) -> None:
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO packets (
                    timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length,
                    ttl, dns_query, payload_preview, summary, anomaly_score, extra_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    packet.timestamp,
                    packet.src_ip,
                    packet.dst_ip,
                    packet.protocol,
                    packet.src_port,
                    packet.dst_port,
                    packet.length,
                    packet.ttl,
                    packet.dns_query,
                    packet.payload_preview,
                    packet.summary,
                    anomaly_score,
                    json.dumps(packet.extra, default=str),
                ),
            )
            self.conn.commit()

    def add_alert(self, alert: ThreatAlert) -> None:
        with self.lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, severity, title, description, src_ip, dst_ip,
                    protocol, score, category, evidence_json, recommended_action
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.timestamp,
                    alert.severity,
                    alert.title,
                    alert.description,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.protocol,
                    alert.score,
                    alert.category,
                    json.dumps(alert.evidence, default=str),
                    alert.recommended_action,
                ),
            )
            self.conn.commit()

    def latest_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def latest_packets(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def search_alerts(self, query: str, limit: int = 80) -> list[dict[str, Any]]:
        needle = f"%{query.strip()}%"
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT * FROM alerts
                WHERE title LIKE ? OR description LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR category LIKE ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (needle, needle, needle, needle, needle, limit),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def add_reputation(self, result: dict[str, Any]) -> None:
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO reputation_checks (
                    timestamp, indicator, indicator_type, malicious, suspicious,
                    harmless, undetected, score, source, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    time.time(),
                    result.get("indicator"),
                    result.get("indicator_type"),
                    result.get("malicious"),
                    result.get("suspicious"),
                    result.get("harmless"),
                    result.get("undetected"),
                    result.get("score"),
                    result.get("source"),
                    json.dumps(result.get("details", {}), default=str),
                ),
            )
            self.conn.commit()

    def add_cves(self, query: str, records: list[dict[str, Any]]) -> None:
        with self.lock:
            for record in records:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO cve_results (
                        cve_id, query, description, severity, cvss, published, source, url, cached_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.get("cve_id"),
                        query,
                        record.get("description"),
                        record.get("severity"),
                        record.get("cvss"),
                        record.get("published"),
                        record.get("source"),
                        record.get("url"),
                        time.time(),
                    ),
                )
            self.conn.commit()

    def clear_history(self) -> None:
        with self.lock:
            self.conn.executescript(
                """
                DELETE FROM packets;
                DELETE FROM alerts;
                DELETE FROM reputation_checks;
                DELETE FROM cve_results;
                DELETE FROM sqlite_sequence WHERE name IN ('packets', 'reputation_checks');
                PRAGMA wal_checkpoint(TRUNCATE);
                """
            )
            self.conn.commit()

    def create_device(
        self,
        *,
        name: str,
        ip_address: str = "",
        mac_address: str = "",
        device_type: str = "",
        owner: str = "",
        trust_level: str = "Unknown",
        notes: str = "",
    ) -> int:
        now = time.time()
        with self.lock:
            cursor = self.conn.execute(
                """
                INSERT INTO device_inventory (
                    name, ip_address, mac_address, device_type, owner,
                    trust_level, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (name, ip_address, mac_address, device_type, owner, trust_level, notes, now, now),
            )
            self.conn.commit()
            return int(cursor.lastrowid)

    def list_devices(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM device_inventory ORDER BY updated_at DESC, id DESC"
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def update_device(
        self,
        device_id: int,
        *,
        name: str,
        ip_address: str = "",
        mac_address: str = "",
        device_type: str = "",
        owner: str = "",
        trust_level: str = "Unknown",
        notes: str = "",
    ) -> None:
        with self.lock:
            self.conn.execute(
                """
                UPDATE device_inventory
                SET name = ?, ip_address = ?, mac_address = ?, device_type = ?,
                    owner = ?, trust_level = ?, notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (name, ip_address, mac_address, device_type, owner, trust_level, notes, time.time(), device_id),
            )
            self.conn.commit()

    def delete_device(self, device_id: int) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM device_inventory WHERE id = ?", (device_id,))
            self.conn.commit()

    def trusted_device_identifiers(self) -> list[str]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT ip_address, mac_address
                FROM device_inventory
                WHERE LOWER(trust_level) = 'trusted'
                """
            ).fetchall()
        values: list[str] = []
        for row in rows:
            if row["ip_address"]:
                values.append(str(row["ip_address"]))
            if row["mac_address"]:
                values.append(str(row["mac_address"]))
        return values

    def summary(self) -> dict[str, Any]:
        with self.lock:
            packet_count = self.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            alert_count = self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            critical_count = self.conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
            high_count = self.conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'").fetchone()[0]
            bytes_seen = self.conn.execute("SELECT COALESCE(SUM(length), 0) FROM packets").fetchone()[0]
        return {
            "packet_count": packet_count,
            "alert_count": alert_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "bytes_seen": bytes_seen,
        }

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    def _init_schema(self) -> None:
        with self.lock:
            self.conn.executescript(
                """
                PRAGMA journal_mode = WAL;

                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    length INTEGER NOT NULL,
                    ttl INTEGER,
                    dns_query TEXT,
                    payload_preview TEXT,
                    summary TEXT,
                    anomaly_score REAL DEFAULT 0,
                    extra_json TEXT DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
                CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);

                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    score REAL,
                    category TEXT,
                    evidence_json TEXT DEFAULT '{}',
                    recommended_action TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

                CREATE TABLE IF NOT EXISTS reputation_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    indicator TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    malicious INTEGER DEFAULT 0,
                    suspicious INTEGER DEFAULT 0,
                    harmless INTEGER DEFAULT 0,
                    undetected INTEGER DEFAULT 0,
                    score REAL DEFAULT 0,
                    source TEXT,
                    details_json TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS cve_results (
                    cve_id TEXT PRIMARY KEY,
                    query TEXT,
                    description TEXT,
                    severity TEXT,
                    cvss REAL,
                    published TEXT,
                    source TEXT,
                    url TEXT,
                    cached_at REAL
                );

                CREATE TABLE IF NOT EXISTS device_inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    ip_address TEXT DEFAULT '',
                    mac_address TEXT DEFAULT '',
                    device_type TEXT DEFAULT '',
                    owner TEXT DEFAULT '',
                    trust_level TEXT DEFAULT 'Unknown',
                    notes TEXT DEFAULT '',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_device_inventory_ip ON device_inventory(ip_address);
                CREATE INDEX IF NOT EXISTS idx_device_inventory_trust ON device_inventory(trust_level);
                """
            )
            self.conn.commit()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        for key in ["evidence_json", "extra_json", "details_json"]:
            if key in item and item[key]:
                try:
                    item[key.replace("_json", "")] = json.loads(item[key])
                except json.JSONDecodeError:
                    item[key.replace("_json", "")] = {}
        return item
