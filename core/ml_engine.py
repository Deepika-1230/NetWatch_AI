from __future__ import annotations

import logging
import math
import random
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.analyzer import PacketFeatureExtractor, PacketRecord, payload_entropy

LOGGER = logging.getLogger(__name__)

try:
    from joblib import dump, load
except Exception:  # pragma: no cover - optional dependency
    dump = None
    load = None

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except Exception:  # pragma: no cover - optional dependency
    np = None
    IsolationForest = None
    StandardScaler = None


@dataclass(slots=True)
class AnomalyResult:
    score: float
    is_anomaly: bool
    reason: str
    features: list[float]


class IsolationForestEngine:
    """Isolation Forest model with a deterministic heuristic fallback."""

    def __init__(self, model_path: Path) -> None:
        self.model_path = model_path
        self.lock = threading.Lock()
        self.samples: list[list[float]] = []
        self.model: Any | None = None
        self.scaler: Any | None = None
        self.packet_count = 0
        self.available = bool(IsolationForest and StandardScaler and np)
        if self.available and not self._load():
            self._fit_bootstrap()

    def update(self, packet: PacketRecord) -> AnomalyResult:
        features = PacketFeatureExtractor.extract(packet)
        self.packet_count += 1
        with self.lock:
            self.samples.append(features)
            if len(self.samples) > 1200:
                self.samples = self.samples[-1200:]

            if self.available and self.model is not None and self.scaler is not None:
                score = self._model_score(features)
                if self.packet_count % 240 == 0 and len(self.samples) >= 180:
                    self._refit_recent()
                return AnomalyResult(
                    score=score,
                    is_anomaly=score >= 0.82,
                    reason="Isolation Forest" if score < 0.82 else "Isolation Forest outlier",
                    features=features,
                )

        score, reason = self._heuristic_score(packet)
        return AnomalyResult(score=score, is_anomaly=score >= 0.82, reason=reason, features=features)

    def _model_score(self, features: list[float]) -> float:
        arr = np.array([features], dtype=float)
        scaled = self.scaler.transform(arr)
        raw = float(self.model.decision_function(scaled)[0])
        pred = int(self.model.predict(scaled)[0])
        score = 1 / (1 + math.exp(5.5 * raw))
        if pred == -1:
            score = max(score, 0.78)
        return max(0.0, min(1.0, score))

    def _fit_bootstrap(self) -> None:
        baseline = self._synthetic_baseline(420)
        self.scaler = StandardScaler()
        scaled = self.scaler.fit_transform(np.array(baseline, dtype=float))
        self.model = IsolationForest(n_estimators=160, contamination=0.045, random_state=42)
        self.model.fit(scaled)
        self.samples = baseline[-240:]
        self._save()
        LOGGER.info("Fitted bootstrap Isolation Forest baseline with %s samples", len(baseline))

    def _refit_recent(self) -> None:
        try:
            baseline = self._synthetic_baseline(220) + self.samples[-500:]
            self.scaler = StandardScaler()
            scaled = self.scaler.fit_transform(np.array(baseline, dtype=float))
            self.model = IsolationForest(n_estimators=160, contamination=0.05, random_state=42)
            self.model.fit(scaled)
            self._save()
            LOGGER.info("Refitted Isolation Forest with recent traffic sample")
        except Exception:
            LOGGER.exception("Could not refit Isolation Forest")

    def _load(self) -> bool:
        if not self.model_path.exists() or not load:
            return False
        try:
            bundle = load(self.model_path)
            self.model = bundle["model"]
            self.scaler = bundle["scaler"]
            LOGGER.info("Loaded ML model from %s", self.model_path)
            return True
        except Exception:
            LOGGER.exception("Could not load model, fitting a fresh baseline")
            try:
                self.model_path.unlink(missing_ok=True)
            except Exception:
                LOGGER.warning("Could not remove corrupted ML model", exc_info=True)
            return False

    def _save(self) -> None:
        if not dump:
            return
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.model_path.with_suffix(self.model_path.suffix + ".tmp")
            dump({"model": self.model, "scaler": self.scaler}, tmp_path)
            tmp_path.replace(self.model_path)
        except Exception:
            LOGGER.warning("Could not save ML model", exc_info=True)

    @staticmethod
    def _synthetic_baseline(size: int) -> list[list[float]]:
        records: list[list[float]] = []
        protocols = [6, 17, 53, 443, 80]
        common_ports = [53, 80, 123, 443, 445, 993, 995, 3389]
        for _ in range(size):
            length = max(60, random.gauss(520, 270))
            dst_port = random.choice(common_ports)
            src_port = random.randint(1024, 65535)
            proto = 17 if dst_port in {53, 123} else random.choice(protocols)
            records.append(
                [
                    float(length),
                    float(src_port),
                    float(dst_port),
                    float(proto),
                    1.0,
                    random.choice([0.0, 1.0]),
                    float(max(0, random.gauss(80, 55))),
                    random.uniform(1.5, 5.2),
                    random.choice([64.0, 128.0, 255.0]),
                    random.uniform(-1.0, 1.0),
                    random.uniform(-1.0, 1.0),
                ]
            )
        return records

    @staticmethod
    def _heuristic_score(packet: PacketRecord) -> tuple[float, str]:
        score = 0.12
        reasons: list[str] = []
        if packet.length > 1500:
            score += 0.24
            reasons.append("jumbo payload")
        if packet.dst_port in {22, 23, 445, 3389, 5900, 6379, 9200}:
            score += 0.22
            reasons.append("sensitive service")
        if payload_entropy(packet.payload) > 6.4 and len(packet.payload) > 180:
            score += 0.25
            reasons.append("high entropy payload")
        if packet.protocol == "DNS" and packet.dns_query and len(packet.dns_query) > 55:
            score += 0.18
            reasons.append("unusual DNS query")
        if packet.flags and "S" in packet.flags and packet.length < 90:
            score += 0.11
            reasons.append("SYN probe")
        return min(1.0, score), ", ".join(reasons) or "heuristic baseline"
