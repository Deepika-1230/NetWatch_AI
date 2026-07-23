from __future__ import annotations

from datetime import datetime
from typing import Any

import customtkinter as ctk

from core.analyzer import PacketRecord, ThreatAlert
from gui.theme import COLORS, FONT_BODY, FONT_MONO, FONT_SECTION, FONT_TITLE, severity_color


class MetricCard(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, label: str, color: str = COLORS["blue"]) -> None:
        super().__init__(master, fg_color=COLORS["panel_glass"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        self.grid_columnconfigure(0, weight=1)
        self.label = ctk.CTkLabel(self, text=label.upper(), text_color=COLORS["muted"], font=("Segoe UI", 10, "bold"))
        self.label.grid(row=0, column=0, sticky="w", padx=14, pady=(12, 0))
        self.value = ctk.CTkLabel(self, text="0", text_color=color, font=("Segoe UI", 24, "bold"))
        self.value.grid(row=1, column=0, sticky="w", padx=14, pady=(2, 12))

    def set_value(self, text: str) -> None:
        self.value.configure(text=text)


class DashboardPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, controller: Any) -> None:
        super().__init__(master, fg_color="transparent")
        self.controller = controller
        self.packet_lines = 0
        self.alert_cards: list[ctk.CTkFrame] = []

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Live Packet Capture Dashboard", font=FONT_TITLE, text_color=COLORS["text"]).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="Isolation Forest anomaly scoring, protocol integrity checks, and packet stream evidence.",
            font=FONT_BODY,
            text_color=COLORS["muted"],
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        actions = ctk.CTkFrame(header, fg_color="transparent")
        actions.grid(row=0, column=1, rowspan=2, sticky="e")
        self.start_btn = ctk.CTkButton(actions, text="Start Capture", command=self.controller.start_capture, fg_color=COLORS["green"], hover_color="#16a34a")
        self.start_btn.grid(row=0, column=0, padx=(0, 8))
        self.stop_btn = ctk.CTkButton(actions, text="Stop", command=self.controller.stop_capture, fg_color="#334155", hover_color="#475569", width=80)
        self.stop_btn.grid(row=0, column=1)

        cards = ctk.CTkFrame(self, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", padx=18, pady=8)
        for index in range(5):
            cards.grid_columnconfigure(index, weight=1, uniform="metric")
        self.card_packets = MetricCard(cards, "Packets", COLORS["blue"])
        self.card_threats = MetricCard(cards, "Threats", COLORS["red"])
        self.card_score = MetricCard(cards, "Anomaly Score", COLORS["yellow"])
        self.card_rate = MetricCard(cards, "Packets/sec", COLORS["green"])
        self.card_uptime = MetricCard(cards, "Capture", COLORS["purple"])
        for index, card in enumerate([self.card_packets, self.card_threats, self.card_score, self.card_rate, self.card_uptime]):
            card.grid(row=0, column=index, sticky="nsew", padx=5)

        middle = ctk.CTkFrame(self, fg_color="transparent")
        middle.grid(row=2, column=0, sticky="nsew", padx=18, pady=8)
        middle.grid_columnconfigure(0, weight=2)
        middle.grid_columnconfigure(1, weight=1)
        middle.grid_rowconfigure(0, weight=1)

        stream_panel = ctk.CTkFrame(middle, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        stream_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        stream_panel.grid_rowconfigure(1, weight=1)
        stream_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(stream_panel, text="Packet Stream Terminal", font=FONT_SECTION, text_color=COLORS["text"]).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))
        self.stream = ctk.CTkTextbox(stream_panel, fg_color="#050816", text_color="#b7f7c8", font=FONT_MONO, wrap="none", height=270)
        self.stream.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.stream.insert("end", "NetWatch AI packet stream ready. Start capture to begin.\n")

        score_panel = ctk.CTkFrame(middle, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        score_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        score_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(score_panel, text="Threat Score", font=FONT_SECTION, text_color=COLORS["text"]).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 8))
        self.score_bar = ctk.CTkProgressBar(score_panel, progress_color=COLORS["yellow"])
        self.score_bar.grid(row=1, column=0, sticky="ew", padx=14, pady=(4, 6))
        self.score_bar.set(0)
        self.score_label = ctk.CTkLabel(score_panel, text="Baseline traffic", text_color=COLORS["muted"], font=FONT_BODY)
        self.score_label.grid(row=2, column=0, sticky="w", padx=14)
        ctk.CTkLabel(score_panel, text="Top Talkers", font=FONT_SECTION, text_color=COLORS["text"]).grid(row=3, column=0, sticky="w", padx=14, pady=(24, 6))
        self.talkers_box = ctk.CTkTextbox(score_panel, height=130, fg_color="#0a1020", text_color=COLORS["text"], font=FONT_MONO)
        self.talkers_box.grid(row=4, column=0, sticky="ew", padx=14, pady=(0, 12))

        alerts_panel = ctk.CTkFrame(self, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        alerts_panel.grid(row=3, column=0, sticky="nsew", padx=18, pady=(8, 18))
        alerts_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(alerts_panel, text="Active Threat Alerts", font=FONT_SECTION, text_color=COLORS["text"]).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))
        self.alerts_container = ctk.CTkScrollableFrame(alerts_panel, fg_color="transparent", height=180)
        self.alerts_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._show_empty_alerts()
        self.after(1000, self.refresh_metrics)

    def handle_event(self, event: dict[str, Any]) -> None:
        if event.get("type") == "packet":
            packet: PacketRecord = event["packet"]
            anomaly = event["anomaly"]
            alerts = event.get("alerts", [])
            self._append_packet_line(packet, anomaly.score, alerts)
            if alerts:
                self._prepend_alerts(alerts)
            self.score_bar.set(min(1.0, anomaly.score))
            self.score_label.configure(text=f"{anomaly.reason} | score {anomaly.score:.2f}")
        elif event.get("type") == "status":
            self._append_status(str(event.get("message", "")))

    def refresh_metrics(self) -> None:
        if not getattr(self, "_netwatch_visible", False):
            self.after(1200, self.refresh_metrics)
            return
        metrics = self.controller.metrics()
        alert_total = sum(metrics.get("threats", {}).values()) or metrics.get("alert_count", 0)
        self.card_packets.set_value(f"{metrics.get('total_packets', 0):,}")
        self.card_threats.set_value(str(alert_total))
        self.card_rate.set_value(f"{metrics.get('packets_per_second', 0):.1f}")
        self.card_uptime.set_value("LIVE" if metrics.get("capture_running") else "IDLE")
        if self.score_label.cget("text") == "Baseline traffic":
            self.card_score.set_value("0.00")
        else:
            self.card_score.set_value(self.score_label.cget("text").split("score ")[-1])
        self.talkers_box.delete("1.0", "end")
        for ip, count in metrics.get("top_talkers", []):
            self.talkers_box.insert("end", f"{ip:<18} {count:>5} packets\n")
        self.after(int(self.controller.settings.get("dashboard_refresh_ms", 650)), self.refresh_metrics)

    def _append_packet_line(self, packet: PacketRecord, score: float, alerts: list[ThreatAlert]) -> None:
        verdict = "ALERT" if alerts else ("ANOMALY" if score >= 0.82 else "normal")
        line = (
            f"{packet.short_time}  {packet.src_ip:<15}:{str(packet.src_port or '-'):>5}  -> "
            f"{packet.dst_ip:<15}:{str(packet.dst_port or '-'):>5}  {packet.protocol:<5} "
            f"{packet.length:>5}B  score={score:.2f}  {verdict}  {packet.dns_query or packet.payload_preview[:42]}\n"
        )
        self.stream.insert("end", line)
        self.stream.see("end")
        self.packet_lines += 1
        if self.packet_lines > 360:
            self.stream.delete("1.0", "80.0")
            self.packet_lines -= 80

    def _append_status(self, message: str) -> None:
        self.stream.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.stream.see("end")

    def _prepend_alerts(self, alerts: list[ThreatAlert]) -> None:
        if self.alert_cards and getattr(self.alert_cards[0], "is_empty_state", False):
            for card in self.alert_cards:
                card.destroy()
            self.alert_cards.clear()
        for alert in alerts:
            card = ctk.CTkFrame(self.alerts_container, fg_color="#101827", border_color=severity_color(alert.severity), border_width=1, corner_radius=8)
            card.grid_columnconfigure(1, weight=1)
            badge = ctk.CTkLabel(card, text=alert.severity, text_color=severity_color(alert.severity), font=("Segoe UI", 11, "bold"))
            badge.grid(row=0, column=0, padx=12, pady=10, sticky="nw")
            text = ctk.CTkLabel(
                card,
                text=f"{alert.title}\n{alert.src_ip} -> {alert.dst_ip} | {alert.description}",
                text_color=COLORS["text"],
                justify="left",
                anchor="w",
                wraplength=860,
                font=FONT_BODY,
            )
            text.grid(row=0, column=1, padx=8, pady=10, sticky="ew")
            card.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
            for existing in self.alert_cards:
                existing.grid_configure(row=int(existing.grid_info().get("row", 0)) + 1)
            self.alert_cards.insert(0, card)
        for card in self.alert_cards[12:]:
            card.destroy()
        self.alert_cards = self.alert_cards[:12]

    def _show_empty_alerts(self) -> None:
        card = ctk.CTkFrame(self.alerts_container, fg_color="#0d1424", corner_radius=8)
        card.is_empty_state = True
        ctk.CTkLabel(card, text="No active alerts yet. Simulated mode will generate realistic SOC events.", text_color=COLORS["muted"], font=FONT_BODY).pack(padx=16, pady=18)
        card.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        self.alert_cards.append(card)
