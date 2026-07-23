from __future__ import annotations

import threading
from datetime import datetime
from typing import Any

import customtkinter as ctk
from tkinter import messagebox

from gui.theme import COLORS, FONT_BODY, FONT_SECTION, FONT_TITLE, risk_color, severity_color


class ThreatsPage(ctk.CTkFrame):
    ALERT_LIMIT = 24
    REFRESH_DELAY_MS = 10000

    def __init__(self, master: ctk.CTkBaseClass, controller: Any) -> None:
        super().__init__(master, fg_color="transparent")
        self.controller = controller
        self._refresh_job: str | None = None
        self._last_first_alert_id = ""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Threat Intelligence", text_color=COLORS["text"], font=FONT_TITLE).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Alert history, AI explanations, risk scores, remediation, and one-click response actions.", text_color=COLORS["muted"], font=FONT_BODY).grid(row=1, column=0, sticky="w")

        search_panel = ctk.CTkFrame(self, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        search_panel.grid(row=1, column=0, sticky="ew", padx=18, pady=8)
        search_panel.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(search_panel, text="Reputation Check", text_color=COLORS["text"], font=FONT_SECTION).grid(row=0, column=0, padx=14, pady=14, sticky="w")
        self.indicator_entry = ctk.CTkEntry(search_panel, placeholder_text="Enter IP address, e.g. 45.133.32.156")
        self.indicator_entry.grid(row=0, column=1, sticky="ew", padx=8, pady=14)
        ctk.CTkButton(search_panel, text="Check", width=90, command=self._check_indicator).grid(row=0, column=2, padx=(8, 14), pady=14)
        self.reputation_label = ctk.CTkLabel(search_panel, text="Offline-safe simulated intelligence is used when API access is unavailable.", text_color=COLORS["muted"], font=FONT_BODY)
        self.reputation_label.grid(row=1, column=0, columnspan=3, sticky="w", padx=14, pady=(0, 12))

        alerts_panel = ctk.CTkFrame(self, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        alerts_panel.grid(row=2, column=0, sticky="nsew", padx=18, pady=(8, 18))
        alerts_panel.grid_columnconfigure(0, weight=1)
        alerts_panel.grid_rowconfigure(1, weight=1)
        toolbar = ctk.CTkFrame(alerts_panel, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 4))
        toolbar.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(toolbar, text="Threat History Database", text_color=COLORS["text"], font=FONT_SECTION).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(toolbar, text="Refresh", width=90, command=lambda: self.refresh(force=True)).grid(row=0, column=1, padx=(0, 8), sticky="e")
        ctk.CTkButton(toolbar, text="Clear History", width=120, fg_color=COLORS["red"], hover_color="#dc2626", command=self._clear_history).grid(row=0, column=2, sticky="e")
        self.alert_list = ctk.CTkScrollableFrame(alerts_panel, fg_color="transparent")
        self.alert_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._show_placeholder()

    def handle_event(self, event: dict[str, Any]) -> None:
        if not getattr(self, "_netwatch_visible", False):
            return
        if event.get("type") == "intel":
            self._schedule_refresh(200)
        elif event.get("type") == "packet" and event.get("alerts"):
            self._schedule_refresh(self.REFRESH_DELAY_MS)

    def refresh(self, force: bool = False) -> None:
        self._refresh_job = None
        if not getattr(self, "_netwatch_visible", False):
            return
        alerts = self.controller.latest_alerts(self.ALERT_LIMIT)
        first_alert_id = str(alerts[0].get("alert_id", "")) if alerts else ""
        if not force and first_alert_id and first_alert_id == self._last_first_alert_id:
            return
        self._last_first_alert_id = first_alert_id
        for child in self.alert_list.winfo_children():
            child.destroy()
        if not alerts:
            ctk.CTkLabel(self.alert_list, text="No alerts have been stored yet.", text_color=COLORS["muted"], font=FONT_BODY).grid(row=0, column=0, sticky="w", padx=12, pady=14)
            return
        for index, alert in enumerate(alerts):
            self._add_alert_row(index, alert)

    def _schedule_refresh(self, delay_ms: int) -> None:
        if self._refresh_job is None:
            self._refresh_job = self.after(delay_ms, self.refresh)

    def _show_placeholder(self) -> None:
        ctk.CTkLabel(
            self.alert_list,
            text="Open this page or press Refresh to load threat history.",
            text_color=COLORS["muted"],
            font=FONT_BODY,
        ).grid(row=0, column=0, sticky="w", padx=12, pady=14)

    def _add_alert_row(self, index: int, alert: dict[str, Any]) -> None:
        row = ctk.CTkFrame(self.alert_list, fg_color="#0d1424", border_color=severity_color(alert.get("severity", "")), border_width=1, corner_radius=8)
        row.grid(row=index, column=0, sticky="ew", padx=4, pady=5)
        row.grid_columnconfigure(1, weight=1)
        when = datetime.fromtimestamp(float(alert.get("timestamp") or 0)).strftime("%Y-%m-%d %H:%M:%S")
        risk = int(alert.get("risk_score") or float(alert.get("score") or 0) * 100)
        explanation = alert.get("ai_explanation") or alert.get("description") or "This alert matched a detection rule."
        remediation = alert.get("remediation_text") or alert.get("recommended_action") or "Investigate and preserve evidence."
        trusted = alert.get("trusted_device")
        trusted_text = f"\nTrusted device: {trusted} - review before blocking." if trusted else ""
        ctk.CTkLabel(row, text=alert.get("severity", ""), text_color=severity_color(alert.get("severity", "")), font=("Segoe UI", 11, "bold"), width=80).grid(row=0, column=0, padx=12, pady=12, sticky="nw")
        ctk.CTkLabel(
            row,
            text=(
                f"{alert.get('title')}  |  ML score {float(alert.get('score') or 0):.2f}\n"
                f"{when}  {alert.get('src_ip')} -> {alert.get('dst_ip')}  {alert.get('category')}{trusted_text}\n"
                f"AI explanation: {explanation}\n"
                f"Remediation: {remediation}"
            ),
            text_color=COLORS["text"],
            font=FONT_BODY,
            justify="left",
            anchor="w",
            wraplength=800,
        ).grid(row=0, column=1, sticky="ew", padx=8, pady=12)
        ctk.CTkLabel(
            row,
            text=f"RISK\n{risk}/100",
            text_color=risk_color(risk),
            font=("Segoe UI", 12, "bold"),
            width=76,
            justify="center",
        ).grid(row=0, column=2, padx=8, pady=12, sticky="n")
        actions = ctk.CTkFrame(row, fg_color="transparent")
        actions.grid(row=0, column=3, sticky="e", padx=10, pady=8)
        ctk.CTkButton(actions, text="VT", width=54, command=lambda item=alert: self._check_alert(item)).grid(row=0, column=0, padx=3, pady=2)
        ctk.CTkButton(actions, text="CVE", width=54, command=lambda item=alert: self._lookup_alert_cves(item)).grid(row=0, column=1, padx=3, pady=2)
        ctk.CTkButton(actions, text="Block", width=64, fg_color=COLORS["red"], hover_color="#dc2626", command=lambda item=alert: self._block_alert(item)).grid(row=0, column=2, padx=3, pady=2)

    def _check_indicator(self) -> None:
        indicator = self.indicator_entry.get().strip()
        if not indicator:
            return
        result = self.controller.check_reputation(indicator)
        color = COLORS["green"] if result["score"] < 0.35 else COLORS["yellow"] if result["score"] < 0.7 else COLORS["red"]
        self.reputation_label.configure(
            text=(
                f"{indicator}: malicious={result['malicious']} suspicious={result['suspicious']} "
                f"harmless={result['harmless']} score={result['score']:.2f} source={result['source']}"
            ),
            text_color=color,
        )

    def _check_alert(self, alert: dict[str, Any]) -> None:
        def worker() -> None:
            result = self.controller.check_alert_reputation(alert)
            self.after(0, lambda: self._show_reputation_result(str(alert.get("src_ip", "")), result))

        threading.Thread(target=worker, daemon=True).start()

    def _lookup_alert_cves(self, alert: dict[str, Any]) -> None:
        self.reputation_label.configure(text="Looking up CVEs for selected alert service...", text_color=COLORS["muted"])

        def worker() -> None:
            records = self.controller.lookup_alert_cves(alert)
            self.after(0, lambda: self._show_cve_result(alert, records))

        threading.Thread(target=worker, daemon=True).start()

    def _block_alert(self, alert: dict[str, Any]) -> None:
        result = self.controller.block_alert_source(alert)
        color = COLORS["green"] if result["success"] else COLORS["red"]
        mode = "executed" if result["executed"] else "preview"
        self.reputation_label.configure(
            text=f"Firewall {mode}: {result['message']} | {result['command']}",
            text_color=color,
        )

    def _clear_history(self) -> None:
        confirmed = messagebox.askyesno(
            "Clear NetWatch AI history",
            "Clear saved packets, alerts, CVE results, and reputation checks?\n\nSettings and API keys will not be deleted.",
        )
        if not confirmed:
            return
        self.controller.clear_history()
        self._last_first_alert_id = ""
        self.reputation_label.configure(text="History cleared. Start capture again to collect fresh alerts.", text_color=COLORS["green"])
        self.refresh(force=True)

    def _show_reputation_result(self, indicator: str, result: dict[str, Any]) -> None:
        color = COLORS["green"] if result["score"] < 0.35 else COLORS["yellow"] if result["score"] < 0.7 else COLORS["red"]
        self.reputation_label.configure(
            text=(
                f"{indicator}: malicious={result['malicious']} suspicious={result['suspicious']} "
                f"harmless={result['harmless']} score={result['score']:.2f} source={result['source']}"
            ),
            text_color=color,
        )

    def _show_cve_result(self, alert: dict[str, Any], records: list[dict[str, Any]]) -> None:
        if not records:
            self.reputation_label.configure(text="No CVE records found for selected alert.", text_color=COLORS["muted"])
            return
        top = records[0]
        self.reputation_label.configure(
            text=(
                f"CVE lookup for {alert.get('dst_ip')}:{alert.get('dst_port')} -> "
                f"{top.get('cve_id')} {top.get('severity')} CVSS {top.get('cvss')} | {top.get('description')}"
            ),
            text_color=severity_color(str(top.get("severity", ""))),
        )
