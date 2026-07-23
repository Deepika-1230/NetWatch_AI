from __future__ import annotations

from typing import Any

import customtkinter as ctk

from gui.theme import COLORS, FONT_BODY, FONT_SECTION, FONT_TITLE, risk_color, severity_color


class TimelinePage(ctk.CTkFrame):
    ALERT_LIMIT = 12
    REFRESH_DELAY_MS = 10000

    def __init__(self, master: ctk.CTkBaseClass, controller: Any) -> None:
        super().__init__(master, fg_color="transparent")
        self.controller = controller
        self._refresh_job: str | None = None
        self._last_signature = ""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Incident Timeline", text_color=COLORS["text"], font=FONT_TITLE).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="Chronological investigation view with observed traffic, AI explanation, risk score, and suggested response.",
            text_color=COLORS["muted"],
            font=FONT_BODY,
        ).grid(row=1, column=0, sticky="w")
        ctk.CTkButton(header, text="Refresh", width=100, command=lambda: self.refresh(force=True)).grid(row=0, column=1, rowspan=2, sticky="e")

        panel = ctk.CTkFrame(self, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        panel.grid(row=1, column=0, sticky="nsew", padx=18, pady=(8, 18))
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(panel, text="Forensic Sequence", text_color=COLORS["text"], font=FONT_SECTION).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))
        self.timeline_list = ctk.CTkScrollableFrame(panel, fg_color="transparent")
        self.timeline_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._show_placeholder()

    def handle_event(self, event: dict[str, Any]) -> None:
        if not getattr(self, "_netwatch_visible", False):
            return
        if event.get("type") == "packet" and event.get("alerts"):
            self._schedule_refresh(self.REFRESH_DELAY_MS)

    def refresh(self, force: bool = False) -> None:
        self._refresh_job = None
        if not getattr(self, "_netwatch_visible", False):
            return
        items = self.controller.incident_timeline(self.ALERT_LIMIT)
        signature = str(items[-1].get("timestamp", "")) if items else ""
        if not force and signature and signature == self._last_signature:
            return
        self._last_signature = signature
        for child in self.timeline_list.winfo_children():
            child.destroy()
        if not items:
            ctk.CTkLabel(
                self.timeline_list,
                text="No incidents yet. Start simulated capture to generate a forensic timeline.",
                text_color=COLORS["muted"],
                font=FONT_BODY,
            ).grid(row=0, column=0, sticky="w", padx=12, pady=14)
            return

        for row_index, item in enumerate(items):
            self._add_timeline_row(row_index, item)

    def _schedule_refresh(self, delay_ms: int) -> None:
        if self._refresh_job is None:
            self._refresh_job = self.after(delay_ms, self.refresh)

    def _show_placeholder(self) -> None:
        ctk.CTkLabel(
            self.timeline_list,
            text="Open this page or press Refresh to load the incident timeline.",
            text_color=COLORS["muted"],
            font=FONT_BODY,
        ).grid(row=0, column=0, sticky="w", padx=12, pady=14)

    def _add_timeline_row(self, index: int, item: dict[str, Any]) -> None:
        severity = str(item.get("severity") or "LOW")
        risk = int(item.get("risk_score") or 0)
        card = ctk.CTkFrame(
            self.timeline_list,
            fg_color="#0d1424",
            border_color=severity_color(severity),
            border_width=1,
            corner_radius=8,
        )
        card.grid(row=index, column=0, sticky="ew", padx=4, pady=5)
        card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(card, text=str(item.get("time") or "--:--:--"), text_color=COLORS["muted"], font=("Segoe UI", 11, "bold"), width=70).grid(row=0, column=0, sticky="n", padx=12, pady=12)
        ctk.CTkLabel(
            card,
            text=f"{item.get('phase')} | {item.get('title')}\n{item.get('detail')}",
            text_color=COLORS["text"],
            font=FONT_BODY,
            justify="left",
            anchor="w",
            wraplength=900,
        ).grid(row=0, column=1, sticky="ew", padx=8, pady=12)
        ctk.CTkLabel(card, text=f"RISK\n{risk}", text_color=risk_color(risk), font=("Segoe UI", 12, "bold"), width=70, justify="center").grid(row=0, column=2, padx=12, pady=12, sticky="n")
