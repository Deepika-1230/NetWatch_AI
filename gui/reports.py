from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

import customtkinter as ctk

from gui.theme import COLORS, FONT_BODY, FONT_MONO, FONT_SECTION, FONT_TITLE


class ReportsPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, controller: Any) -> None:
        super().__init__(master, fg_color="transparent")
        self.controller = controller
        self.reports_dir = controller.app_root / "reports"
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Reports Center", text_color=COLORS["text"], font=FONT_TITLE).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="Create and review forensic PDF reports from saved evidence.",
            text_color=COLORS["muted"],
            font=FONT_BODY,
        ).grid(row=1, column=0, sticky="w")
        ctk.CTkButton(header, text="Export PDF", width=110, fg_color=COLORS["green"], hover_color="#16a34a", command=self._export_report).grid(row=0, column=1, rowspan=2, padx=(0, 8), sticky="e")
        ctk.CTkButton(header, text="Open Folder", width=110, command=self._open_folder).grid(row=0, column=2, rowspan=2, sticky="e")

        panel = ctk.CTkFrame(self, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        panel.grid(row=1, column=0, sticky="nsew", padx=18, pady=(8, 18))
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(2, weight=1)
        ctk.CTkLabel(panel, text="Saved Reports", text_color=COLORS["text"], font=FONT_SECTION).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))
        self.status = ctk.CTkLabel(panel, text="Reports are saved inside the project reports folder.", text_color=COLORS["muted"], font=FONT_BODY)
        self.status.grid(row=1, column=0, sticky="w", padx=14, pady=(0, 8))
        self.output = ctk.CTkTextbox(panel, fg_color="#090f1f", text_color=COLORS["text"], font=FONT_MONO, wrap="none")
        self.output.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 14))
        self.refresh()

    def refresh(self) -> None:
        self.output.delete("1.0", "end")
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        files = sorted(self.reports_dir.glob("*.pdf"), key=lambda path: path.stat().st_mtime, reverse=True)
        if not files:
            self.output.insert("end", "No PDF reports yet.\n\nClick Export PDF after collecting packets or alerts.\n")
            return
        for path in files[:30]:
            stat = path.stat()
            size_kb = max(1, round(stat.st_size / 1024))
            self.output.insert("end", f"{path.name}\n  {size_kb} KB  |  saved in reports folder\n\n")

    def _export_report(self) -> None:
        self.status.configure(text="Generating forensic report...", text_color=COLORS["muted"])

        def worker() -> None:
            try:
                path = self.controller.export_report()
                message = f"Report created: {path.name}"
                color = COLORS["green"]
            except Exception as exc:
                message = f"Report failed: {exc}"
                color = COLORS["red"]
            self.after(0, lambda: self._finish_export(message, color))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_export(self, message: str, color: str) -> None:
        self.status.configure(text=message, text_color=color)
        self.refresh()

    def _open_folder(self) -> None:
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(Path(self.reports_dir))  # type: ignore[attr-defined]
        except Exception:
            self.status.configure(text="Could not open the reports folder automatically.", text_color=COLORS["muted"])
