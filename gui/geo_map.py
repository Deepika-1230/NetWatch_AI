from __future__ import annotations

from typing import Any

import customtkinter as ctk
import tkinter as tk

from gui.theme import COLORS, FONT_BODY, FONT_TITLE, severity_color


class GeoMapPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, controller: Any) -> None:
        super().__init__(master, fg_color="transparent")
        self.controller = controller
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="IP Geolocation Threat Map", text_color=COLORS["text"], font=FONT_TITLE).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Threat source locations plotted from GeoIP enrichment and offline demo coordinates.", text_color=COLORS["muted"], font=FONT_BODY).grid(row=1, column=0, sticky="w")
        ctk.CTkButton(header, text="Refresh Map", width=110, command=self.refresh).grid(row=0, column=1, rowspan=2, sticky="e")

        panel = ctk.CTkFrame(self, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        panel.grid(row=1, column=0, sticky="nsew", padx=18, pady=(8, 18))
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(0, weight=1)
        self.canvas = tk.Canvas(panel, bg=COLORS["panel"], highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.after(1000, self.refresh)

    def handle_event(self, event: dict[str, Any]) -> None:
        if event.get("type") == "packet" and event.get("alerts"):
            self.refresh()

    def refresh(self) -> None:
        if not getattr(self, "_netwatch_visible", False):
            return
        width = max(self.canvas.winfo_width(), 860)
        height = max(self.canvas.winfo_height(), 520)
        self.canvas.delete("all")
        self.canvas.create_rectangle(0, 0, width, height, fill=COLORS["panel"], outline="")
        self.canvas.create_text(18, 18, anchor="w", text="Threat origins", fill=COLORS["text"], font=("Segoe UI", 13, "bold"))
        self.canvas.create_text(18, 42, anchor="w", text="Private LAN traffic is pinned near Kathmandu for demo context.", fill=COLORS["muted"], font=("Segoe UI", 10))

        for lon in range(-180, 181, 45):
            x = self._x(lon, width)
            self.canvas.create_line(x, 72, x, height - 26, fill="#1f2a3d")
        for lat in range(-60, 61, 30):
            y = self._y(lat, height)
            self.canvas.create_line(16, y, width - 16, y, fill="#1f2a3d")

        points = self.controller.geo_threat_points(160)
        if not points:
            self.canvas.create_text(width / 2, height / 2, text="No geolocated threats yet.", fill=COLORS["muted"], font=("Segoe UI", 14))
            return

        for point in points:
            lat = point.get("latitude")
            lon = point.get("longitude")
            if lat is None or lon is None:
                continue
            x = self._x(float(lon), width)
            y = self._y(float(lat), height)
            color = severity_color(str(point.get("severity", "")))
            self.canvas.create_oval(x - 6, y - 6, x + 6, y + 6, fill=color, outline="")
            self.canvas.create_text(
                x + 10,
                y,
                anchor="w",
                text=f"{point.get('src_ip')}  {point.get('city')}, {point.get('country')}",
                fill=COLORS["text"],
                font=("Segoe UI", 9),
            )

    @staticmethod
    def _x(longitude: float, width: int) -> float:
        return (longitude + 180) / 360 * width

    @staticmethod
    def _y(latitude: float, height: int) -> float:
        return (90 - latitude) / 180 * height
