from __future__ import annotations

from pathlib import Path

import customtkinter as ctk

from core.auth import AuthManager
from gui.theme import COLORS, FONT_BODY, FONT_SECTION


class LoginWindow(ctk.CTk):
    def __init__(self, app_root: Path, auth: AuthManager) -> None:
        super().__init__()
        self.app_root = app_root
        self.auth = auth
        self.authenticated = False
        self.attempts = 0

        self.title("NetWatch AI Login")
        self.geometry("520x430")
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color=COLORS["bg"])
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        card = ctk.CTkFrame(self, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=12)
        card.grid(row=0, column=0, sticky="nsew", padx=34, pady=34)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text="NetWatch AI", text_color=COLORS["text"], font=("Segoe UI", 28, "bold")).grid(row=0, column=0, sticky="w", padx=24, pady=(24, 2))
        ctk.CTkLabel(card, text="Secure login required before opening the SOC dashboard.", text_color=COLORS["muted"], font=FONT_BODY).grid(row=1, column=0, sticky="w", padx=24, pady=(0, 24))

        ctk.CTkLabel(card, text="Password", text_color=COLORS["text"], font=FONT_SECTION).grid(row=2, column=0, sticky="w", padx=24, pady=(0, 8))
        self.password_entry = ctk.CTkEntry(card, show="*", placeholder_text="Enter login password", height=38)
        self.password_entry.grid(row=3, column=0, sticky="ew", padx=24, pady=(0, 12))
        self.password_entry.bind("<Return>", lambda _: self._login())

        self.status = ctk.CTkLabel(card, text=self._initial_hint(), text_color=COLORS["muted"], font=FONT_BODY, justify="left", anchor="w", wraplength=420)
        self.status.grid(row=4, column=0, sticky="ew", padx=24, pady=(0, 16))

        ctk.CTkButton(card, text="Unlock Dashboard", height=38, fg_color=COLORS["green"], hover_color="#16a34a", command=self._login).grid(row=5, column=0, sticky="ew", padx=24, pady=(0, 10))
        ctk.CTkButton(card, text="Exit", height=34, fg_color="#334155", hover_color="#475569", command=self.destroy).grid(row=6, column=0, sticky="ew", padx=24, pady=(0, 22))

        self.after(150, self.password_entry.focus_set)

    def _initial_hint(self) -> str:
        if self.auth.is_default_password():
            return "Enter the project login password. You can change it later in Settings."
        return "Enter your NetWatch AI password."

    def _login(self) -> None:
        password = self.password_entry.get()
        if self.auth.verify_password(password):
            self.status.configure(text="Login successful. Opening dashboard...", text_color=COLORS["green"])
            self.after(250, self._open_dashboard)
            return

        self.attempts += 1
        self.password_entry.delete(0, "end")
        if self.attempts >= 5:
            self.status.configure(text="Too many failed attempts. Restart the app to try again.", text_color=COLORS["red"])
            self.password_entry.configure(state="disabled")
            return
        self.status.configure(text=f"Incorrect password. Attempts left: {5 - self.attempts}", text_color=COLORS["red"])

    def _open_dashboard(self) -> None:
        self.authenticated = True
        self.destroy()
