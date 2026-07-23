from __future__ import annotations

from typing import Any

import customtkinter as ctk

from gui.theme import COLORS, FONT_BODY, FONT_SECTION, FONT_TITLE


class SettingsPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, controller: Any) -> None:
        super().__init__(master, fg_color="transparent")
        self.controller = controller
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        ctk.CTkLabel(header, text="Settings", text_color=COLORS["text"], font=FONT_TITLE).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Capture mode, trusted devices, API keys, firewall safety, and desktop notification preferences.", text_color=COLORS["muted"], font=FONT_BODY).grid(row=1, column=0, sticky="w")

        body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=18, pady=(8, 18))
        body.grid_columnconfigure(0, weight=1)

        panel = ctk.CTkFrame(body, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        panel.grid(row=0, column=0, sticky="ew")
        panel.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(panel, text="Capture", text_color=COLORS["text"], font=FONT_SECTION).grid(row=0, column=0, columnspan=2, sticky="w", padx=14, pady=(14, 8))

        ctk.CTkLabel(panel, text="Mode", text_color=COLORS["muted"], font=FONT_BODY).grid(row=1, column=0, sticky="w", padx=14, pady=8)
        self.mode = ctk.CTkOptionMenu(panel, values=["simulated", "live"])
        self.mode.set(str(controller.settings.get("capture_mode", "simulated")))
        self.mode.grid(row=1, column=1, sticky="ew", padx=14, pady=8)

        ctk.CTkLabel(panel, text="Interface", text_color=COLORS["muted"], font=FONT_BODY).grid(row=2, column=0, sticky="w", padx=14, pady=8)
        self.interface = ctk.CTkEntry(panel, placeholder_text="Leave blank for default interface")
        self.interface.insert(0, str(controller.settings.get("interface", "")))
        self.interface.grid(row=2, column=1, sticky="ew", padx=14, pady=8)

        ctk.CTkLabel(panel, text="Notifications", text_color=COLORS["muted"], font=FONT_BODY).grid(row=3, column=0, sticky="w", padx=14, pady=8)
        self.notifications = ctk.CTkSwitch(panel, text="Desktop alerts for high and critical threats")
        if controller.settings.get("notifications", True):
            self.notifications.select()
        self.notifications.grid(row=3, column=1, sticky="w", padx=14, pady=8)

        ctk.CTkLabel(panel, text="Response Automation", text_color=COLORS["text"], font=FONT_SECTION).grid(row=4, column=0, columnspan=2, sticky="w", padx=14, pady=(20, 8))

        ctk.CTkLabel(panel, text="Firewall Blocking", text_color=COLORS["muted"], font=FONT_BODY).grid(row=5, column=0, sticky="w", padx=14, pady=8)
        self.firewall_execute = ctk.CTkSwitch(panel, text="Execute firewall commands instead of preview only")
        if controller.settings.get("firewall_execute", False):
            self.firewall_execute.select()
        self.firewall_execute.grid(row=5, column=1, sticky="w", padx=14, pady=8)

        ctk.CTkLabel(panel, text="Trusted Device List", text_color=COLORS["text"], font=FONT_SECTION).grid(row=6, column=0, columnspan=2, sticky="w", padx=14, pady=(20, 8))

        ctk.CTkLabel(panel, text="Safe IPs / MACs", text_color=COLORS["muted"], font=FONT_BODY).grid(row=7, column=0, sticky="nw", padx=14, pady=8)
        self.trusted_devices = ctk.CTkTextbox(panel, height=76, fg_color="#090f1f", text_color=COLORS["text"], font=("Consolas", 11))
        self.trusted_devices.insert("end", "\n".join(controller.settings.get("trusted_devices", [])))
        self.trusted_devices.grid(row=7, column=1, sticky="ew", padx=14, pady=8)
        ctk.CTkLabel(panel, text="One item per line. Trusted devices receive lower risk scores and safer suggestions.", text_color=COLORS["muted"], font=FONT_BODY).grid(row=8, column=1, sticky="w", padx=14, pady=(0, 8))

        ctk.CTkLabel(panel, text="Threat Intelligence", text_color=COLORS["text"], font=FONT_SECTION).grid(row=9, column=0, columnspan=2, sticky="w", padx=14, pady=(20, 8))

        ctk.CTkLabel(panel, text="VirusTotal API Key", text_color=COLORS["muted"], font=FONT_BODY).grid(row=10, column=0, sticky="w", padx=14, pady=8)
        self.vt_key = ctk.CTkEntry(panel, show="*", placeholder_text="Optional")
        self.vt_key.insert(0, str(controller.settings.get("virustotal_api_key", "")))
        self.vt_key.grid(row=10, column=1, sticky="ew", padx=14, pady=8)

        ctk.CTkLabel(panel, text="NVD API Key", text_color=COLORS["muted"], font=FONT_BODY).grid(row=11, column=0, sticky="w", padx=14, pady=8)
        self.nvd_key = ctk.CTkEntry(panel, show="*", placeholder_text="Optional")
        self.nvd_key.insert(0, str(controller.settings.get("nvd_api_key", "")))
        self.nvd_key.grid(row=11, column=1, sticky="ew", padx=14, pady=8)

        ctk.CTkLabel(panel, text="Login Security", text_color=COLORS["text"], font=FONT_SECTION).grid(row=12, column=0, columnspan=2, sticky="w", padx=14, pady=(20, 8))

        ctk.CTkLabel(panel, text="Current Password", text_color=COLORS["muted"], font=FONT_BODY).grid(row=13, column=0, sticky="w", padx=14, pady=8)
        self.current_password = ctk.CTkEntry(panel, show="*", placeholder_text="Required to change password")
        self.current_password.grid(row=13, column=1, sticky="ew", padx=14, pady=8)

        ctk.CTkLabel(panel, text="New Password", text_color=COLORS["muted"], font=FONT_BODY).grid(row=14, column=0, sticky="w", padx=14, pady=8)
        self.new_password = ctk.CTkEntry(panel, show="*", placeholder_text="Minimum 6 characters")
        self.new_password.grid(row=14, column=1, sticky="ew", padx=14, pady=8)

        ctk.CTkLabel(panel, text="Confirm Password", text_color=COLORS["muted"], font=FONT_BODY).grid(row=15, column=0, sticky="w", padx=14, pady=8)
        self.confirm_password = ctk.CTkEntry(panel, show="*", placeholder_text="Repeat new password")
        self.confirm_password.grid(row=15, column=1, sticky="ew", padx=14, pady=8)

        ctk.CTkButton(panel, text="Change Login Password", command=self._change_password).grid(row=16, column=0, columnspan=2, sticky="ew", padx=14, pady=(8, 4))

        self.status = ctk.CTkLabel(panel, text="API keys are optional; firewall blocking stays in safe preview mode unless enabled.", text_color=COLORS["muted"], font=FONT_BODY)
        self.status.grid(row=17, column=0, columnspan=2, sticky="w", padx=14, pady=(12, 4))
        ctk.CTkButton(panel, text="Save Settings", command=self._save, fg_color=COLORS["green"], hover_color="#16a34a").grid(row=18, column=0, columnspan=2, sticky="ew", padx=14, pady=(8, 16))

    def _save(self) -> None:
        self.controller.save_settings(
            {
                "capture_mode": self.mode.get(),
                "interface": self.interface.get().strip(),
                "notifications": bool(self.notifications.get()),
                "firewall_execute": bool(self.firewall_execute.get()),
                "trusted_devices": self.trusted_devices.get("1.0", "end").strip(),
                "virustotal_api_key": self.vt_key.get().strip(),
                "nvd_api_key": self.nvd_key.get().strip(),
            }
        )
        self.status.configure(text="Settings saved. Restart capture for interface/mode changes to take effect.", text_color=COLORS["green"])

    def _change_password(self) -> None:
        success, message = self.controller.change_login_password(
            self.current_password.get(),
            self.new_password.get(),
            self.confirm_password.get(),
        )
        self.status.configure(text=message, text_color=COLORS["green"] if success else COLORS["red"])
        if success:
            for entry in [self.current_password, self.new_password, self.confirm_password]:
                entry.delete(0, "end")
