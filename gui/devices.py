from __future__ import annotations

from datetime import datetime
from typing import Any

import customtkinter as ctk
from tkinter import messagebox

from gui.theme import COLORS, FONT_BODY, FONT_MONO, FONT_SECTION, FONT_TITLE


class DevicesPage(ctk.CTkFrame):
    TRUST_LEVELS = ["Unknown", "Trusted", "Watch", "Blocked"]

    def __init__(self, master: ctk.CTkBaseClass, controller: Any) -> None:
        super().__init__(master, fg_color="transparent")
        self.controller = controller
        self.selected_device_id: int | None = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Network Devices", text_color=COLORS["text"], font=FONT_TITLE).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="CRUD device inventory plus observed LAN and internet hosts.",
            text_color=COLORS["muted"],
            font=FONT_BODY,
        ).grid(row=1, column=0, sticky="w")
        ctk.CTkButton(header, text="Refresh", width=100, command=self.refresh).grid(row=0, column=1, rowspan=2, sticky="e")

        body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=18, pady=(8, 18))
        body.grid_columnconfigure(0, weight=1)

        inventory_panel = ctk.CTkFrame(body, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        inventory_panel.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        inventory_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(inventory_panel, text="Device Inventory CRUD", text_color=COLORS["text"], font=FONT_SECTION).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))

        form = ctk.CTkFrame(inventory_panel, fg_color="transparent")
        form.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 8))
        for column in range(4):
            form.grid_columnconfigure(column, weight=1)

        self.name_entry = self._entry(form, "Device name", 0, 0)
        self.ip_entry = self._entry(form, "IP address", 0, 1)
        self.mac_entry = self._entry(form, "MAC address", 0, 2)
        self.type_entry = self._entry(form, "Device type", 0, 3)
        self.owner_entry = self._entry(form, "Owner", 1, 0)
        self.notes_entry = self._entry(form, "Notes", 1, 1, columnspan=2)
        self.trust_menu = ctk.CTkOptionMenu(form, values=self.TRUST_LEVELS)
        self.trust_menu.set("Unknown")
        self.trust_menu.grid(row=1, column=3, sticky="ew", padx=5, pady=6)

        actions = ctk.CTkFrame(inventory_panel, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 8))
        actions.grid_columnconfigure(5, weight=1)
        ctk.CTkButton(actions, text="Create", width=100, fg_color=COLORS["green"], hover_color="#16a34a", command=self._create_device).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkButton(actions, text="Update", width=100, command=self._update_device).grid(row=0, column=1, padx=(0, 8))
        ctk.CTkButton(actions, text="Delete", width=100, fg_color=COLORS["red"], hover_color="#dc2626", command=self._delete_selected).grid(row=0, column=2, padx=(0, 8))
        ctk.CTkButton(actions, text="Clear Form", width=110, fg_color="#334155", hover_color="#475569", command=self._clear_form).grid(row=0, column=3, padx=(0, 8))
        self.status = ctk.CTkLabel(actions, text="Create, read, update, and delete monitored devices.", text_color=COLORS["muted"], font=FONT_BODY)
        self.status.grid(row=0, column=5, sticky="e")

        self.inventory_list = ctk.CTkScrollableFrame(inventory_panel, fg_color="transparent", height=260)
        self.inventory_list.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 12))

        observed_panel = ctk.CTkFrame(body, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        observed_panel.grid(row=1, column=0, sticky="ew")
        observed_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(observed_panel, text="Observed Device Table", text_color=COLORS["text"], font=FONT_SECTION).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))
        self.observed_output = ctk.CTkTextbox(observed_panel, height=220, fg_color="#090f1f", text_color=COLORS["text"], font=FONT_MONO, wrap="none")
        self.observed_output.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 14))

        self.refresh()

    def handle_event(self, event: dict[str, Any]) -> None:
        if getattr(self, "_netwatch_visible", False) and event.get("type") == "packet":
            packet_count = int(self.controller.metrics().get("total_packets", 0))
            if packet_count % 25 == 0:
                self._refresh_observed_devices()

    def refresh(self) -> None:
        self._refresh_inventory()
        self._refresh_observed_devices()

    def _entry(self, master: ctk.CTkFrame, placeholder: str, row: int, column: int, columnspan: int = 1) -> ctk.CTkEntry:
        entry = ctk.CTkEntry(master, placeholder_text=placeholder)
        entry.grid(row=row, column=column, columnspan=columnspan, sticky="ew", padx=5, pady=6)
        return entry

    def _payload(self) -> dict[str, str]:
        return {
            "name": self.name_entry.get(),
            "ip_address": self.ip_entry.get(),
            "mac_address": self.mac_entry.get(),
            "device_type": self.type_entry.get(),
            "owner": self.owner_entry.get(),
            "trust_level": self.trust_menu.get(),
            "notes": self.notes_entry.get(),
        }

    def _create_device(self) -> None:
        payload = self._payload()
        if not payload["name"].strip():
            self._set_status("Device name is required.", COLORS["yellow"])
            return
        self.controller.create_device(payload)
        self._set_status("Device created.", COLORS["green"])
        self._clear_form()
        self._refresh_inventory()

    def _update_device(self) -> None:
        if self.selected_device_id is None:
            self._set_status("Select a device first.", COLORS["yellow"])
            return
        payload = self._payload()
        if not payload["name"].strip():
            self._set_status("Device name is required.", COLORS["yellow"])
            return
        self.controller.update_device(self.selected_device_id, payload)
        self._set_status("Device updated.", COLORS["green"])
        self._clear_form()
        self._refresh_inventory()

    def _delete_selected(self) -> None:
        if self.selected_device_id is None:
            self._set_status("Select a device first.", COLORS["yellow"])
            return
        if not messagebox.askyesno("Delete device", "Delete selected device from inventory?"):
            return
        self.controller.delete_device(self.selected_device_id)
        self._set_status("Device deleted.", COLORS["green"])
        self._clear_form()
        self._refresh_inventory()

    def _delete_device(self, device: dict[str, Any]) -> None:
        if not messagebox.askyesno("Delete device", f"Delete {device.get('name', 'this device')}?"):
            return
        self.controller.delete_device(int(device["id"]))
        self._set_status("Device deleted.", COLORS["green"])
        self._clear_form()
        self._refresh_inventory()

    def _load_device(self, device: dict[str, Any]) -> None:
        self.selected_device_id = int(device["id"])
        self._replace_entry(self.name_entry, device.get("name", ""))
        self._replace_entry(self.ip_entry, device.get("ip_address", ""))
        self._replace_entry(self.mac_entry, device.get("mac_address", ""))
        self._replace_entry(self.type_entry, device.get("device_type", ""))
        self._replace_entry(self.owner_entry, device.get("owner", ""))
        self._replace_entry(self.notes_entry, device.get("notes", ""))
        trust_level = str(device.get("trust_level") or "Unknown")
        self.trust_menu.set(trust_level if trust_level in self.TRUST_LEVELS else "Unknown")
        self._set_status(f"Selected device #{self.selected_device_id} for update.", COLORS["blue"])

    def _clear_form(self) -> None:
        self.selected_device_id = None
        for entry in [self.name_entry, self.ip_entry, self.mac_entry, self.type_entry, self.owner_entry, self.notes_entry]:
            entry.delete(0, "end")
        self.trust_menu.set("Unknown")

    def _refresh_inventory(self) -> None:
        for child in self.inventory_list.winfo_children():
            child.destroy()
        devices = self.controller.list_devices()
        if not devices:
            ctk.CTkLabel(
                self.inventory_list,
                text="No saved devices yet. Use the form above to create one.",
                text_color=COLORS["muted"],
                font=FONT_BODY,
            ).grid(row=0, column=0, sticky="w", padx=12, pady=12)
            return

        for index, device in enumerate(devices):
            self._add_inventory_row(index, device)

    def _add_inventory_row(self, index: int, device: dict[str, Any]) -> None:
        trust = str(device.get("trust_level") or "Unknown")
        color = COLORS["green"] if trust == "Trusted" else COLORS["yellow"] if trust == "Watch" else COLORS["red"] if trust == "Blocked" else COLORS["muted"]
        card = ctk.CTkFrame(self.inventory_list, fg_color="#0d1424", border_color=COLORS["border"], border_width=1, corner_radius=8)
        card.grid(row=index, column=0, sticky="ew", padx=4, pady=5)
        card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(card, text=trust.upper(), text_color=color, font=("Segoe UI", 11, "bold"), width=80).grid(row=0, column=0, padx=12, pady=10, sticky="nw")
        ctk.CTkLabel(
            card,
            text=(
                f"{device.get('name')}  |  {device.get('device_type') or 'Device'}\n"
                f"IP: {device.get('ip_address') or '-'}  MAC: {device.get('mac_address') or '-'}  Owner: {device.get('owner') or '-'}\n"
                f"Notes: {device.get('notes') or '-'}"
            ),
            text_color=COLORS["text"],
            font=FONT_BODY,
            justify="left",
            anchor="w",
            wraplength=850,
        ).grid(row=0, column=1, sticky="ew", padx=8, pady=10)
        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.grid(row=0, column=2, sticky="e", padx=10, pady=8)
        ctk.CTkButton(actions, text="Edit", width=70, command=lambda item=device: self._load_device(item)).grid(row=0, column=0, padx=3)
        ctk.CTkButton(actions, text="Delete", width=70, fg_color=COLORS["red"], hover_color="#dc2626", command=lambda item=device: self._delete_device(item)).grid(row=0, column=1, padx=3)

    def _refresh_observed_devices(self) -> None:
        self.observed_output.delete("1.0", "end")
        rows = self.controller.topology_rows()
        if not rows:
            self.observed_output.insert("end", "No observed devices yet.\n\nStart capture from Live Traffic, wait a few seconds, then press Refresh.\n")
            return

        self.observed_output.insert("end", f"{'IP ADDRESS':<18} {'ROLE':<10} {'PACKETS':>8} {'BYTES':>12}  PROTOCOLS\n")
        self.observed_output.insert("end", "-" * 78 + "\n")
        for row in rows:
            last_seen = datetime.fromtimestamp(float(row.get("last_seen") or 0)).strftime("%H:%M:%S")
            self.observed_output.insert(
                "end",
                f"{row.get('ip', ''):<18} {row.get('role', ''):<10} {int(row.get('packets') or 0):>8} "
                f"{int(row.get('bytes') or 0):>12}  {row.get('protocols', '')}\n"
                f"{'':<18} {'last seen':<10} {last_seen}\n\n",
            )

    @staticmethod
    def _replace_entry(entry: ctk.CTkEntry, value: Any) -> None:
        entry.delete(0, "end")
        entry.insert(0, str(value or ""))

    def _set_status(self, message: str, color: str) -> None:
        self.status.configure(text=message, text_color=color)
