from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import customtkinter as ctk
from tkinter import filedialog, messagebox

from gui.theme import COLORS, FONT_BODY, FONT_MONO, FONT_SECTION, FONT_TITLE, severity_color


class ForensicsPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, controller: Any) -> None:
        super().__init__(master, fg_color="transparent")
        self.controller = controller
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=18, pady=(18, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Digital Forensics Workbench", text_color=COLORS["text"], font=FONT_TITLE).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Offline PCAP analysis, payload inspection, CVE lookup, and forensic report export.", text_color=COLORS["muted"], font=FONT_BODY).grid(row=1, column=0, sticky="w")

        pcap_panel = self._panel("Offline PCAP Analysis")
        pcap_panel.grid(row=1, column=0, sticky="nsew", padx=(18, 8), pady=8)
        pcap_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(pcap_panel, text="Import a .pcap/.pcapng file and run the same detection pipeline used by live capture.", text_color=COLORS["muted"], font=FONT_BODY, wraplength=480).grid(row=1, column=0, sticky="w", padx=14, pady=(0, 8))
        ctk.CTkButton(pcap_panel, text="Choose PCAP", command=self._choose_pcap).grid(row=2, column=0, sticky="ew", padx=14, pady=8)
        self.pcap_output = ctk.CTkTextbox(pcap_panel, fg_color="#090f1f", text_color=COLORS["text"], font=FONT_MONO, height=120)
        self.pcap_output.grid(row=3, column=0, sticky="nsew", padx=14, pady=(4, 14))

        report_panel = self._panel("Forensic PDF Report")
        report_panel.grid(row=1, column=1, sticky="nsew", padx=(8, 18), pady=8)
        report_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(report_panel, text="Export alert history, metrics, recommended actions, and a topology snapshot.", text_color=COLORS["muted"], font=FONT_BODY, wraplength=480).grid(row=1, column=0, sticky="w", padx=14, pady=(0, 8))
        ctk.CTkButton(report_panel, text="Export Investigation PDF", command=self._export_report, fg_color=COLORS["green"], hover_color="#16a34a").grid(row=2, column=0, sticky="ew", padx=14, pady=8)
        self.report_output = ctk.CTkTextbox(report_panel, fg_color="#090f1f", text_color=COLORS["text"], font=FONT_MONO, height=120)
        self.report_output.grid(row=3, column=0, sticky="nsew", padx=14, pady=(4, 14))

        payload_panel = self._panel("Packet Payload Inspector")
        payload_panel.grid(row=2, column=0, sticky="nsew", padx=(18, 8), pady=(8, 18))
        payload_panel.grid_rowconfigure(2, weight=1)
        payload_panel.grid_columnconfigure(0, weight=1)
        self.payload_input = ctk.CTkTextbox(payload_panel, height=120, fg_color="#090f1f", text_color=COLORS["text"], font=FONT_MONO)
        self.payload_input.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 8))
        self.payload_input.insert("end", "GET /search?q=' OR 1=1 UNION SELECT password FROM users-- HTTP/1.1\\r\\nHost: example.local\\r\\n\\r\\n")
        ctk.CTkButton(payload_panel, text="Inspect Payload", command=self._inspect_payload).grid(row=2, column=0, sticky="ew", padx=14, pady=4)
        self.payload_output = ctk.CTkTextbox(payload_panel, fg_color="#050816", text_color="#b7f7c8", font=FONT_MONO, height=190)
        self.payload_output.grid(row=3, column=0, sticky="nsew", padx=14, pady=(8, 14))

        cve_panel = self._panel("CVE Vulnerability Lookup")
        cve_panel.grid(row=2, column=1, sticky="nsew", padx=(8, 18), pady=(8, 18))
        cve_panel.grid_columnconfigure(0, weight=1)
        self.cve_entry = ctk.CTkEntry(cve_panel, placeholder_text="Search service or product, e.g. OpenSSH 8.2")
        self.cve_entry.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 8))
        self.cve_entry.insert(0, "OpenSSH 8.2")
        ctk.CTkButton(cve_panel, text="Lookup NVD CVEs", command=self._lookup_cves).grid(row=2, column=0, sticky="ew", padx=14, pady=4)
        self.cve_output = ctk.CTkScrollableFrame(cve_panel, fg_color="transparent", height=260)
        self.cve_output.grid(row=3, column=0, sticky="nsew", padx=10, pady=(8, 12))

    def _panel(self, title: str) -> ctk.CTkFrame:
        panel = ctk.CTkFrame(self, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        ctk.CTkLabel(panel, text=title, text_color=COLORS["text"], font=FONT_SECTION).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 8))
        return panel

    def _choose_pcap(self) -> None:
        path = filedialog.askopenfilename(title="Choose PCAP", filetypes=[("Packet captures", "*.pcap *.pcapng"), ("All files", "*.*")])
        if not path:
            return
        self.pcap_output.delete("1.0", "end")
        self.pcap_output.insert("end", f"Analyzing {path}...\n")

        def worker() -> None:
            try:
                result = self.controller.analyze_pcap(Path(path))
                message = f"Complete: {result['packets']} packets processed in {result['elapsed_seconds']}s.\nAlerts in database: {result['alerts']}\n"
            except Exception as exc:
                message = f"PCAP analysis failed: {exc}\n"
            self.after(0, lambda: self._write_text(self.pcap_output, message))

        threading.Thread(target=worker, daemon=True).start()

    def _export_report(self) -> None:
        self.report_output.delete("1.0", "end")
        self.report_output.insert("end", "Generating report...\n")

        def worker() -> None:
            try:
                path = self.controller.export_report()
                message = f"Report created:\n{path.name}\nSaved in the reports folder.\n"
            except Exception as exc:
                message = f"Report generation failed: {exc}\n"
            self.after(0, lambda: self._write_text(self.report_output, message))

        threading.Thread(target=worker, daemon=True).start()

    def _inspect_payload(self) -> None:
        text = self.payload_input.get("1.0", "end").strip()
        result = self.controller.inspect_payload_text(text)
        self.payload_output.delete("1.0", "end")
        if result["findings"]:
            self.payload_output.insert("end", "Findings:\n")
            for finding in result["findings"]:
                self.payload_output.insert("end", f"- {finding['severity']} {finding['title']} at offset {finding['offset']}: {finding['matched']}\n")
        else:
            self.payload_output.insert("end", "No suspicious payload rules matched.\n")
        self.payload_output.insert("end", "\nHex/ASCII view:\n")
        self.payload_output.insert("end", result["hexdump"])

    def _lookup_cves(self) -> None:
        query = self.cve_entry.get().strip()
        if not query:
            return
        for child in self.cve_output.winfo_children():
            child.destroy()

        def worker() -> None:
            records = self.controller.lookup_cves(query)
            self.after(0, lambda: self._render_cves(records))

        threading.Thread(target=worker, daemon=True).start()

    def _render_cves(self, records: list[dict[str, Any]]) -> None:
        if not records:
            ctk.CTkLabel(self.cve_output, text="No CVEs found.", text_color=COLORS["muted"]).grid(row=0, column=0, sticky="w", padx=10, pady=10)
            return
        for index, record in enumerate(records):
            frame = ctk.CTkFrame(self.cve_output, fg_color="#0d1424", border_color=severity_color(record.get("severity", "")), border_width=1, corner_radius=8)
            frame.grid(row=index, column=0, sticky="ew", padx=4, pady=5)
            frame.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(
                frame,
                text=f"{record['cve_id']} | {record['severity']} | CVSS {record['cvss']}\n{record['description']}",
                text_color=COLORS["text"],
                font=FONT_BODY,
                justify="left",
                wraplength=480,
            ).grid(row=0, column=0, sticky="ew", padx=12, pady=10)

    @staticmethod
    def _write_text(widget: ctk.CTkTextbox, message: str) -> None:
        widget.insert("end", message)
        widget.see("end")
