from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

try:
    from fpdf import FPDF
except Exception:  # pragma: no cover - optional dependency
    FPDF = None


class ForensicReportGenerator:
    """Creates a PDF-ready incident report from NetWatch evidence."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def create_report(
        self,
        alerts: list[dict[str, Any]],
        metrics: dict[str, Any],
        topology_image: Path | None = None,
        title: str = "NetWatch AI Forensic Investigation Report",
    ) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.output_dir / f"netwatch_forensic_report_{timestamp}.pdf"
        if FPDF:
            self._create_with_fpdf(output_path, title, alerts, metrics, topology_image)
        else:
            self._create_minimal_pdf(output_path, title, alerts, metrics)
        return output_path

    def _create_with_fpdf(
        self,
        output_path: Path,
        title: str,
        alerts: list[dict[str, Any]],
        metrics: dict[str, Any],
        topology_image: Path | None,
    ) -> None:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_fill_color(11, 16, 32)
        pdf.rect(0, 0, 210, 30, style="F")
        pdf.set_text_color(219, 234, 254)
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 10, title, ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, f"Generated: {datetime.now().isoformat(timespec='seconds')}", ln=True)

        pdf.ln(8)
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "Executive Summary", ln=True)
        pdf.set_font("Helvetica", "", 10)
        summary = (
            f"Packets observed: {metrics.get('total_packets') or metrics.get('packet_count', 0)} | "
            f"Bytes observed: {metrics.get('total_bytes') or metrics.get('bytes_seen', 0)} | "
            f"Alerts: {len(alerts)}"
        )
        pdf.multi_cell(0, 6, summary)

        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "Priority Findings", ln=True)
        pdf.set_font("Helvetica", "", 9)
        if not alerts:
            pdf.multi_cell(0, 6, "No alerts were recorded in the selected evidence window.")
        for alert in alerts[:30]:
            when = datetime.fromtimestamp(float(alert.get("timestamp", 0))).strftime("%Y-%m-%d %H:%M:%S")
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*self._severity_color(alert.get("severity", "LOW")))
            pdf.cell(0, 6, f"{alert.get('severity')} - {alert.get('title')}", ln=True)
            pdf.set_text_color(15, 23, 42)
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(
                0,
                5,
                f"{when} | {alert.get('src_ip')} -> {alert.get('dst_ip')} | "
                f"ML Score {float(alert.get('score') or 0):.2f} | Risk {int(alert.get('risk_score') or 0)}/100\n"
                f"{alert.get('ai_explanation') or alert.get('description')}\n"
                f"Action: {alert.get('remediation_text') or alert.get('recommended_action', 'Investigate and preserve evidence.')}",
            )
            pdf.ln(1)

        if topology_image and topology_image.exists():
            pdf.add_page()
            pdf.set_text_color(15, 23, 42)
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 8, "Network Topology Snapshot", ln=True)
            pdf.image(str(topology_image), x=10, w=190)

        pdf.output(str(output_path))

    @staticmethod
    def _severity_color(severity: str) -> tuple[int, int, int]:
        return {
            "CRITICAL": (220, 38, 38),
            "HIGH": (234, 88, 12),
            "MEDIUM": (202, 138, 4),
            "LOW": (37, 99, 235),
        }.get(severity, (51, 65, 85))

    @staticmethod
    def _create_minimal_pdf(output_path: Path, title: str, alerts: list[dict[str, Any]], metrics: dict[str, Any]) -> None:
        lines = [
            title,
            f"Generated: {datetime.now().isoformat(timespec='seconds')}",
            f"Packets observed: {metrics.get('total_packets') or metrics.get('packet_count', 0)}",
            f"Alerts: {len(alerts)}",
            "",
        ]
        for alert in alerts[:20]:
            lines.append(f"{alert.get('severity')} - {alert.get('title')} - {alert.get('src_ip')} -> {alert.get('dst_ip')}")
            lines.append(str(alert.get("description", ""))[:100])
        text = "\n".join(lines).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream = f"BT /F1 10 Tf 40 780 Td 12 TL ({text}) Tj ET"
        objects = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            f"<< /Length {len(stream.encode('latin-1', errors='replace'))} >>\nstream\n{stream}\nendstream",
        ]
        body = "%PDF-1.4\n"
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(len(body.encode("latin-1", errors="replace")))
            body += f"{index} 0 obj\n{obj}\nendobj\n"
        xref = len(body.encode("latin-1", errors="replace"))
        body += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
        for offset in offsets[1:]:
            body += f"{offset:010d} 00000 n \n"
        body += f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
        output_path.write_bytes(body.encode("latin-1", errors="replace"))
