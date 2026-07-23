from __future__ import annotations

from collections import Counter, deque
from typing import Any

import customtkinter as ctk

from gui.theme import COLORS, FONT_BODY, FONT_MONO, FONT_SECTION, FONT_TITLE

try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import networkx as nx
except Exception:  # pragma: no cover - optional dependency
    FigureCanvasTkAgg = None
    Figure = None
    nx = None


class AnalyticsPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, controller: Any) -> None:
        super().__init__(master, fg_color="transparent")
        self.controller = controller
        self.scores: deque[float] = deque(maxlen=80)
        self.packet_counts: deque[int] = deque(maxlen=80)
        self.protocols: Counter[str] = Counter()
        self._refresh_job: str | None = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Traffic Analytics & Topology", text_color=COLORS["text"], font=FONT_TITLE).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Protocol mix, anomaly trend, and live network graph built from observed traffic.", text_color=COLORS["muted"], font=FONT_BODY).grid(row=1, column=0, sticky="w")
        ctk.CTkButton(header, text="Refresh", width=90, command=self.refresh).grid(row=0, column=1, rowspan=2, sticky="e")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=18, pady=(8, 18))
        body.grid_columnconfigure(0, weight=2)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        chart_panel = ctk.CTkFrame(body, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        chart_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        chart_panel.grid_rowconfigure(1, weight=1)
        chart_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(chart_panel, text="Behavior Graphs", text_color=COLORS["text"], font=FONT_SECTION).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))

        topology_panel = ctk.CTkFrame(body, fg_color=COLORS["panel"], border_color=COLORS["border"], border_width=1, corner_radius=10)
        topology_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        topology_panel.grid_rowconfigure(2, weight=1)
        topology_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(topology_panel, text="Discovered Hosts", text_color=COLORS["text"], font=FONT_SECTION).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))
        ctk.CTkLabel(topology_panel, text="Nodes are ranked by observed bytes.", text_color=COLORS["muted"], font=FONT_BODY).grid(row=1, column=0, sticky="w", padx=14)
        self.hosts_box = ctk.CTkTextbox(topology_panel, fg_color="#090f1f", text_color=COLORS["text"], font=FONT_MONO)
        self.hosts_box.grid(row=2, column=0, sticky="nsew", padx=14, pady=12)

        if Figure is None:
            ctk.CTkLabel(chart_panel, text="Install matplotlib and networkx to enable analytics charts.", text_color=COLORS["muted"]).grid(row=1, column=0, padx=18, pady=18)
            self.figure = None
            self.canvas = None
        else:
            self.figure = Figure(figsize=(9, 6), dpi=100, facecolor=COLORS["panel"])
            self.ax_trend = self.figure.add_subplot(221)
            self.ax_proto = self.figure.add_subplot(222)
            self.ax_topology = self.figure.add_subplot(212)
            self.canvas = FigureCanvasTkAgg(self.figure, master=chart_panel)
            self.canvas.get_tk_widget().grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._schedule_refresh(1500)

    def handle_event(self, event: dict[str, Any]) -> None:
        if event.get("type") == "packet":
            self.scores.append(float(event["anomaly"].score))
            self.packet_counts.append(1)
            self.protocols[event["packet"].protocol] += 1

    def refresh(self) -> None:
        self._refresh_job = None
        if not getattr(self, "_netwatch_visible", False):
            self._schedule_refresh(2500)
            return
        self._update_hosts()
        if self.figure is not None:
            self._update_charts()
        self._schedule_refresh(1800)

    def _schedule_refresh(self, delay_ms: int) -> None:
        if self._refresh_job is None:
            self._refresh_job = self.after(delay_ms, self.refresh)

    def _update_hosts(self) -> None:
        rows = self.controller.topology_rows()
        self.hosts_box.delete("1.0", "end")
        if not rows:
            self.hosts_box.insert("end", "No topology data yet.\n")
            return
        for row in rows:
            self.hosts_box.insert(
                "end",
                f"{row['ip']:<16} {row['role']:<8} {row['packets']:>5} pkts  {row['bytes']:>8} B\n"
                f"  {row['protocols']}\n\n",
            )

    def _update_charts(self) -> None:
        for ax in [self.ax_trend, self.ax_proto, self.ax_topology]:
            ax.clear()
            ax.set_facecolor("#0b1020")
            ax.tick_params(colors="#94a3b8", labelsize=8)
            for spine in ax.spines.values():
                spine.set_color("#26344d")

        scores = list(self.scores) or [0]
        self.ax_trend.plot(scores, color=COLORS["yellow"], linewidth=2)
        self.ax_trend.fill_between(range(len(scores)), scores, color=COLORS["yellow"], alpha=0.12)
        self.ax_trend.set_title("Anomaly Score Trend", color=COLORS["text"], fontsize=10)
        self.ax_trend.set_ylim(0, 1)

        metrics = self.controller.metrics()
        protocol_counts = metrics.get("protocol_counts", {}) or dict(self.protocols)
        if protocol_counts:
            names = list(protocol_counts.keys())[:8]
            values = [protocol_counts[name] for name in names]
            self.ax_proto.bar(names, values, color=COLORS["blue"])
        self.ax_proto.set_title("Protocol Mix", color=COLORS["text"], fontsize=10)
        self.ax_proto.tick_params(axis="x", rotation=25)

        graph = self.controller.topology.graph_snapshot()
        self.ax_topology.set_title("Network Topology", color=COLORS["text"], fontsize=10)
        self.ax_topology.axis("off")
        if graph is not None and graph.number_of_nodes() > 0 and nx is not None:
            pos = nx.spring_layout(graph, seed=5, k=0.55)
            colors = ["#22c55e" if graph.nodes[node].get("role") == "Internal" else "#38bdf8" for node in graph.nodes()]
            sizes = [350 + min(1600, graph.nodes[node].get("packets", 1) * 18) for node in graph.nodes()]
            nx.draw_networkx_edges(graph, pos, ax=self.ax_topology, edge_color="#64748b", alpha=0.38)
            nx.draw_networkx_nodes(graph, pos, ax=self.ax_topology, node_color=colors, node_size=sizes, edgecolors="#dbeafe", linewidths=0.8)
            nx.draw_networkx_labels(graph, pos, ax=self.ax_topology, font_size=7, font_color="#e5e7eb")
        else:
            self.ax_topology.text(0.5, 0.5, "Start capture to build topology", color="#94a3b8", ha="center", va="center")

        self.figure.tight_layout(pad=1.4)
        self.canvas.draw_idle()
