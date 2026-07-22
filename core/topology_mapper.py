from __future__ import annotations

import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.analyzer import PacketRecord, is_private_ip

LOGGER = logging.getLogger(__name__)

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import networkx as nx
except Exception:  # pragma: no cover - optional dependency
    plt = None
    nx = None


@dataclass(slots=True)
class HostNode:
    ip: str
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes_seen: int = 0
    protocols: Counter[str] = field(default_factory=Counter)
    mac: str | None = None
    hostname: str | None = None
    role: str = "External"


class NetworkTopology:
    """Maintains a live communication graph from observed packets."""

    def __init__(self) -> None:
        self.nodes: dict[str, HostNode] = {}
        self.edges: Counter[tuple[str, str]] = Counter()

    def observe(self, packet: PacketRecord) -> None:
        for ip in [packet.src_ip, packet.dst_ip]:
            self._touch_node(ip, packet)
        key = tuple(sorted((packet.src_ip, packet.dst_ip)))
        self.edges[key] += 1

    def graph_snapshot(self) -> Any:
        if nx is None:
            return None
        graph = nx.Graph()
        for ip, node in self.nodes.items():
            graph.add_node(
                ip,
                packets=node.packets,
                bytes=node.bytes_seen,
                role=node.role,
                label=node.hostname or ip,
            )
        for (src, dst), weight in self.edges.items():
            if src in self.nodes and dst in self.nodes:
                graph.add_edge(src, dst, weight=weight)
        return graph

    def top_hosts(self, limit: int = 8) -> list[HostNode]:
        return sorted(self.nodes.values(), key=lambda node: node.bytes_seen, reverse=True)[:limit]

    def render(self, output_path: Path) -> Path | None:
        if nx is None or plt is None:
            LOGGER.warning("NetworkX/Matplotlib are unavailable; topology render skipped")
            return None
        graph = self.graph_snapshot()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig = plt.figure(figsize=(10, 6), facecolor="#0b1020")
        ax = fig.add_subplot(111)
        ax.set_facecolor("#0b1020")
        ax.set_title("NetWatch AI Network Topology", color="#dbeafe", fontsize=14, pad=12)
        ax.axis("off")
        if graph.number_of_nodes() == 0:
            ax.text(0.5, 0.5, "No topology data yet", color="#94a3b8", ha="center", va="center")
        else:
            pos = nx.spring_layout(graph, k=0.7, seed=7)
            node_colors = ["#22c55e" if self.nodes[node].role == "Internal" else "#38bdf8" for node in graph.nodes()]
            node_sizes = [450 + min(1800, self.nodes[node].packets * 16) for node in graph.nodes()]
            edge_widths = [1 + min(8, graph.edges[edge]["weight"] / 8) for edge in graph.edges()]
            nx.draw_networkx_edges(graph, pos, ax=ax, alpha=0.4, width=edge_widths, edge_color="#64748b")
            nx.draw_networkx_nodes(
                graph,
                pos,
                ax=ax,
                node_color=node_colors,
                node_size=node_sizes,
                linewidths=1.2,
                edgecolors="#e2e8f0",
                alpha=0.92,
            )
            nx.draw_networkx_labels(graph, pos, ax=ax, font_size=8, font_color="#e5e7eb")
        fig.tight_layout()
        fig.savefig(output_path, dpi=160, facecolor=fig.get_facecolor())
        plt.close(fig)
        return output_path

    def as_table(self) -> list[dict[str, Any]]:
        rows = []
        for node in self.top_hosts(20):
            rows.append(
                {
                    "ip": node.ip,
                    "role": node.role,
                    "packets": node.packets,
                    "bytes": node.bytes_seen,
                    "protocols": ", ".join(f"{proto}:{count}" for proto, count in node.protocols.most_common(4)),
                    "last_seen": node.last_seen,
                }
            )
        return rows

    def _touch_node(self, ip: str, packet: PacketRecord) -> None:
        now = packet.timestamp or time.time()
        node = self.nodes.get(ip)
        if not node:
            node = HostNode(ip=ip, first_seen=now, last_seen=now, role="Internal" if is_private_ip(ip) else "External")
            self.nodes[ip] = node
        node.last_seen = now
        node.packets += 1
        node.bytes_seen += packet.length
        node.protocols[packet.protocol] += 1
        if packet.extra.get("src_mac") and packet.src_ip == ip:
            node.mac = packet.extra.get("src_mac")

