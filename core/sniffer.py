from __future__ import annotations

import ipaddress
import logging
import random
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

from core.analyzer import PacketRecord

LOGGER = logging.getLogger(__name__)

try:
    from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Raw, rdpcap, sniff
except Exception:  # pragma: no cover - optional dependency
    ARP = DNS = DNSQR = DNSRR = ICMP = IP = TCP = UDP = Raw = None
    rdpcap = sniff = None

try:
    import pyshark
except Exception:  # pragma: no cover - optional dependency
    pyshark = None


PacketCallback = Callable[[PacketRecord], None]
ErrorCallback = Callable[[str], None]


class PacketSniffer:
    """Threaded packet capture service with live, PCAP, and simulation modes."""

    def __init__(
        self,
        packet_callback: PacketCallback,
        error_callback: ErrorCallback | None = None,
        interface: str | None = None,
        mode: str = "simulated",
    ) -> None:
        self.packet_callback = packet_callback
        self.error_callback = error_callback
        self.interface = interface or ""
        self.mode = mode
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._scan_port = 20
        self._live_packet_count = 0

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running:
            return
        self._stop_event.clear()
        self._live_packet_count = 0
        self._thread = threading.Thread(target=self._run, name="NetWatchSniffer", daemon=True)
        self._thread.start()
        LOGGER.info("Started packet sniffer in %s mode", self.mode)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.5)
        LOGGER.info("Stopped packet sniffer")

    def read_pcap(self, path: Path, limit: int = 5000) -> list[PacketRecord]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(path)
        if rdpcap:
            packets = rdpcap(str(path), count=limit)
            return [record for record in (self._from_scapy(packet) for packet in packets) if record]
        if pyshark:
            records: list[PacketRecord] = []
            capture = pyshark.FileCapture(str(path), keep_packets=False)
            try:
                for index, packet in enumerate(capture):
                    if index >= limit:
                        break
                    record = self._from_pyshark(packet)
                    if record:
                        records.append(record)
            finally:
                capture.close()
            return records
        raise RuntimeError("PCAP analysis requires scapy or pyshark. Install requirements.txt first.")

    def _run(self) -> None:
        if self.mode == "live" and sniff:
            try:
                started = time.time()
                while not self._stop_event.is_set():
                    sniff(
                        iface=self.interface or None,
                        prn=self._handle_scapy_packet,
                        store=False,
                        timeout=1,
                    )
                    if self._live_packet_count == 0 and time.time() - started >= 8:
                        self._emit_error(
                            "Live capture received no packets. Check Npcap, Administrator mode, or interface. "
                            "Falling back to simulated demo traffic."
                        )
                        if not self._stop_event.is_set():
                            self._run_simulated()
                        return
                return
            except PermissionError:
                self._emit_error("Live capture requires administrator/root privileges. Falling back to simulated traffic.")
            except Exception as exc:
                self._emit_error(f"Live capture failed: {exc}. Falling back to simulated traffic.")
                LOGGER.exception("Live capture failed")
        self._run_simulated()

    def _handle_scapy_packet(self, packet: object) -> None:
        record = self._from_scapy(packet)
        if record:
            self._live_packet_count += 1
            self.packet_callback(record)

    def _run_simulated(self) -> None:
        for record in self._simulated_stream():
            if self._stop_event.is_set():
                break
            self.packet_callback(record)
            time.sleep(random.uniform(0.08, 0.36))

    def _simulated_stream(self) -> Iterable[PacketRecord]:
        internal_hosts = [f"192.168.1.{i}" for i in range(10, 42)]
        external_hosts = ["8.8.8.8", "1.1.1.1", "13.107.42.14", "45.133.32.156", "185.199.108.133", "104.18.12.123"]
        gateway = "192.168.1.1"
        domains = ["updates.microsoft.com", "github.com", "cdn.cloudflare.com", "payroll.internal", "login.example.com"]
        while True:
            roll = random.random()
            now = time.time()
            src = random.choice(internal_hosts)
            dst = random.choice(external_hosts + internal_hosts)
            proto = random.choice(["TCP", "UDP", "DNS", "HTTP", "TLS"])
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([53, 80, 123, 443, 445, 993, 3389])
            payload = b""
            extra: dict[str, object] = {}
            flags = ""
            dns_query = None

            if roll < 0.08:
                src = "45.133.32.156"
                dst = random.choice(internal_hosts)
                proto = "TCP"
                dst_port = self._scan_port
                self._scan_port += random.randint(1, 4)
                if self._scan_port > 180:
                    self._scan_port = 20
                flags = "S"
                length = random.randint(54, 76)
                summary = f"TCP SYN probe {src}:{src_port} > {dst}:{dst_port}"
            elif roll < 0.14:
                proto = "HTTP"
                dst_port = 80
                payload = b"GET /search?q=' OR 1=1 UNION SELECT password FROM users-- HTTP/1.1\r\nHost: login.example.com\r\n\r\n"
                length = len(payload) + random.randint(54, 90)
                summary = f"HTTP request {src} > {dst} suspicious query"
            elif roll < 0.19:
                proto = "DNS"
                dst = "192.168.1.53"
                dst_port = 53
                dns_query = random.choice(["github.com", "bank.example.com", "cdn.cloudflare.com"])
                answers = ["203.0.113.99"] if random.random() < 0.5 else ["10.10.10.10"]
                extra["dns_answers"] = answers
                length = random.randint(92, 180)
                summary = f"DNS response {dns_query} -> {', '.join(answers)}"
            elif roll < 0.23:
                proto = "ARP"
                src = gateway
                dst = "192.168.1.255"
                src_port = dst_port = None
                extra = {
                    "arp_psrc": gateway,
                    "arp_hwsrc": random.choice(["00:50:56:aa:10:01", "de:ad:be:ef:00:01"]),
                    "arp_op": "is-at",
                    "gratuitous": True,
                }
                length = 60
                summary = f"ARP is-at {gateway} {extra['arp_hwsrc']}"
            elif roll < 0.29:
                proto = "TCP"
                dst_port = 443
                payload = random.randbytes(random.randint(400, 1200)) if hasattr(random, "randbytes") else bytes(
                    random.getrandbits(8) for _ in range(random.randint(400, 1200))
                )
                length = len(payload) + 54
                summary = f"Encrypted-looking payload {src} > {dst}:443"
            else:
                if proto == "DNS":
                    dst = random.choice(["8.8.8.8", "1.1.1.1", "192.168.1.53"])
                    dst_port = 53
                    dns_query = random.choice(domains)
                    length = random.randint(74, 180)
                    summary = f"DNS query {src} asks {dns_query}"
                elif proto in {"HTTP", "TLS"}:
                    dst_port = 80 if proto == "HTTP" else 443
                    length = random.randint(160, 1450)
                    summary = f"{proto} session {src}:{src_port} > {dst}:{dst_port}"
                else:
                    length = random.randint(64, 1500)
                    summary = f"{proto} {src}:{src_port} > {dst}:{dst_port}"

            yield PacketRecord(
                timestamp=now,
                src_ip=src,
                dst_ip=dst,
                protocol=proto,
                length=length,
                src_port=src_port,
                dst_port=dst_port,
                ttl=random.choice([54, 64, 118, 128, 255]),
                dns_query=dns_query,
                payload=payload,
                summary=summary,
                interface=self.interface or "simulated0",
                flags=flags,
                extra=extra,
            )

    def _from_scapy(self, packet: object) -> PacketRecord | None:
        if IP is None:
            return None
        try:
            timestamp = float(getattr(packet, "time", time.time()))
            extra: dict[str, object] = {}
            payload = bytes(packet[Raw].load) if Raw in packet else b""
            src_port = dst_port = ttl = None
            flags = ""
            dns_query = None
            protocol = "OTHER"

            if ARP in packet:
                protocol = "ARP"
                src_ip = str(packet[ARP].psrc)
                dst_ip = str(packet[ARP].pdst)
                extra.update(
                    {
                        "arp_psrc": str(packet[ARP].psrc),
                        "arp_pdst": str(packet[ARP].pdst),
                        "arp_hwsrc": str(packet[ARP].hwsrc),
                        "arp_hwdst": str(packet[ARP].hwdst),
                        "arp_op": str(packet[ARP].op),
                        "src_mac": str(packet[ARP].hwsrc),
                        "gratuitous": str(packet[ARP].psrc) == str(packet[ARP].pdst),
                    }
                )
            elif IP in packet:
                src_ip = str(packet[IP].src)
                dst_ip = str(packet[IP].dst)
                ttl = int(packet[IP].ttl)
                if TCP in packet:
                    protocol = "TCP"
                    src_port = int(packet[TCP].sport)
                    dst_port = int(packet[TCP].dport)
                    flags = str(packet[TCP].flags)
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = int(packet[UDP].sport)
                    dst_port = int(packet[UDP].dport)
                elif ICMP in packet:
                    protocol = "ICMP"
                else:
                    protocol = str(packet[IP].proto)
                if DNS in packet:
                    protocol = "DNS"
                    if packet.haslayer(DNSQR):
                        raw_query = packet[DNSQR].qname
                        dns_query = raw_query.decode("utf-8", errors="replace").rstrip(".") if isinstance(raw_query, bytes) else str(raw_query).rstrip(".")
                    answers: list[str] = []
                    for index in range(int(getattr(packet[DNS], "ancount", 0))):
                        rr = packet[DNS].an[index]
                        if isinstance(rr, DNSRR):
                            answers.append(str(rr.rdata))
                    extra["dns_answers"] = answers
            else:
                return None

            return PacketRecord(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                length=len(packet),
                src_port=src_port,
                dst_port=dst_port,
                ttl=ttl,
                dns_query=dns_query,
                payload=payload,
                summary=packet.summary(),
                interface=self.interface,
                flags=flags,
                extra=extra,
            )
        except Exception:
            LOGGER.debug("Could not normalize scapy packet", exc_info=True)
            return None

    @staticmethod
    def _from_pyshark(packet: object) -> PacketRecord | None:
        try:
            timestamp = float(packet.sniff_timestamp)
            src_ip = getattr(packet.ip, "src", "0.0.0.0") if hasattr(packet, "ip") else "0.0.0.0"
            dst_ip = getattr(packet.ip, "dst", "0.0.0.0") if hasattr(packet, "ip") else "0.0.0.0"
            protocol = packet.highest_layer.upper()
            src_port = int(getattr(packet[packet.transport_layer], "srcport", 0)) if getattr(packet, "transport_layer", None) else None
            dst_port = int(getattr(packet[packet.transport_layer], "dstport", 0)) if getattr(packet, "transport_layer", None) else None
            dns_query = getattr(packet.dns, "qry_name", None) if hasattr(packet, "dns") else None
            payload = bytes.fromhex(getattr(packet.data, "data", "").replace(":", "")) if hasattr(packet, "data") else b""
            return PacketRecord(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="DNS" if dns_query else protocol,
                length=int(packet.length),
                src_port=src_port,
                dst_port=dst_port,
                dns_query=dns_query,
                payload=payload,
                summary=str(packet),
            )
        except Exception:
            LOGGER.debug("Could not normalize pyshark packet", exc_info=True)
            return None

    def _emit_error(self, message: str) -> None:
        LOGGER.warning(message)
        if self.error_callback:
            self.error_callback(message)
