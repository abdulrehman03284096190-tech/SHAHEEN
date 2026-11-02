from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from scapy.all import ARP, DNS, ICMP, IP, IPv6, Raw, TCP, UDP, Ether


@dataclass
class PacketRecord:
    packet_number: int
    timestamp: str
    source_address: str = ""
    destination_address: str = ""
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str = "UNKNOWN"
    packet_length: int = 0
    summary: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    raw_bytes: bytes = b""
    session_id: int | None = None
    record_id: int | None = None

    @property
    def formatted_summary(self) -> str:
        if self.source_port is not None and self.destination_port is not None:
            return f"{self.protocol} {self.source_address}:{self.source_port} -> {self.destination_address}:{self.destination_port}"
        return f"{self.protocol} {self.source_address} -> {self.destination_address}"

    @property
    def hex_dump(self) -> str:
        if not self.raw_bytes:
            return ""
        hex_bytes = self.raw_bytes.hex()
        chunks = [hex_bytes[i : i + 2] for i in range(0, len(hex_bytes), 2)]
        lines: list[str] = []
        for index in range(0, len(chunks), 16):
            segment = chunks[index : index + 16]
            ascii_chars = []
            for byte in segment:
                value = int(byte, 16)
                ascii_chars.append(chr(value) if 32 <= value < 127 else ".")
            lines.append(f"{index:04x}: {' '.join(segment):<47} {''.join(ascii_chars)}")
        return "\n".join(lines)

    @property
    def protocol_tree(self) -> list[dict[str, Any]]:
        layers: list[dict[str, Any]] = [
            {
                "name": "Frame",
                "fields": {
                    "number": self.packet_number,
                    "timestamp": self.timestamp,
                    "captured_length": self.packet_length,
                    "summary": self.summary,
                },
            }
        ]
        for layer_name, fields in self.details.items():
            layers.append({"name": layer_name.upper(), "fields": dict(fields)})
        if self.raw_bytes:
            layers.append(
                {
                    "name": "Packet bytes",
                    "fields": {"length": len(self.raw_bytes)},
                }
            )
        return layers


def _safe_layer_value(layer: Any, attr: str, default: Any = None) -> Any:
    try:
        return getattr(layer, attr, default)
    except Exception:
        return default


def parse_packet(
    packet: Any,
    number: int,
    *,
    include_raw_bytes: bool = True,
) -> PacketRecord:
    try:
        timestamp = datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat()
    except (AttributeError, TypeError, ValueError, OverflowError, OSError):
        timestamp = datetime.now(timezone.utc).isoformat()
    summary = "packet"
    protocol = "UNKNOWN"
    src = ""
    dst = ""
    sport = None
    dport = None
    details: dict[str, Any] = {}

    if packet.haslayer(Ether):
        protocol = "ETHERNET"
        eth = packet[Ether]
        details["ethernet"] = {
            "src": eth.src,
            "dst": eth.dst,
            "type": eth.type,
        }
    if packet.haslayer(IP):
        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        details["ip"] = {
            "src": ip.src,
            "dst": ip.dst,
            "ttl": getattr(ip, "ttl", None),
            "proto": getattr(ip, "proto", None),
            "len": getattr(ip, "len", None),
        }
        protocol = getattr(ip, "proto", 0)
        if isinstance(protocol, int) and protocol == 6:
            protocol = "TCP"
        elif isinstance(protocol, int) and protocol == 17:
            protocol = "UDP"
        elif isinstance(protocol, int) and protocol == 1:
            protocol = "ICMP"
        if ip.haslayer(TCP):
            protocol = "TCP"
            sport = ip[TCP].sport
            dport = ip[TCP].dport
            details["tcp"] = {
                "sport": sport,
                "dport": dport,
                "seq": _safe_layer_value(ip[TCP], "seq", None),
                "ack": _safe_layer_value(ip[TCP], "ack", None),
                "flags": str(_safe_layer_value(ip[TCP], "flags", "")),
                "window": _safe_layer_value(ip[TCP], "window", None),
                "checksum": _safe_layer_value(ip[TCP], "chksum", None),
            }
        elif ip.haslayer(UDP):
            protocol = "UDP"
            sport = ip[UDP].sport
            dport = ip[UDP].dport
            details["udp"] = {
                "sport": sport,
                "dport": dport,
                "len": _safe_layer_value(ip[UDP], "len", None),
                "checksum": _safe_layer_value(ip[UDP], "chksum", None),
            }
        elif ip.haslayer(ICMP):
            protocol = "ICMP"
            details["icmp"] = {
                "type": _safe_layer_value(ip[ICMP], "type", None),
                "code": _safe_layer_value(ip[ICMP], "code", None),
            }
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        src = ip6.src
        dst = ip6.dst
        protocol = "IPv6"
        details["ipv6"] = {
            "src": ip6.src,
            "dst": ip6.dst,
            "nh": getattr(ip6, "nh", None),
            "len": getattr(ip6, "plen", None),
        }
        if ip6.haslayer(TCP):
            protocol = "TCP"
            sport = ip6[TCP].sport
            dport = ip6[TCP].dport
            details["tcp"] = {
                "sport": sport,
                "dport": dport,
                "seq": getattr(ip6[TCP], "seq", None),
                "ack": getattr(ip6[TCP], "ack", None),
                "flags": str(getattr(ip6[TCP], "flags", "")),
                "window": getattr(ip6[TCP], "window", None),
                "checksum": getattr(ip6[TCP], "chksum", None),
            }
        elif ip6.haslayer(UDP):
            protocol = "UDP"
            sport = ip6[UDP].sport
            dport = ip6[UDP].dport
            details["udp"] = {
                "sport": sport,
                "dport": dport,
                "len": getattr(ip6[UDP], "len", None),
                "checksum": getattr(ip6[UDP], "chksum", None),
            }
    elif packet.haslayer(ARP):
        arp = packet[ARP]
        src = arp.psrc
        dst = arp.pdst
        protocol = "ARP"
        details["arp"] = {"psrc": arp.psrc, "pdst": arp.pdst, "op": getattr(arp, "op", None)}

    if packet.haslayer(DNS):
        protocol = "DNS"
        dns = packet[DNS]
        qname = getattr(dns.qd, "qname", b"")
        if isinstance(qname, bytes):
            qname = qname.decode("utf-8", errors="replace")
        summary = f"DNS {qname}"
        details["dns"] = {
            "qr": getattr(dns, "qr", None),
            "qdname": qname,
            "ancount": getattr(dns, "ancount", None),
            "opcode": getattr(dns, "opcode", None),
        }
    elif packet.haslayer(TCP):
        tcp = packet[TCP]
        summary = f"TCP {tcp.sport}->{tcp.dport} flags={tcp.flags}"
        details.setdefault("tcp", {
            "sport": getattr(tcp, "sport", None),
            "dport": getattr(tcp, "dport", None),
            "seq": getattr(tcp, "seq", None),
            "ack": getattr(tcp, "ack", None),
            "flags": str(getattr(tcp, "flags", "")),
        })
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        summary = f"UDP {udp.sport}->{udp.dport} len={udp.len}"
        details.setdefault("udp", {"sport": udp.sport, "dport": udp.dport, "len": getattr(udp, "len", None)})
    elif packet.haslayer(ICMP):
        summary = "ICMP"
    elif packet.haslayer(ARP):
        summary = "ARP request/reply"
    elif packet.haslayer(Raw):
        summary = "RAW"

    packet_length = len(packet)
    metadata = {
        "layer_count": len(packet.layers()),
        "raw_length": packet_length,
        "has_raw": packet.haslayer(Raw),
        "tcp_flags_syn": 0,
    }
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        metadata["tcp_flags_syn"] = int(bool(int(tcp.flags) & 0x02))
        metadata["tcp_flags"] = {
            "syn": metadata["tcp_flags_syn"],
            "ack": int(bool(int(tcp.flags) & 0x10)),
            "rst": int(bool(int(tcp.flags) & 0x04)),
        }

    raw_bytes = bytes(packet) if include_raw_bytes else b""
    return PacketRecord(
        packet_number=number,
        timestamp=timestamp,
        source_address=src,
        destination_address=dst,
        source_port=sport,
        destination_port=dport,
        protocol=protocol,
        packet_length=packet_length,
        summary=summary,
        metadata=metadata,
        details=details,
        raw_bytes=raw_bytes,
    )
