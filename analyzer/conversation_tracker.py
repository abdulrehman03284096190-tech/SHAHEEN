from __future__ import annotations

from collections import defaultdict

from analyzer.packet_parser import PacketRecord


class ConversationTracker:
    def __init__(self) -> None:
        self._conversations: dict[str, dict[str, object]] = {}

    def _normalize(self, packet: PacketRecord) -> tuple[str, int | None, str, int | None]:
        a = (packet.source_address, packet.source_port)
        b = (packet.destination_address, packet.destination_port)
        if a <= b:
            return a[0], a[1], b[0], b[1]
        return b[0], b[1], a[0], a[1]

    def track(self, packet: PacketRecord) -> str:
        if not packet.source_address or not packet.destination_address:
            return ""
        a_addr, a_port, b_addr, b_port = self._normalize(packet)
        key = f"{packet.protocol}|{a_addr}:{a_port}|{b_addr}:{b_port}"
        conv = self._conversations.setdefault(key, {
            "protocol": packet.protocol,
            "endpoints": [(a_addr, a_port), (b_addr, b_port)],
            "packet_count": 0,
            "byte_count": 0,
            "first_seen": packet.timestamp,
            "last_seen": packet.timestamp,
            "forward_packets": 0,
            "reverse_packets": 0,
        })
        conv["packet_count"] = int(conv["packet_count"]) + 1
        conv["byte_count"] = int(conv["byte_count"]) + packet.packet_length
        conv["last_seen"] = packet.timestamp
        if packet.timestamp < str(conv["first_seen"]):
            conv["first_seen"] = packet.timestamp
        if (packet.source_address, packet.source_port) == (a_addr, a_port):
            conv["forward_packets"] = int(conv["forward_packets"]) + 1
        else:
            conv["reverse_packets"] = int(conv["reverse_packets"]) + 1
        return key

    def summaries(self) -> list[dict[str, object]]:
        return [
            {
                "key": key,
                "protocol": value["protocol"],
                "endpoints": value["endpoints"],
                "first_seen": value["first_seen"],
                "last_seen": value["last_seen"],
                "packet_count": value["packet_count"],
                "byte_count": value["byte_count"],
            }
            for key, value in self._conversations.items()
        ]

    @property
    def conversations(self):
        return self._conversations
