from analyzer.conversation_tracker import ConversationTracker
from analyzer.packet_parser import PacketRecord, parse_packet
from detection.detection_engine import DetectionEngine
from scapy.all import Ether, IP, TCP


def _make_tcp_packet(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=443, seq=1):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, flags="S")


def test_conversation_tracker_normalizes_bidirectional_flow() -> None:
    tracker = ConversationTracker()
    pkt1 = parse_packet(_make_tcp_packet(), 1)
    pkt2 = parse_packet(_make_tcp_packet(src="10.0.0.2", dst="10.0.0.1", sport=443, dport=1234, seq=10), 2)
    tracker.track(pkt1)
    tracker.track(pkt2)
    summaries = tracker.summaries()
    assert len(summaries) == 1
    assert summaries[0]["packet_count"] == 2


def test_detection_engine_deduplicates_alerts() -> None:
    engine = DetectionEngine()
    packets = [
        PacketRecord(
            packet_number=i,
            timestamp="2024-01-01T00:00:00",
            source_address="192.168.1.8",
            destination_address="8.8.8.8",
            source_port=5000+i,
            destination_port=443,
            protocol="TCP",
            packet_length=120,
            summary="TCP",
            metadata={"tcp_flags_syn": 1},
            details={"tcp": {"sport": 5000 + i, "dport": 443}},
        )
        for i in range(12)
    ]
    alerts = engine.generate_alerts(packets)
    assert any(alert["rule_id"] == "CONNECTION_RETRY" for alert in alerts)
    assert len(alerts) == len({(a["rule_id"], a["source_address"], a["destination_address"]) for a in alerts})
