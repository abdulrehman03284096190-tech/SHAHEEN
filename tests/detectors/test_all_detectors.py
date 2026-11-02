from analyzer.packet_parser import PacketRecord
from detection.enhanced_engine import EnhancedDetectionEngine


def test_port_scan_detection():
    engine = EnhancedDetectionEngine()
    packets = []
    for i in range(20):
        packets.append(PacketRecord(
            packet_number=i,
            timestamp="2024-01-01T00:00:00",
            source_address="192.168.1.100",
            destination_address="10.0.0.1",
            source_port=50000+i,
            destination_port=80+i,
            protocol="TCP",
            packet_length=60,
            summary="TCP",
            metadata={"tcp_flags_syn": 1},
            details={},
        ))
    alerts = engine.generate_alerts(packets)
    assert any(a["rule_id"] == "PORT_SCAN" for a in alerts)


def test_dns_anomaly_detection():
    engine = EnhancedDetectionEngine()
    packets = []
    for i in range(25):
        packets.append(PacketRecord(
            packet_number=i,
            timestamp="2024-01-01T00:00:00",
            source_address="192.168.1.50",
            destination_address="8.8.8.8",
            source_port=53000+i,
            destination_port=53,
            protocol="DNS",
            packet_length=80,
            summary="DNS query",
            metadata={},
            details={"dns": {"qdname": f"test{i}.example.com"}},
        ))
    alerts = engine.generate_alerts(packets)
    assert any(a["rule_id"] == "DNS_ANOMALY" for a in alerts)
