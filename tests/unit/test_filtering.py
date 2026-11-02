from analyzer.filter_engine import evaluate_filter, parse_filter_expression
from analyzer.packet_parser import PacketRecord


def test_parse_filter_expression_rejects_dangerous_input() -> None:
    try:
        parse_filter_expression("__import__('os').system('echo')")
        assert False, "Dangerous expression should be rejected"
    except ValueError:
        pass


def test_evaluate_filter_accepts_ip_and_protocol_rules() -> None:
    packet = PacketRecord(
        packet_number=1,
        timestamp="2024-01-01T00:00:00",
        source_address="192.168.1.5",
        destination_address="8.8.8.8",
        source_port=12345,
        destination_port=53,
        protocol="DNS",
        packet_length=120,
        summary="DNS",
        metadata={"tcp_flags_syn": 0},
    )
    assert evaluate_filter(packet, "dns")
    assert evaluate_filter(packet, "ip.src == 192.168.1.5")
    assert evaluate_filter(packet, "ip.addr == 8.8.8.8")
    assert evaluate_filter(packet, "tcp or dns") is True


def test_evaluate_filter_supports_comparison_and_boolean_logic() -> None:
    packet = PacketRecord(
        packet_number=2,
        timestamp="2024-01-01T00:00:01",
        source_address="10.0.0.2",
        destination_address="10.0.0.3",
        source_port=5000,
        destination_port=443,
        protocol="TCP",
        packet_length=1400,
        summary="TCP SYN",
        metadata={"tcp_flags_syn": 1},
    )
    assert evaluate_filter(packet, "tcp")
    assert evaluate_filter(packet, "frame.len > 1000")
    assert evaluate_filter(packet, "tcp.flags.syn == 1")
    assert evaluate_filter(packet, "(tcp and tcp.port == 443) or dns")
    assert evaluate_filter(packet, "not dns")
