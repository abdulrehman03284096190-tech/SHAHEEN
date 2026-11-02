from scapy.all import IP, TCP, Ether, wrpcap

from capture.pcap_reader import read_pcap_file


def test_read_pcap_file_reads_packets(tmp_path) -> None:
    pcap_path = tmp_path / "sample.pcap"
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
    wrpcap(str(pcap_path), [packet, packet])

    records = read_pcap_file(str(pcap_path))
    assert len(records) == 2
    assert records[0].protocol == "TCP"
