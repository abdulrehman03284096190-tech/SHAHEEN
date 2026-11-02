from __future__ import annotations

from typing import Iterable, List

from analyzer.packet_parser import PacketRecord
from detection.detectors.port_scan import PortScanDetector
from detection.detectors.arp_spoof import ARPSpoofDetector
from detection.detectors.dns_anomaly import DNSAnomalyDetector
from detection.detectors.syn_flood import SYNFloodDetector
from detection.detectors.suspicious_ip import SuspiciousIPMonitor
from detection.detectors.unusual_traffic import UnusualTrafficDetector


class DetectorManager:
    def __init__(self, watchlist=None):
        self.port_scan = PortScanDetector()
        self.arp_spoof = ARPSpoofDetector()
        self.dns_anomaly = DNSAnomalyDetector()
        self.syn_flood = SYNFloodDetector()
        self.suspicious_ip = SuspiciousIPMonitor(watchlist=watchlist)
        self.unusual_traffic = UnusualTrafficDetector()
    
    def run_all(self, packets: Iterable[PacketRecord]) -> List[dict[str, object]]:
        all_alerts = []
        packet_list = list(packets)
        
        all_alerts.extend(self.port_scan.detect(packet_list))
        all_alerts.extend(self.arp_spoof.detect(packet_list))
        all_alerts.extend(self.dns_anomaly.detect(packet_list))
        all_alerts.extend(self.syn_flood.detect(packet_list))
        all_alerts.extend(self.suspicious_ip.detect(packet_list))
        all_alerts.extend(self.unusual_traffic.detect(packet_list))
        
        return all_alerts
