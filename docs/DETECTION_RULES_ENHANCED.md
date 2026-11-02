# Enhanced Detection Rules - SHAHEEN

## Overview
SHAHEEN implements 6 core detection modules for Blue Team threat detection.

## Detection Modules

### 1. Port Scanning Detection (PORT_SCAN)
- Threshold Medium: 15 unique destination ports in observed traffic
- Threshold High: 30 unique destination ports
- Severity: Medium (15-29 ports), High (>=30 ports or multi-host)

### 2. ARP Spoofing Detection (ARP_SPOOF)
- Purpose: Detect IP-to-MAC mapping conflicts
- Severity: High

### 3. DNS Anomaly Detection (DNS_ANOMALY, DNS_LONG_DOMAIN)
- Excessive Queries: >=20 DNS queries from single source (Medium)
- Long Domains: Domain names >30 characters (Medium)

### 4. SYN Flood Detection (SYN_FLOOD)
- Threshold: >=100 SYN packets to destination
- Severity: High (ratio >=0.1), Critical (ratio <0.1)

### 5. Suspicious IP Monitoring (SUSPICIOUS_IP)
- Feature: Local watchlist management
- Severity: High

### 6. Unusual Traffic Detection (UNUSUAL_PORT)
- Monitored Ports: 22, 23, 3389, 4444, 5555, 6666, 7777, 8888, 9999, 31337
- Threshold: >=3 connections
- Severity: Medium/High based on port

