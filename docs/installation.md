# Installation

## Requirements

- Windows 10/11
- Python 3.12+ (the current development environment uses Python 3.15)
- Npcap for live capture; offline capture-file analysis does not require Npcap

## Setup

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Live packet capture

Install Npcap from its official Windows installer and enable the WinPcap API
compatible mode. Restart Shaheen after installation so Scapy can discover the
provider. Select a specific adapter in Shaheen. Capturing may require a user
account permitted by the Npcap installation; Shaheen does not request
administrator elevation automatically.

The application checks whether Scapy has an active libpcap/Npcap provider, but
provider detection does not prove that a particular interface can be captured.
Permission and adapter errors are reported when capture is attempted. PCAP and
PCAPNG import remains available when Npcap is absent.

## Optional development dependencies

```powershell
pip install -r requirements-dev.txt
```
