from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scapy.arch import get_windows_if_list


class InterfaceDiscoveryError(RuntimeError):
    """Windows network-interface enumeration failed."""


@dataclass(frozen=True)
class CaptureInterface:
    name: str
    description: str = ""
    mac_address: str = ""
    addresses: tuple[str, ...] = ()
    is_loopback: bool = False
    is_virtual: bool = False
    index: int | None = None

    @property
    def label(self) -> str:
        address_text = ", ".join(self.addresses) if self.addresses else "no IP address"
        mac_text = f", MAC {self.mac_address}" if self.mac_address else ""
        flags = []
        if self.is_loopback:
            flags.append("loopback")
        if self.is_virtual:
            flags.append("virtual")
        kind = f" ({', '.join(flags)})" if flags else ""
        return (
            f"{self.name} — {self.description or 'Network adapter'} "
            f"[{address_text}{mac_text}]{kind}"
        )


class InterfaceManager:
    @staticmethod
    def list_interfaces() -> list[CaptureInterface]:
        try:
            discovered: list[dict[str, Any]] = get_windows_if_list()
        except Exception as exc:
            raise InterfaceDiscoveryError(
                f"Windows interface discovery failed: {exc}"
            ) from exc

        interfaces: list[CaptureInterface] = []
        for item in discovered:
            name = str(item.get("name") or item.get("iface") or "").strip()
            if not name:
                continue
            description = str(item.get("description") or "")
            lowered = f"{name} {description}".lower()
            if any(
                token in lowered
                for token in ("lightweight filter", "light-weight filter", "qos packet scheduler")
            ):
                continue
            addresses = tuple(
                str(address)
                for address in item.get("ips", [])
                if address
            )
            interfaces.append(
                CaptureInterface(
                    name=name,
                    description=description,
                    mac_address=str(item.get("mac") or ""),
                    addresses=addresses,
                    is_loopback="loopback" in lowered or "loopback" in name.lower(),
                    is_virtual=any(
                        token in lowered
                        for token in ("virtual", "hyper-v", "vmware", "tap-", "vpn")
                    ),
                    index=item.get("index") if isinstance(item.get("index"), int) else None,
                )
            )
        return interfaces
