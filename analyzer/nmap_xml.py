from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class NmapHost:
    address: str
    hostname: str
    open_ports: tuple[str, ...]


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _children_by_local_name(parent: ET.Element, tag_name: str) -> list[ET.Element]:
    return [child for child in list(parent) if _local_name(child.tag) == tag_name]


def parse_nmap_xml(path: str | Path) -> list[NmapHost]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ValueError(f"Could not read Nmap XML: {exc}") from exc
    if _local_name(root.tag) != "nmaprun":
        raise ValueError("The selected XML file is not an Nmap scan result.")

    hosts: list[NmapHost] = []
    for host in [node for node in list(root) if _local_name(node.tag) == "host"]:
        state = next(iter(_children_by_local_name(host, "status")), None)
        if state is not None and state.get("state") not in {None, "up"}:
            continue

        addresses = _children_by_local_name(host, "address")
        address = next(
            (
                node.get("addr", "")
                for preferred_type in ("ipv4", "ipv6", "mac")
                for node in addresses
                if node.get("addrtype") == preferred_type and node.get("addr")
            ),
            "",
        )
        if not address:
            continue

        hostname_node = next((node for node in host.iter() if _local_name(node.tag) == "hostname"), None)
        hostname = hostname_node.get("name", "") if hostname_node is not None else ""
        open_ports = []
        port_nodes = [node for node in host.iter() if _local_name(node.tag) == "port"]
        for port in port_nodes:
            port_state = next((node for node in port.iter() if _local_name(node.tag) == "state"), None)
            if port_state is None or port_state.get("state") != "open":
                continue
            service = next((node for node in port.iter() if _local_name(node.tag) == "service"), None)
            service_name = service.get("name", "") if service is not None else ""
            protocol = port.get("protocol", "")
            port_id = port.get("portid", "")
            label = f"{port_id}/{protocol}" if protocol else port_id
            if service_name:
                label += f" {service_name}"
            if label:
                open_ports.append(label)
        hosts.append(NmapHost(address, hostname, tuple(open_ports)))

    return hosts
