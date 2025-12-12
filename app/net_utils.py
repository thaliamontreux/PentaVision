from __future__ import annotations

import ipaddress
import socket
from typing import Dict, List

try:
    import psutil  # type: ignore[import]
except Exception:  # pragma: no cover - optional dependency
    psutil = None  # type: ignore[assignment]


def get_ipv4_interfaces() -> List[Dict[str, str]]:
    interfaces: List[Dict[str, str]] = []

    if psutil is not None:
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if getattr(addr, "family", None) != socket.AF_INET:
                        continue
                    ip = getattr(addr, "address", "") or ""
                    netmask = getattr(addr, "netmask", "") or ""
                    broadcast = getattr(addr, "broadcast", "") or ""
                    if not ip:
                        continue
                    network_cidr = ""
                    if netmask:
                        try:
                            network = ipaddress.IPv4Network(
                                f"{ip}/{netmask}", strict=False
                            )
                            network_cidr = str(network)
                        except Exception:
                            network_cidr = ""
                    interfaces.append(
                        {
                            "name": str(name),
                            "ip": ip,
                            "netmask": netmask,
                            "broadcast": broadcast,
                            "network": network_cidr,
                        }
                    )
        except Exception:
            interfaces = []

    if interfaces:
        return interfaces

    try:
        hostname = socket.gethostname()
        addrinfos = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
    except Exception:
        return interfaces

    seen_ips = set()
    for _family, _socktype, _proto, _canonname, sockaddr in addrinfos:
        ip = sockaddr[0]
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)
        network_cidr = ""
        try:
            network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
            network_cidr = str(network)
        except Exception:
            network_cidr = ""
        interfaces.append(
            {
                "name": "primary",
                "ip": ip,
                "netmask": "",
                "broadcast": "",
                "network": network_cidr,
            }
        )
    return interfaces
