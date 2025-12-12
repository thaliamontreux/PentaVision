from __future__ import annotations

import ipaddress
import socket
import subprocess
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
                ipv4_ip = ""
                ipv4_netmask = ""
                ipv4_broadcast = ""
                for addr in addrs:
                    if getattr(addr, "family", None) == socket.AF_INET:
                        ipv4_ip = getattr(addr, "address", "") or ""
                        ipv4_netmask = getattr(addr, "netmask", "") or ""
                        ipv4_broadcast = getattr(addr, "broadcast", "") or ""
                        break
                network_cidr = ""
                if ipv4_ip and ipv4_netmask:
                    try:
                        network = ipaddress.IPv4Network(
                            f"{ipv4_ip}/{ipv4_netmask}", strict=False
                        )
                        network_cidr = str(network)
                    except Exception:
                        network_cidr = ""
                interfaces.append(
                    {
                        "name": str(name),
                        "ip": ipv4_ip,
                        "netmask": ipv4_netmask,
                        "broadcast": ipv4_broadcast,
                        "network": network_cidr,
                    }
                )
        except Exception:
            interfaces = []

    if interfaces:
        return interfaces

    # Linux fallback: use the `ip` command to enumerate IPv4 interfaces.
    try:
        output = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show"],
            text=True,
        )
    except Exception:
        output = ""

    if output:
        seen_names = set()
        for line in output.splitlines():
            parts = line.split()
            # Example: "2: ens192    inet 192.168.1.10/24 brd 192.168.1.255 ..."
            if len(parts) < 4:
                continue
            name = parts[1]
            inet_cidr = parts[3]
            ip, _, _ = inet_cidr.partition("/")
            if not ip or name in seen_names:
                continue
            seen_names.add(name)
            network_cidr = ""
            try:
                network = ipaddress.IPv4Network(inet_cidr, strict=False)
                network_cidr = str(network)
            except Exception:
                network_cidr = ""
            interfaces.append(
                {
                    "name": name,
                    "ip": ip,
                    "netmask": "",
                    "broadcast": "",
                    "network": network_cidr,
                }
            )

    if interfaces:
        return interfaces

    # Final fallback: simple hostname lookup, which may only expose loopback.
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
