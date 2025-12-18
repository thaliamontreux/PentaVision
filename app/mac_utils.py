from __future__ import annotations

import re
import subprocess


def normalize_mac(mac: str) -> str:
    value = (mac or "").strip().upper()
    if not value:
        return ""
    cleaned = "".join(ch for ch in value if ch in "0123456789ABCDEF")
    if len(cleaned) < 6:
        return ""
    pairs = [cleaned[i : i + 2] for i in range(0, len(cleaned), 2)]
    return ":".join(pairs)


def detect_mac_for_ip(ip_address: str) -> str:
    ip_address = (ip_address or "").strip()
    if not ip_address:
        return ""

    def _run(cmd: list[str]) -> str:
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            out = (res.stdout or "") + "\n" + (res.stderr or "")
            return out
        except Exception:
            return ""

    _run(["ping", "-c", "1", "-W", "1", ip_address])

    out = _run(["ip", "neigh", "show", ip_address])
    match = re.search(r"lladdr\s+(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", out)
    if match:
        return normalize_mac(match.group(1))

    out = _run(["arp", "-n", ip_address])
    match = re.search(r"(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", out)
    if match:
        return normalize_mac(match.group(1))

    out = _run(["arp", "-a", ip_address])
    match = re.search(r"(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", out)
    if match:
        return normalize_mac(match.group(1))

    return ""
