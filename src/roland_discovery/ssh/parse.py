from __future__ import annotations

import re
from typing import List, Set, Tuple

_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def extract_ipv4s(text: str) -> Set[str]:
    """Extract IPv4-like tokens (best-effort)."""
    ips = set()
    for m in _IPV4_RE.finditer(text or ""):
        ip = m.group(1)
        parts = ip.split('.')
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            ips.add(ip)
    return ips


def parse_show_ip_interface_brief(text: str) -> Dict[str, Dict]:
    interfaces = {}
    lines = text.splitlines()
    started = False
    for line in lines:
        if "Interface" in line and "IP-Address" in line:
            started = True
            continue
        if started and line.strip() and not line.startswith("Interface"):
            parts = line.split()
            if len(parts) >= 5:
                iface = parts[0]
                ip = parts[1] if parts[1] != "unassigned" else None
                status = parts[3]
                proto = parts[4]
                interfaces[iface] = {"ip": ip, "status": status, "protocol": proto}
    return interfaces