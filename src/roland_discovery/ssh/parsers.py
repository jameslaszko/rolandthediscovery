from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class InterfaceIP:
    ifname: str
    ip: str


_HOSTNAME_RE = re.compile(r"^hostname\s+(?P<hn>\S+)", re.IGNORECASE)

def parse_hostname_from_running_config(output: str) -> Optional[str]:
    for line in output.splitlines():
        m = _HOSTNAME_RE.search(line.strip())
        if m:
            return m.group("hn")
    return None


def parse_show_hostname(output: str) -> Optional[str]:
    # NX-OS: "hostname HUB-BB-NX02"
    hn = parse_hostname_from_running_config(output)
    if hn:
        return hn
    # Some platforms: single token
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if "hostname" in line.lower():
            # already handled above
            continue
        # If output is just a hostname, accept it
        if re.fullmatch(r"[A-Za-z0-9_.-]{2,}", line):
            return line
    return None


def parse_show_ip_int_brief(output: str) -> List[InterfaceIP]:
    # IOS: Interface  IP-Address  OK?  Method  Status  Protocol
    # NX-OS: Interface  IP Address  Interface Status ...
    ips: List[InterfaceIP] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("interface"):
            continue
        # split on whitespace; take first 2 cols
        parts = re.split(r"\s+", line)
        if len(parts) < 2:
            continue
        ifname, ip = parts[0], parts[1]
        if ip.lower() in ("unassigned", "unknown", "dhcp", "0.0.0.0"):
            continue
        # basic IPv4 filter
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
            ips.append(InterfaceIP(ifname=ifname, ip=ip))
    return ips
