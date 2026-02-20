from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

@dataclass
class DeviceClass:
    vendor: str = "unknown"
    family: str = "unknown"
    role: str = "unknown"

def classify_device(sysdescr: Optional[str], hostname: Optional[str]) -> DeviceClass:
    """Best-effort device classification from sysDescr and/or hostname.
    Robust fallback to hostname when sysdescr is empty (CDP case).
    """
    hn = (hostname or "").strip().lower()
    sd = (sysdescr or "").strip().lower()

    # Hostname pattern fallbacks (when sysdescr empty)
    if hn:
        if any(p in hn for p in ["tp", "scab", "hub", "cc"]):
            return DeviceClass(vendor="cisco", family="catalyst/ie", role="switch")
        if any(p in hn for p in ["rtr", "router", "gw", "border"]):
            return DeviceClass(vendor="cisco", family="ios", role="router")

    # Special hostname excludes
    if hn.startswith("axis"):
        return DeviceClass(vendor="axis", family="axis", role="camera")

    # Combine text: prefer sysdescr, fallback to hostname
    text = sd if sd else hn
    text_full = (sd + " " + hn).strip()  # sometimes helps catch mixed info

    vendor = "unknown"
    family = "unknown"
    role = "unknown"

    if "cisco" in text or "cisco" in text_full:
        vendor = "cisco"

        # Nexus
        if any(k in text or k in text_full for k in ["nx-os", "nexus", "n5k", "n7k", "n9k", "n5000", "n7000", "n9000"]):
            family = "nexus"
            role = "switch/router"

        # IE (Industrial Ethernet)
        elif any(k in text or k in text_full for k in ["ie2000", "ie3000", "ie4000", "ie4010", "ie5000", "ie"]):
            family = "ie"
            role = "switch"

        # Catalyst / IOS-XE
        elif any(k in text or k in text_full for k in ["cat3k", "cat9k", "catalyst", "ios-xe", "cat3k_caa", "l3 switch"]):
            family = "catalyst"
            role = "switch"

        # Generic IOS
        else:
            family = "ios"
            # Guess role from hostname
            if any(k in hn for k in ["rtr", "router", "gw", "border", "r-", "fw"]):
                role = "router"
            else:
                role = "switch"

    # Pure hostname fallback (no Cisco keyword needed)
    elif any(k in hn for k in ["switch", "sw", "core", "dist", "agg", "hub"]):
        vendor = "cisco"  # assume Cisco in your env
        family = "unknown"
        role = "switch"

    elif any(k in hn for k in ["rtr", "router", "r-", "gw", "border"]):
        vendor = "cisco"
        family = "unknown"
        role = "router"

    return DeviceClass(vendor=vendor, family=family, role=role)