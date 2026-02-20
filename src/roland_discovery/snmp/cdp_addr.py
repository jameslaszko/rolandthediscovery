from __future__ import annotations

from typing import Dict, Optional, Tuple

CDP_ADDR_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"

def _parse_cdp_index(oid_str: str) -> Tuple[int, int]:
    parts = oid_str.split(".")
    device_index = int(parts[-1])
    if_index = int(parts[-2])
    return if_index, device_index

def _clean_value(v: str) -> str:
    if ":" in v:
        v = v.split(":", 1)[1].strip()
    return v.strip().strip('"')

def _decode_ipv4_from_hex_string(s: str) -> Optional[str]:
    s = s.replace(":", " ").replace("-", " ").strip()
    parts = [p for p in s.split() if p]
    if len(parts) < 4:
        return None
    try:
        b = bytes(int(p, 16) for p in parts[:4])
        return ".".join(str(x) for x in b)
    except ValueError:
        return None

def _decode_ipv4(v: str) -> Optional[str]:
    v = _clean_value(v)
    ip = _decode_ipv4_from_hex_string(v)
    if ip:
        return ip
    if v.count(".") == 3:
        return v
    return None

def get_cdp_mgmt_addresses(snmp) -> Dict[Tuple[int, int], str]:
    out: Dict[Tuple[int, int], str] = {}
    for oid, val in snmp.walk(CDP_ADDR_OID):
        key = _parse_cdp_index(oid)
        ip = _decode_ipv4(val)
        if ip:
            out[key] = ip
    return out
