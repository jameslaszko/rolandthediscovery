from __future__ import annotations

from typing import Set, Dict

# ipAddrTable: ipAdEntAddr (deprecated but widely supported and simple)
# Each row's OID ends with the IPv4 address (a.b.c.d).
IPADENTADDR_OID = "1.3.6.1.2.1.4.20.1.1"
# ipAddrTable: ipAdEntIfIndex
IPADENTIFINDEX_OID = "1.3.6.1.2.1.4.20.1.2"

# IF-MIB: ifName
IFNAME_OID = "1.3.6.1.2.1.31.1.1.1.1"

def _parse_ipv4_from_oid(oid: str) -> str | None:
    parts = oid.split(".")
    if len(parts) < 4:
        return None
    try:
        a, b, c, d = (int(parts[-4]), int(parts[-3]), int(parts[-2]), int(parts[-1]))
    except ValueError:
        return None
    if not (0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 255 and 0 <= d <= 255):
        return None
    return f"{a}.{b}.{c}.{d}"

def load_interface_ips(snmp) -> Set[str]:
    ips: Set[str] = set()
    for oid, _val in snmp.walk(IPADENTADDR_OID):
        ip = _parse_ipv4_from_oid(oid)
        if ip:
            ips.add(ip)
    return ips

def load_ip_to_ifname(snmp):
    result = {}

    try:
        # 1. IP → ifIndex
        ip_to_index_oid = "1.3.6.1.2.1.4.20.1.2"
        ip_to_index_raw = snmp.walk(ip_to_index_oid)
        ip_to_index = {}
        for full_oid, value in ip_to_index_raw:
            print("[RAW SNMP ipAdEntIfIndex]", (full_oid, value))
            # Suffix after OID. is the IP (dot-separated)
            suffix = full_oid[len(ip_to_index_oid) + 1:]  # strip OID + dot
            ip = suffix.replace('.', '.')  # already dot-separated
            value = value.replace('INTEGER: ', '').strip()
            try:
                ifindex = int(value)
                ip_to_index[ip] = ifindex
            except ValueError:
                continue

        print(f"[DEBUG ipmib] Found {len(ip_to_index)} IP → ifIndex mappings")
        if ip_to_index:
            print("[DEBUG ipmib] Sample IP → ifIndex:", dict(list(ip_to_index.items())[:5]))

        # 2. ifIndex → name (prefer ifName)
        ifname_oid = "1.3.6.1.2.1.31.1.1.1.1"
        ifname_raw = snmp.walk(ifname_oid)
        ifindex_to_name = {}
        for full_oid, value in ifname_raw:
            print("[RAW SNMP ifName]", (full_oid, value))
            # Suffix after OID. is the ifIndex (e.g., "1")
            suffix = full_oid[len(ifname_oid) + 1:]  # strip OID + dot
            try:
                idx = int(suffix)
            except ValueError:
                continue
            value = value.replace('STRING: ', '').strip()
            if value:
                ifindex_to_name[idx] = value

        if not ifindex_to_name:
            # Fallback to ifDescr
            ifdescr_oid = "1.3.6.1.2.1.2.2.1.2"
            ifdescr_raw = snmp.walk(ifdescr_oid)
            for full_oid, value in ifdescr_raw:
                print("[RAW SNMP ifDescr]", (full_oid, value))
                suffix = full_oid[len(ifdescr_oid) + 1:]
                try:
                    idx = int(suffix)
                except ValueError:
                    continue
                value = value.replace('STRING: ', '').strip()
                if value:
                    ifindex_to_name[idx] = value

        print(f"[DEBUG ipmib] Found {len(ifindex_to_name)} ifIndex → name mappings")
        if ifindex_to_name:
            print("[DEBUG ipmib] Sample ifIndex → name:", dict(list(ifindex_to_name.items())[:5]))

        # 3. Combine
        for ip, ifindex in ip_to_index.items():
            name = ifindex_to_name.get(ifindex)
            if name:
                result[ip] = name
            else:
                print(f"[WARN ipmib] No name for ifIndex {ifindex} (IP {ip})")

        print(f"[DEBUG ipmib] Final ip_to_ifname entries: {len(result)}")
        if result:
            print("[DEBUG ipmib] Sample ip_to_ifname:", dict(list(result.items())[:5]))

        return result

    except Exception as e:
        print(f"[ERROR ipmib] Failed to load ip_to_ifname: {str(e)}")
        return {}