from __future__ import annotations

from typing import Dict, Iterable, Iterator, List, Tuple

from roland_discovery.snmp.bridge import load_baseport_ifindex
from roland_discovery.snmp.qbridge import DOT1Q_FDB_PORT, iter_fdb_ports
from roland_discovery.snmp.vtp import operational_vlans

DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"  # dot1dTpFdbPort

def _parse_mac_from_oid(oid_str: str) -> str:
    parts = oid_str.split(".")
    mac_bytes = [int(x) for x in parts[-6:]]
    return ":".join(f"{b:02x}" for b in mac_bytes)

def iter_fdb(snmp, base_community: str) -> Iterator[Tuple[int, str, int]]:
    """Yield (vlan, mac, ifindex) for learned MACs.

    Strategy:
      1) Prefer Q-BRIDGE-MIB (dot1qTpFdbPort). If supported, we get VLAN in the OID.
      2) If Q-BRIDGE-MIB is missing, fall back to BRIDGE-MIB per-VLAN community indexing
         (community@<vlan>) and dot1dTpFdbPort.

    Note: Many Cisco platforms require community string indexing to query FDB tables per VLAN.
    """
    baseport_to_ifindex = load_baseport_ifindex(snmp)

    # 1) Q-BRIDGE-MIB
    try:
        for vlan, mac, bridge_port in iter_fdb_ports(snmp):
            ifindex = baseport_to_ifindex.get(bridge_port)
            if ifindex:
                yield vlan, mac, ifindex
        return
    except Exception:
        pass

    # 2) BRIDGE-MIB with VLAN indexing (community@vlan)
    vlans = []
    try:
        vlans = operational_vlans(snmp)
    except Exception:
        vlans = []

    # Fallback: if we couldn't enumerate VLANs, try a few common ones
    if not vlans:
        vlans = [1]

    for vlan in vlans:
        comm = f"{base_community}@{vlan}"
        try:
            for oid, val in snmp.walk(DOT1D_TP_FDB_PORT, community=comm):
                mac = _parse_mac_from_oid(oid)
                # val may be like "INTEGER: 63" or just "63"
                if ":" in val:
                    val = val.split(":", 1)[1].strip()
                bridge_port = int(val.strip())
                ifindex = baseport_to_ifindex.get(bridge_port)
                if ifindex:
                    yield vlan, mac, ifindex
        except Exception:
            # ignore VLANs we can't query
            continue

def mac_counts_by_ifindex(snmp, base_community: str) -> Dict[int, int]:
    counts: Dict[int, int] = {}
    for vlan, mac, ifindex in iter_fdb(snmp, base_community):
        counts[ifindex] = counts.get(ifindex, 0) + 1
    return counts
