from __future__ import annotations

from typing import List, Set

from roland_discovery.snmp.ifmib import load_ifnames
from roland_discovery.snmp.bridge import load_baseport_ifindex
from roland_discovery.snmp.qbridge import iter_fdb_ports

_SKIP_PREFIXES = ("Vlan", "loopback", "port-channel", "Po", "mgmt", "lo")

def discover_endpoints_for_device(snmp, switch_ip: str, switch_hostname: str | None, infra_ports: Set[str], max_endpoints: int) -> List[dict]:
    ifnames = load_ifnames(snmp)
    bp_to_ifindex = load_baseport_ifindex(snmp)

    out: List[dict] = []
    count = 0

    for vlan, mac, bridge_port in iter_fdb_ports(snmp):
        if count >= max_endpoints:
            break
        ifindex = bp_to_ifindex.get(bridge_port)
        if ifindex is None:
            continue
        ifname = ifnames.get(ifindex, f"if{ifindex}")

        if ifname in infra_ports:
            continue
        if ifname.startswith(_SKIP_PREFIXES):
            continue

        out.append(
            {
                "switch_ip": switch_ip,
                "switch_hostname": switch_hostname,
                "vlan": vlan,
                "mac": mac,
                "ifname": ifname,
            }
        )
        count += 1

    return out
