from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from roland_discovery.snmp.ifmib import load_ifnames

LLDP_REM_SYSNAME = "0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_PORTID  = "0.8802.1.1.2.1.4.1.1.7"

def _clean_value(v: str) -> str:
    if ":" in v:
        v = v.split(":", 1)[1].strip()
    return v.strip().strip('"')

def _parse_lldp_index(oid_str: str) -> Tuple[int, int, int]:
    parts = oid_str.split(".")
    rem_index = int(parts[-1])
    local_port = int(parts[-2])
    time_mark = int(parts[-3])
    return time_mark, local_port, rem_index

@dataclass(frozen=True)
class Neighbor:
    protocol: str
    local_if: str
    remote_device: str
    remote_port: str
    mgmt_ip: Optional[str] = None

def get_lldp_neighbors(snmp) -> List[Neighbor]:
    ifnames = load_ifnames(snmp)
    sysnames: Dict[Tuple[int,int,int], str] = {}
    portids: Dict[Tuple[int,int,int], str] = {}

    for oid, val in snmp.walk(LLDP_REM_SYSNAME):
        sysnames[_parse_lldp_index(oid)] = _clean_value(val)

    for oid, val in snmp.walk(LLDP_REM_PORTID):
        portids[_parse_lldp_index(oid)] = _clean_value(val)

    neighbors: List[Neighbor] = []
    for idx, dev in sysnames.items():
        _tm, local_port, _ri = idx
        neighbors.append(
            Neighbor(
                protocol="lldp",
                local_if=ifnames.get(local_port, f"if{local_port}"),
                remote_device=dev,
                remote_port=portids.get(idx, "unknown"),
                mgmt_ip=None,
            )
        )
    return neighbors
