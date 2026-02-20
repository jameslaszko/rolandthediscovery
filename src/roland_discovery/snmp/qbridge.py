DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"

def _parse_vlan_mac_from_oid(oid_str: str):
    parts = oid_str.split(".")
    vlan = int(parts[-7])
    mac_bytes = [int(x) for x in parts[-6:]]
    mac = ":".join(f"{b:02x}" for b in mac_bytes)
    return vlan, mac

def iter_fdb_ports(snmp):
    for oid, val in snmp.walk(DOT1Q_FDB_PORT):
        vlan, mac = _parse_vlan_mac_from_oid(oid)
        if ":" in val:
            val = val.split(":", 1)[1].strip()
        bridge_port = int(val.strip())
        yield vlan, mac, bridge_port
