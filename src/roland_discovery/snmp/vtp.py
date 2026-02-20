VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
VTP_VLAN_NAME  = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"

def load_vlans(snmp):
    """Return {vlan_id: {"state": str, "name": str}} where possible.

    Many Cisco devices expose VLAN inventory via CISCO-VTP-MIB.
    """
    out = {}
    # state
    for oid, val in snmp.walk(VTP_VLAN_STATE):
        vlan = int(oid.split(".")[-1])
        out.setdefault(vlan, {})["state"] = val
    # name (best-effort)
    try:
        for oid, val in snmp.walk(VTP_VLAN_NAME):
            vlan = int(oid.split(".")[-1])
            out.setdefault(vlan, {})["name"] = val.strip().strip('"')
    except Exception:
        pass
    return out

def operational_vlans(snmp):
    """Return a sorted list of VLAN IDs that look operational.

    Accepts either numeric enums or textual enums from snmpwalk output.
    """
    vlans = load_vlans(snmp)
    ops = []
    for vlan, meta in vlans.items():
        state = (meta.get("state") or "").lower()
        # Cisco commonly returns operational(1); we accept 1 or "operational"
        if "operational" in state or state.strip() in {"1", "operational(1)"}:
            ops.append(vlan)
    return sorted(set(ops))
