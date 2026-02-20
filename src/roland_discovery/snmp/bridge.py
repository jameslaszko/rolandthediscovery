DOT1D_BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"

def load_baseport_ifindex(snmp):
    out = {}
    for oid, val in snmp.walk(DOT1D_BASEPORT_IFINDEX):
        bp = int(oid.split(".")[-1])
        if ":" in val:
            val = val.split(":", 1)[1].strip()
        out[bp] = int(val.strip())
    return out
