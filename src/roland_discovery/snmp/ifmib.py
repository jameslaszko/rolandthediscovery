IFNAME_OID = "1.3.6.1.2.1.31.1.1.1.1"

def _clean_value(v: str) -> str:
    if ":" in v:
        v = v.split(":", 1)[1].strip()
    return v.strip().strip('"')

def load_ifnames(snmp):
    names = {}
    for oid, val in snmp.walk(IFNAME_OID):
        names[int(oid.split(".")[-1])] = _clean_value(val)
    return names
