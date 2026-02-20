SYSNAME_OID = "1.3.6.1.2.1.1.5.0"
SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"

def _clean_value(v: str) -> str:
    if ":" in v:
        v = v.split(":", 1)[1].strip()
    return v.strip().strip('"')

def get_sysname(snmp) -> str | None:
    for _oid, val in snmp.walk(SYSNAME_OID):
        return _clean_value(val)
    return None

def get_sysdescr(snmp) -> str | None:
    for _oid, val in snmp.walk(SYSDESCR_OID):
        return _clean_value(val)
    return None
