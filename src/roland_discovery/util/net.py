import ipaddress
from typing import Iterable, List

def _parse_nets(cidrs: Iterable[str]) -> List[ipaddress._BaseNetwork]:
    nets = []
    for c in cidrs or []:
        nets.append(ipaddress.ip_network(c, strict=False))
    return nets

def allowed(ip: str, include: Iterable[str], exclude: Iterable[str]) -> bool:
    addr = ipaddress.ip_address(ip)
    inc = _parse_nets(include)
    exc = _parse_nets(exclude)

    if inc and not any(addr in n for n in inc):
        return False
    if exc and any(addr in n for n in exc):
        return False
    return True
