import ipaddress
from typing import Iterable, List
from ipaddress import ip_interface, IPv4Network, IPv4Interface

def same_subnet(ip1: str, ip2: str) -> bool:
    """Return True if two IPs are in the same subnet (any mask)."""
    try:
        i1 = ip_interface(ip1)
        i2 = ip_interface(ip2)
        return i1.network == i2.network
    except:
        return False

def is_point_to_point(ip1: str, ip2: str) -> bool:
    """Return True if two IPs form a valid /30 or /31 routed link."""
    try:
        i1 = ip_interface(ip1)
        i2 = ip_interface(ip2)
        net = i1.network
        if net.prefixlen in (30, 31):
            return i1.network == i2.network
        return False
    except:
        return False
        
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
