from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple

from roland_discovery.ssh.client import SshClient  # if needed for type hints; optional


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str


@dataclass
class CdpDetailNeighbor:
    device_id: str
    ip: str
    local_interface: str
    port_id: str


def parse_show_ip_interface_brief(text: str) -> Dict[str, str]:
    out = {}
    lines = text.splitlines()
    start = False
    for line in lines:
        line = line.strip()
        if "Interface" in line and "IP-Address" in line:
            start = True
            continue
        if not start or not line:
            continue
        parts = re.split(r'\s+', line)
        if len(parts) >= 6:
            iface = parts[0]
            ip = parts[1]
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                out[iface] = ip
    print(f"[DEBUG enrich] Parsed {len(out)} entries from ip int brief")
    return out


def parse_show_arp(text: str) -> Dict[str, ArpEntry]:
    out = {}
    lines = text.splitlines()
    start = False
    for line in lines:
        line = line.strip()
        if "Protocol" in line and "Address" in line:
            start = True
            continue
        if not start or not line:
            continue
        parts = re.split(r'\s+', line)
        if len(parts) >= 6 and parts[0].lower() == "internet":
            ip = parts[1]
            age = parts[2]
            mac = parts[3]
            arp_type = parts[4]
            iface = ' '.join(parts[5:])
            out[ip] = ArpEntry(ip=ip, mac=mac, interface=iface)
    print(f"[DEBUG enrich] Parsed {len(out)} ARP entries")
    return out
    
def parse_show_arp(text: str) -> Dict[str, ArpEntry]:
    """Return ip → ArpEntry (handles your "Protocol Address Age (min) Hardware Addr Type Interface")."""
    out = {}
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    in_data = False
    for line in lines:
        if "Protocol" in line and "Address" in line:
            in_data = True
            continue
        if not in_data:
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 6 or parts[0].lower() != "internet":
            continue
        ip = parts[1]
        age = parts[2]
        mac = parts[3]
        arp_type = parts[4]
        iface = ' '.join(parts[5:])
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and re.match(r"^([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$", mac):
            out[ip] = ArpEntry(ip=ip, mac=mac, interface=iface)
    return out


def parse_cdp_neighbors_detail(text: str) -> List[CdpDetailNeighbor]:
    """Parse 'show cdp neighbors detail' into structured neighbors."""
    # Split by "-------------------------"
    blocks = re.split(r"^-+$", text.strip(), flags=re.MULTILINE)
    out = []

    for b in blocks:
        b = b.strip()
        if not b or "Device ID" not in b:
            continue

        device_id = re.search(r"Device ID:\s*(.+)", b, re.I | re.M)
        device_id = device_id.group(1).strip() if device_id else ""

        ip = re.search(r"IP address:\s*(\d+\.\d+\.\d+\.\d+)", b, re.I | re.M)
        ip = ip.group(1) if ip else ""

        local_intf = re.search(r"Interface:\s*([^,\n]+)", b, re.I | re.M)
        local_intf = local_intf.group(1).strip() if local_intf else ""

        port_id = re.search(r"Port ID \(outgoing port\):\s*(.+)", b, re.I | re.M)
        port_id = port_id.group(1).strip() if port_id else ""

        if device_id and local_intf:
            out.append(CdpDetailNeighbor(device_id=device_id, ip=ip, local_interface=local_intf, port_id=port_id))

    return out

# Backwards-compatible alias
parse_show_cdp_neighbors_detail = parse_cdp_neighbors_detail


# -----------------------------
# Switching / VLAN catalog
# -----------------------------


def _parse_vlan_list(v: str) -> List[int]:
    """Parse VLAN lists like '1,10,20-30' into ints (best-effort)."""
    v = (v or "").strip()
    if not v or v.lower() in {"none", "all"}:
        return []
    out: List[int] = []
    for part in v.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                a_i = int(a)
                b_i = int(b)
            except Exception:
                continue
            if a_i <= b_i:
                out.extend(list(range(a_i, b_i + 1)))
        else:
            try:
                out.append(int(part))
            except Exception:
                continue
    return sorted(set(out))

def parse_show_vlan_brief(text: str) -> Dict[int, Dict]:
    vlans = {}
    lines = text.splitlines()
    in_table = False
    current_vlan = None
    for line in lines:
        if "VLAN Name Status Ports" in line:
            in_table = True
            continue
        if in_table and line.strip() and not line.startswith("-"):
            parts = line.split(maxsplit=3)
            if len(parts) >= 3 and parts[0].isdigit():
                vlan_id = int(parts[0])
                name = parts[1]
                status = parts[2]
                ports = parts[3].strip() if len(parts) > 3 else ""
                vlans[vlan_id] = {"name": name, "status": status, "ports": ports.split(", ") if ports else []}
                current_vlan = vlan_id
            elif current_vlan and line.strip().startswith(" "):
                # Continuation line for ports
                vlans[current_vlan]["ports"].extend([p.strip() for p in line.split(",") if p.strip()])
    return vlans

def parse_show_interfaces_trunk(text: str) -> Dict[str, Dict]:
    trunks = {}
    lines = text.splitlines()
    current_port = None
    section = None
    for line in lines:
        if "Port Mode Encapsulation Status Native vlan" in line:
            section = "header"
            continue
        if section == "header" and line.strip() and line[0].isalpha():
            parts = line.split()
            port = parts[0]
            mode = parts[1]
            encap = parts[2]
            status = parts[3]
            native = parts[4]
            trunks[port] = {"mode": mode, "encap": encap, "status": status, "native": native, "allowed": []}
            current_port = port
        if "Vlans allowed on trunk" in line:
            section = "allowed"
            continue
        if section == "allowed" and current_port and line.strip().startswith(current_port):
            allowed_str = line.split(maxsplit=1)[1].strip()
            # Parse ranges like 1-4094 or 1148-1153
            for part in allowed_str.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    trunks[current_port]["allowed"].extend(range(start, end+1))
                else:
                    trunks[current_port]["allowed"].append(int(part))
    return trunks

def parse_show_interfaces_switchport(text: str) -> Dict[str, Dict[str, Any]]:
    """Parse `show interfaces switchport` per-port blocks."""
    out = {}
    current_port = None
    current_block = []

    lines = text.splitlines()
    for ln in lines:
        ln = ln.strip()
        if ln.startswith("Name: "):
            if current_port and current_block:
                blob = '\n'.join(current_block)
                d = {}
                m = re.search(r"Administrative Mode:\s*(.+)", blob, re.I | re.M)
                mode = m.group(1).strip().lower() if m else "unknown"
                if "trunk" in mode:
                    d["mode"] = "trunk"
                elif "access" in mode:
                    d["mode"] = "access"
                elif "dynamic" in mode:
                    d["mode"] = "dynamic"
                else:
                    d["mode"] = "unknown"

                m = re.search(r"Access Mode VLAN:\s*(\d+)", blob, re.M)
                if m:
                    d["access_vlan"] = int(m.group(1))
                m = re.search(r"Trunking Native Mode VLAN:\s*(\d+)", blob, re.M)
                if m:
                    d["native_vlan"] = int(m.group(1))
                m = re.search(r"Trunking VLANs Enabled:\s*(.+)$", blob, re.M)
                if m:
                    d["trunk_vlans"] = _parse_vlan_list(m.group(1).strip())

                out[current_port] = d

            current_port = ln.replace("Name: ", "").strip()
            current_block = []
        elif current_port:
            if ln:
                current_block.append(ln)

    # Flush last block
    if current_port and current_block:
        blob = '\n'.join(current_block)
        d = {}
        m = re.search(r"Administrative Mode:\s*(.+)", blob, re.I | re.M)
        mode = m.group(1).strip().lower() if m else "unknown"
        if "trunk" in mode:
            d["mode"] = "trunk"
        elif "access" in mode:
            d["mode"] = "access"
        elif "dynamic" in mode:
            d["mode"] = "dynamic"
        else:
            d["mode"] = "unknown"

        m = re.search(r"Access Mode VLAN:\s*(\d+)", blob, re.M)
        if m:
            d["access_vlan"] = int(m.group(1))
        m = re.search(r"Trunking Native Mode VLAN:\s*(\d+)", blob, re.M)
        if m:
            d["native_vlan"] = int(m.group(1))
        m = re.search(r"Trunking VLANs Enabled:\s*(.+)$", blob, re.M)
        if m:
            d["trunk_vlans"] = _parse_vlan_list(m.group(1).strip())

        out[current_port] = d

    return out
    
def collect_switching_catalog(
    ssh: Optional[SshClient] = None,
    results: Optional[Dict[str, str]] = None,
    debug: bool = False
) -> Dict[str, Any]:
    if results is None:
        results = {}

    # Force use of pre-fetched if provided; no live exec fallback
    def get_output(cmd: str) -> str:
        if cmd in results:
            out = results[cmd].strip()
            if debug:
                print(f"[enrich] Using pre-fetched '{cmd}' ({len(out)} chars)")
            return out
        if debug:
            print(f"[enrich] No pre-fetched output for '{cmd}'")
        return ""

    vlan_txt   = get_output("show vlan brief") or get_output("show vlan")
    trunk_txt  = get_output("show interfaces trunk") or get_output("show interface trunk")
    sw_txt     = get_output("show interfaces switchport")

    catalog = {
        "commands": {
            "vlan": "show vlan brief" if vlan_txt else "",
            "trunk": "show interfaces trunk" if trunk_txt else "",
            "switchport": "show interfaces switchport" if sw_txt else "",
        },
        "vlans": parse_show_vlan_brief(vlan_txt) if vlan_txt else {},
        "trunks": parse_show_interfaces_trunk(trunk_txt) if trunk_txt else {},
        "switchports": parse_show_interfaces_switchport(sw_txt) if sw_txt else {},
    }

    if debug:
        print(f"[enrich] Catalog: vlans={len(catalog['vlans'])}, trunks={len(catalog['trunks'])}, switchports={len(catalog['switchports'])}")

    return catalog
    
def check_trunk_transitability(node):
    issues = []
    uplink_ports = ["Te1/0/14", "Te1/0/15", ...]  # from your known uplinks
    for port in uplink_ports:
        if port in node["ssh_switching"]["trunks"]:
            allowed = set(node["ssh_switching"]["trunks"][port]["allowed"])
            for vlan_id, sv in node["ip_to_ifname"].items():
                if vlan_id not in allowed:
                    issues.append(f"VLAN {vlan_id} not allowed on uplink {port}")
    return issues