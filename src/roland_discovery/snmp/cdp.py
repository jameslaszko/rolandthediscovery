from dataclasses import dataclass, field
from typing import List

@dataclass
class Neighbor:
    mgmt_ip: str
    remote_device: str
    local_if: str
    remote_port: str
    platform: str = ""
    capabilities: List[str] = field(default_factory=list)

def get_cdp_neighbors(snmp):
    neighbors = []
    device_id_oid = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
    device_id_raw = snmp.walk(device_id_oid)
    for full_oid, value in device_id_raw:
        print("[RAW SNMP cdpCacheDeviceId]", (full_oid, value))  # add for debug
        # Suffix after OID. is "ifIndex.entryIdx"
        # Extract index from suffix (e.g. "3.88")
        suffix = full_oid[len(device_id_oid) + 1:]  # after OID + dot
        index_parts = suffix.split('.')
        if len(index_parts) < 2:
            continue
        ifindex = index_parts[0]
        entry_idx = index_parts[1]
        full_index = f"{ifindex}.{entry_idx}"

        # Remote device name
        remote_device = value.strip()
        if 'STRING: ' in remote_device:
            remote_device = remote_device.split('STRING: ', 1)[1].strip()
        remote_device = remote_device.strip('"')  # remove wrapping quotes

        # mgmt IP - convert hex to dotted
        mgmt_ip = ""
        mgmt_ip_oid = f"1.3.6.1.4.1.9.9.23.1.2.1.1.4.{full_index}"
        mgmt_ip_raw = snmp.get(mgmt_ip_oid)
        if mgmt_ip_raw:
            value = mgmt_ip_raw.strip()
            print(f"[DEBUG cdp mgmt_raw] {mgmt_ip_oid} → {value}")
            hex_part = value
            if 'IpAddress: ' in value:
                hex_part = value.split('IpAddress: ')[1].strip()
            # Clean hex_part: remove any quotes, extra spaces
            hex_part = hex_part.strip('"').strip()
            try:
                # Split on spaces, convert each 2-char hex to int
                hex_list = hex_part.split()
                ip_bytes = [int(h, 16) for h in hex_list if h]  # skip empty
                if len(ip_bytes) == 4:
                    mgmt_ip = '.'.join(str(b) for b in ip_bytes)
                else:
                    raise ValueError("Not 4 bytes")
            except Exception as e:
                print(f"[WARN cdp hex fail] {hex_part} → {e}")
                mgmt_ip = hex_part  # fallback to raw hex

        if not mgmt_ip:
            print(f"[WARN cdp] No mgmt_ip for {remote_device} (index {full_index})")
            
        # Local interface (prefer ifName for short names like Te2/0/23)
        local_if = ""
        ifname_oid = f"1.3.6.1.2.1.31.1.1.1.1.{ifindex}"
        ifname_raw = snmp.get(ifname_oid)
        if ifname_raw:
            value = ifname_raw.strip()
            local_if = value.split('STRING: ', 1)[1].strip() if 'STRING: ' in value else value.strip()

        # Fallback to ifDescr if empty
        if not local_if:
            ifdescr_oid = f"1.3.6.1.2.1.2.2.1.2.{ifindex}"
            ifdescr_raw = snmp.get(ifdescr_oid)
            if ifdescr_raw:
                value = ifdescr_raw.strip()
                local_if = value.split('STRING: ', 1)[1].strip() if 'STRING: ' in value else value.strip()

        # Remote port
        remote_port = ""
        remote_port_oid = f"1.3.6.1.4.1.9.9.23.1.2.1.1.7.{full_index}"
        remote_port_raw = snmp.get(remote_port_oid)
        if remote_port_raw:
            value = remote_port_raw.strip()
            remote_port = value.split('STRING: ', 1)[1].strip() if 'STRING: ' in value else value.strip()
            remote_port = remote_port.strip('"')  # remove quotes

        # Platform
        platform = ""
        platform_oid = f"1.3.6.1.4.1.9.9.23.1.2.1.1.8.{full_index}"
        platform_raw = snmp.get(platform_oid)
        if platform_raw:
            value = platform_raw.strip()
            platform = value.split('STRING: ', 1)[1].strip() if 'STRING: ' in value else value.strip()
            platform = platform.strip('"')  # remove quotes
            
        # Debug print before creating object
        print(f"[DEBUG cdp neighbor] {remote_device} | IP: {mgmt_ip} | local_if: {local_if} | remote_port: {remote_port} | platform: {platform}")

        # Create neighbor only if we have mgmt_ip (skip invalid entries)
        if mgmt_ip:
            neighbor = Neighbor(
                mgmt_ip=mgmt_ip,
                remote_device=remote_device,
                local_if=local_if,
                remote_port=remote_port,
                platform=platform,
            )
            neighbors.append(neighbor)
        else:
            print(f"[WARN cdp] Skipping neighbor {remote_device} - no valid mgmt_ip")
            
    print(f"[DEBUG cdp] Parsed {len(neighbors)} neighbors")
    return neighbors