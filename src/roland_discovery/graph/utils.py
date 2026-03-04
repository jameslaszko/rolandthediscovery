# src/roland_discovery/graph/utils.py

from collections import defaultdict
import json


def deduplicate_nodes(nodes: list, links: list) -> tuple[list, list, dict]:
    """
    Merge nodes by hostname (primary key) while preserving:
      - ALL IPs (VLAN, loopback, mgmt, etc.)
      - Full ip_to_ifname mapping
    Returns: (clean_nodes, clean_links, ip_to_node_lookup)
    """
    by_key = {}
    for node in nodes:
        key = node.get("hostname") or node["id"]          # hostname is authoritative
        if key not in by_key:
            by_key[key] = node.copy()
            by_key[key]["ips"] = list(set(node.get("ips", [])))
            by_key[key]["ip_to_ifname"] = dict(node.get("ip_to_ifname", {}))
            by_key[key]["id"] = key                       # canonical ID = hostname or fallback
        else:
            # Merge IPs & interface mappings from any discovery path
            existing = by_key[key]
            existing["ips"].extend(node.get("ips", []))
            existing["ips"] = list(dict.fromkeys(existing["ips"]))   # dedup + preserve order
            existing["ip_to_ifname"].update(node.get("ip_to_ifname", {}))

    # Remap links to use the canonical hostname (or original ID) as node key
    clean_links = []
    for link in links:
        # Find source/dest nodes to get their canonical key
        src_node = next((n for n in nodes if n["id"] == link["source"]), None)
        dst_node = next((n for n in nodes if n["id"] == link["target"]), None)
        
        src_key = src_node.get("hostname") or link["source"] if src_node else link["source"]
        dst_key = dst_node.get("hostname") or link["target"] if dst_node else link["target"]
        
        # Update link to use canonical keys
        new_link = link.copy()
        new_link["source"] = src_key
        new_link["target"] = dst_key
        clean_links.append(new_link)

    clean_nodes = list(by_key.values())

    # Create IP → canonical node ID lookup (very useful for documentation)
    ip_to_node = {}
    for node in clean_nodes:
        for ip in node.get("ips", []):
            ip_to_node[ip] = node["id"]          # now points to hostname or stable ID

    return clean_nodes, clean_links, ip_to_node