# src/roland_discovery/graph/utils.py
from collections import defaultdict

def deduplicate_nodes(nodes: list, links: any) -> tuple[list, list, dict]:
    """
    Deduplicate nodes by their string value (IP or hostname) while preserving:
      - All IPs when nodes are dicts
      - Basic string nodes when the graph is simple
    Handles networkx-style edge/link views (MultiEdgeView, EdgeView)
    Returns: (clean_nodes, clean_links as list, ip_to_node_lookup dict)
    """
    # Force links to be a real list (handles networkx views)
    if not isinstance(links, list):
        links = list(links)  # converts EdgeView / MultiEdgeView to list of tuples/dicts

    # Check if nodes are simple strings or dicts
    is_simple = all(isinstance(n, str) for n in nodes)

    if is_simple:
        # Simple graph: nodes are just IPs/hostnames → dedup by string value
        unique_nodes = []
        seen = set()
        for node_str in nodes:
            if node_str not in seen:
                seen.add(node_str)
                unique_nodes.append(node_str)
        
        # Minimal node objects for downstream compatibility
        clean_nodes = [{"id": n, "label": n, "type": "ip"} for n in unique_nodes]
        
        # IP → node lookup
        ip_to_node = {n: n for n in unique_nodes}
        
        # Links are already list — no further change needed
        clean_links = links
        
        print(f"[dedup] Simple graph mode: deduplicated {len(nodes)} → {len(clean_nodes)} string nodes")
    
    else:
        # Rich graph: nodes are dicts → merge by hostname or id
        by_key = {}
        for node in nodes:
            key = (
                node.get("hostname")
                or node.get("id")
                or node.get("ip")
                or str(node)
            )
            if key not in by_key:
                by_key[key] = node.copy()
                by_key[key]["ips"] = list(set(node.get("ips", [key])))
                by_key[key]["ip_to_ifname"] = dict(node.get("ip_to_ifname", {}))
                by_key[key]["id"] = key
            else:
                existing = by_key[key]
                existing["ips"].extend(node.get("ips", []))
                existing["ips"] = list(dict.fromkeys(existing["ips"]))
                existing["ip_to_ifname"].update(node.get("ip_to_ifname", {}))

        clean_nodes = list(by_key.values())

        ip_to_node = {}
        for node in clean_nodes:
            for ip in node.get("ips", []):
                ip_to_node[ip] = node["id"]

        # Remap links to canonical keys
        clean_links = []
        for link in links:
            # link is probably a tuple (source, target, data) or dict
            if isinstance(link, tuple):
                src, tgt, data = link if len(link) == 3 else (link[0], link[1], {})
            elif isinstance(link, dict):
                src = link.get("source")
                tgt = link.get("target")
                data = link
            else:
                continue  # skip invalid

            src_node = next((n for n in nodes if n.get("id") == src), None)
            dst_node = next((n for n in nodes if n.get("id") == tgt), None)
            
            src_key = src_node.get("hostname") or src_node.get("id") or src if src_node else src
            tgt_key = dst_node.get("hostname") or dst_node.get("id") or tgt if dst_node else tgt
            
            new_link = data.copy() if isinstance(data, dict) else {}
            new_link["source"] = src_key
            new_link["target"] = tgt_key
            # Preserve any other data (label, proto, local_if, etc.)
            clean_links.append(new_link)

        print(f"[dedup] Rich graph mode: deduplicated {len(nodes)} → {len(clean_nodes)} dict nodes")

    return clean_nodes, clean_links, ip_to_node