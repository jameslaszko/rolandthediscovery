def _hn(g, n):
    return g.nodes[n].get("hostname") or g.nodes[n].get("ip", n)  # fallback to IP if no hostname

def print_summary(g):
    rows = []
    for u, v, k, attrs in g.edges(keys=True, data=True):
        # Use 'proto' (your add_edge uses proto="cdp")
        proto = attrs.get("proto", attrs.get("protocol", "?"))
        local_if = attrs.get("local_if", "?")
        remote_if = attrs.get("remote_if", attrs.get("remote_port", "?"))
        rows.append((proto, u, _hn(g, u), local_if, v, _hn(g, v), remote_if))

    print("\n--- Summary (links) ---")
    # Wider columns to avoid truncation of interface names
    header = f"{'PROTO':<6} {'SRC IP':<16} {'SRC HOSTNAME':<30} {'LOCAL IF':<22} {'DST IP':<16} {'DST HOSTNAME':<30} {'REMOTE IF':<22}"
    print(header)
    print("-" * len(header))

    # Sort by source hostname → destination IP for cleaner reading
    rows.sort(key=lambda r: (r[2].lower(), r[4]))

    for proto, src_ip, src_host, local_if, dst_ip, dst_host, remote_if in rows:
        # Truncate only very long hostnames, but keep interfaces full
        src_host_disp = src_host[:28] + "…" if len(src_host) > 28 else src_host
        dst_host_disp  = dst_host[:28] + "…" if len(dst_host) > 28 else dst_host
        
        print(f"{proto:<6} {src_ip:<16} {src_host_disp:<30} "
              f"{local_if:<22} {dst_ip:<16} {dst_host_disp:<30} "
              f"{remote_if:<22}")

    # Count and report total CDP links
    cdp_count = sum(1 for r in rows if r[0].upper() in ("CDP", "LLDP"))
    print(f"\nTotal links discovered: {len(rows)} (CDP/LLDP: {cdp_count})")

    # Endpoints (unchanged)
    eps = g.graph.get("endpoints") or []
    if eps:
        print(f"\nEndpoints discovered: {len(eps)} (written to topology.json meta.endpoints)")