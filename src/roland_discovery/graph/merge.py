from __future__ import annotations

from typing import Dict, List, Tuple
import networkx as nx

def _pick_canonical_id(hostname: str, existing_ids: set[str]) -> str:
    # Prefer plain hostname for clean graphs; avoid collisions.
    if hostname not in existing_ids:
        return hostname
    pref = f"host:{hostname}"
    if pref not in existing_ids:
        return pref
    i = 2
    while True:
        cand = f"host:{hostname}#{i}"
        if cand not in existing_ids:
            return cand
        i += 1

def merge_by_hostname(g: nx.MultiGraph) -> nx.MultiGraph:
    """Return a new graph where nodes sharing the same 'hostname' are merged.

    The merged node id is the hostname (or 'host:<hostname>' if needed).
    The merged node will have:
      - hostname
      - ips: list[str] (all IPs seen for that hostname)
      - poll_status: 'ok' if any member ok else 'failed' if any failed else missing
      - snmp_error: aggregated (unique) errors
      - sysdescr: first non-empty
    """
    groups: Dict[str, List[str]] = {}
    for n, attrs in g.nodes(data=True):
        hn = attrs.get("hostname")
        ip = attrs.get("ip")
        if hn and ip:
            groups.setdefault(hn, []).append(n)

    if not groups:
        return g

    # node mapping (original -> canonical)
    mapping: Dict[str, str] = {}
    existing = set(g.nodes())
    for hn, nodes in groups.items():
        if len(nodes) < 2:
            continue
        canon = _pick_canonical_id(hn, existing)
        existing.add(canon)
        for n in nodes:
            mapping[n] = canon

    if not mapping:
        return g

    # Build merged graph
    ng = nx.MultiGraph()
    ng.graph.update(g.graph)

    # First add all nodes with mapped ids
    for n, attrs in g.nodes(data=True):
        nn = mapping.get(n, n)
        if nn not in ng:
            ng.add_node(nn, **attrs)
        else:
            # merge attributes
            tgt = ng.nodes[nn]
            # hostname
            if attrs.get("hostname") and not tgt.get("hostname"):
                tgt["hostname"] = attrs.get("hostname")
            # ips list
            ips = set(tgt.get("ips") or [])
            ip = attrs.get("ip")
            if ip:
                ips.add(ip)
            if ips:
                tgt["ips"] = sorted(ips)
            # poll status
            ps = attrs.get("poll_status")
            tps = tgt.get("poll_status")
            if ps == "ok":
                tgt["poll_status"] = "ok"
            elif ps == "failed" and tps != "ok":
                tgt["poll_status"] = "failed"
            # device_role/vendor/family: prefer anything non-unknown
            for k in ("device_role","device_vendor","device_family"):
                if attrs.get(k) and attrs.get(k) != "unknown":
                    if not tgt.get(k) or tgt.get(k) == "unknown":
                        tgt[k] = attrs.get(k)

            # sysdescr: first non-empty wins
            if attrs.get("sysdescr") and not tgt.get("sysdescr"):
                tgt["sysdescr"] = attrs.get("sysdescr")
            # snmp_error aggregate
            errs = set((tgt.get("snmp_errors") or []))
            if attrs.get("snmp_error"):
                errs.add(str(attrs.get("snmp_error")))
            if errs:
                tgt["snmp_errors"] = sorted(errs)

    # Now edges, remap endpoints
    for u, v, k, attrs in g.edges(keys=True, data=True):
        uu = mapping.get(u, u)
        vv = mapping.get(v, v)
        if uu == vv:
            # self-edge after merge is usually noise; keep only if it represents distinct ports
            # but collapsing can create self edges; drop them for clarity.
            continue
        ng.add_edge(uu, vv, **attrs)

    # Deduplicate endpoints to merged ids
    eps = ng.graph.get("endpoints") or []
    if eps:
        # If we merged switch node IDs, update endpoint records too
        for ep in eps:
            sip = ep.get("switch_ip")
            # switch nodes are keyed by ip in graph, so map using any node that has that ip
            # easiest: find node with matching 'ip' and map through mapping
            # if not found, leave as-is.
            for n, attrs in g.nodes(data=True):
                if attrs.get("ip") == sip:
                    ep["switch_node"] = mapping.get(n, n)
                    break

    # Clean up: ensure each merged node has ips populated at least with its 'ip'
    for n, attrs in ng.nodes(data=True):
        ip = attrs.get("ip")
        if attrs.get("hostname"):
            ips = set(attrs.get("ips") or [])
            if ip:
                ips.add(ip)
            if ips:
                attrs["ips"] = sorted(ips)

    return ng

# Backwards-compatible alias
merge_graph_by_hostname = merge_by_hostname


# Backwards compatible alias
merge_graph_by_hostname = merge_by_hostname
