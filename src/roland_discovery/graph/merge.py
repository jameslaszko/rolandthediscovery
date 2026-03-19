from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx


def _is_ip_like(value: Optional[str]) -> bool:
    if not value:
        return False
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value.strip()))


def normalize_hostname(hostname: Optional[str]) -> Optional[str]:
    """
    Safe hostname normalization.

    This intentionally does NOT do fuzzy matching.
    It only strips obvious inventory suffixes like:
      HUB-BB-NX02(SSI191301RT) -> hub-bb-nx02
    """
    if not hostname:
        return None

    s = hostname.strip()
    if not s or s == "?":
        return None
    if _is_ip_like(s):
        return None

    # strip parenthetical asset/inventory suffixes
    s = re.sub(r"\([^)]*\)", "", s).strip()

    # collapse whitespace
    s = re.sub(r"\s+", " ", s).strip()

    return s.lower() if s else None


def _score_node(attrs: Dict) -> Tuple[int, int, int, int]:
    hostname = attrs.get("hostname") or ""
    ips = attrs.get("ips") or []
    sysdescr = attrs.get("sysdescr") or ""
    main_ip = attrs.get("main_ip") or ""

    return (
        1 if hostname and not _is_ip_like(hostname) else 0,
        len(ips),
        1 if sysdescr else 0,
        1 if main_ip else 0,
    )


def _pick_primary_node(g: nx.MultiGraph, nodes: List[str]) -> str:
    return max(nodes, key=lambda n: _score_node(g.nodes[n]))


def _merge_attrs(target: Dict, source: Dict, source_node_id: str) -> None:
    # Prefer cleaner hostname
    t_host = target.get("hostname")
    s_host = source.get("hostname")
    if s_host and (not t_host or _is_ip_like(t_host)):
        target["hostname"] = s_host

    t_norm = target.get("norm_hostname")
    s_norm = source.get("norm_hostname") or normalize_hostname(source.get("hostname"))
    if s_norm and not t_norm:
        target["norm_hostname"] = s_norm

    # IP inventory
    ips = set(target.get("ips") or [])
    for value in source.get("ips") or []:
        if value:
            ips.add(value)
    for value in [source.get("ip"), source.get("main_ip"), source_node_id]:
        if value and _is_ip_like(str(value)):
            ips.add(str(value))
    if ips:
        target["ips"] = sorted(ips)

    # Keep an ip/main_ip if missing
    if not target.get("ip") and source.get("ip"):
        target["ip"] = source.get("ip")
    if not target.get("main_ip") and source.get("main_ip"):
        target["main_ip"] = source.get("main_ip")

    # Prefer non-empty metadata
    for key in (
        "platform",
        "sysdescr",
        "device_role",
        "device_vendor",
        "device_family",
        "poll_status",
        "ssh_status",
        "ssh_source",
        "discovery_depth",
    ):
        if source.get(key) and not target.get(key):
            target[key] = source.get(key)

    # Prefer non-unknown role/vendor/family
    for key in ("device_role", "device_vendor", "device_family"):
        sval = source.get(key)
        tval = target.get(key)
        if sval and sval != "unknown" and (not tval or tval == "unknown"):
            target[key] = sval

    # Merge ip_to_ifname
    t_map = dict(target.get("ip_to_ifname") or {})
    s_map = dict(source.get("ip_to_ifname") or {})
    if s_map:
        t_map.update(s_map)
        target["ip_to_ifname"] = t_map

    # Merge endpoint-ish arrays if present
    for list_key in (
        "ssh_ip_interface_brief",
        "ssh_arp",
        "ssh_cdp_neighbors_detail",
        "cdp_neighbors_raw",
        "orphan_svis",
    ):
        t_list = list(target.get(list_key) or [])
        s_list = list(source.get(list_key) or [])
        if s_list:
            target[list_key] = t_list + s_list

    # Merge switching dict shallowly
    t_sw = dict(target.get("ssh_switching") or {})
    s_sw = dict(source.get("ssh_switching") or {})
    if s_sw:
        for k, v in s_sw.items():
            if k not in t_sw:
                t_sw[k] = v
            elif isinstance(t_sw[k], dict) and isinstance(v, dict):
                merged = dict(t_sw[k])
                merged.update(v)
                t_sw[k] = merged
        target["ssh_switching"] = t_sw

    # Preserve seed flag if any member had it
    if source.get("is_seed"):
        target["is_seed"] = True

    # Preserve lowest discovery depth
    if source.get("discovery_depth") is not None:
        if target.get("discovery_depth") is None:
            target["discovery_depth"] = source.get("discovery_depth")
        else:
            try:
                target["discovery_depth"] = min(
                    int(target["discovery_depth"]),
                    int(source["discovery_depth"]),
                )
            except Exception:
                pass

    # Aggregate errors
    errors: Set[str] = set()
    for key in ("snmp_error", "ssh_error", "cdp_error"):
        if target.get(key):
            errors.add(str(target[key]))
        if source.get(key):
            errors.add(str(source[key]))
    if errors:
        target["merge_errors"] = sorted(errors)


def _norm_if(value: Optional[str]) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", "", value.strip().lower())


def _edge_signature(u: str, v: str, attrs: Dict) -> Tuple[Tuple[str, str], Tuple[str, str], str]:
    endpoints = tuple(sorted([str(u).lower(), str(v).lower()]))
    interfaces = tuple(sorted([_norm_if(attrs.get("local_if")), _norm_if(attrs.get("remote_if"))]))
    proto = str(attrs.get("proto") or "").strip().lower()
    return (endpoints, interfaces, proto)


def merge_by_hostname(g: nx.MultiGraph) -> nx.MultiGraph:
    """
    Merge nodes that share the same normalized hostname.

    Important:
    - No fuzzy SequenceMatcher logic.
    - No merge-by-overlapping-IPs logic.
    - Keeps raw IP-only nodes separate unless they were already attached to a
      real hostname node through previous canonicalization.
    """
    groups: Dict[str, List[str]] = {}

    for n, attrs in g.nodes(data=True):
        hostname = attrs.get("hostname")
        norm = attrs.get("norm_hostname") or normalize_hostname(hostname)
        if not norm:
            continue
        groups.setdefault(norm, []).append(n)

    # Only keep real multi-node groups
    groups = {k: v for k, v in groups.items() if len(v) > 1}
    if not groups:
        return g

    mapping: Dict[str, str] = {}
    primary_for_group: Dict[str, str] = {}

    for norm, members in groups.items():
        primary = _pick_primary_node(g, members)
        primary_for_group[norm] = primary
        for n in members:
            mapping[n] = primary

    ng = nx.MultiGraph()
    ng.graph.update(g.graph)

    # Add merged nodes
    added: Set[str] = set()
    for n, attrs in g.nodes(data=True):
        target_id = mapping.get(n, n)

        if target_id not in added:
            ng.add_node(target_id, **dict(g.nodes[target_id] if target_id in g.nodes else attrs))
            added.add(target_id)

        if target_id != n:
            _merge_attrs(ng.nodes[target_id], attrs, n)

    # Ensure norm_hostname / hostname are coherent on primary nodes
    for norm, primary in primary_for_group.items():
        if not ng.nodes[primary].get("norm_hostname"):
            ng.nodes[primary]["norm_hostname"] = norm
        if not ng.nodes[primary].get("hostname"):
            ng.nodes[primary]["hostname"] = norm

    # Remap edges, then dedupe true duplicates
    seen_edges: Set[Tuple[Tuple[str, str], Tuple[str, str], str]] = set()
    for u, v, attrs in g.edges(data=True):
        uu = mapping.get(u, u)
        vv = mapping.get(v, v)

        if uu == vv:
            continue

        sig = _edge_signature(uu, vv, attrs)
        if sig in seen_edges:
            continue
        seen_edges.add(sig)

        ng.add_edge(uu, vv, **attrs)

    # Update endpoint metadata if present
    eps = ng.graph.get("endpoints") or []
    if eps:
        for ep in eps:
            switch_node = ep.get("switch_node")
            if switch_node in mapping:
                ep["switch_node"] = mapping[switch_node]

            switch_ip = ep.get("switch_ip")
            if switch_ip:
                for n, attrs in ng.nodes(data=True):
                    ips = set(attrs.get("ips") or [])
                    if switch_ip == attrs.get("main_ip") or switch_ip == attrs.get("ip") or switch_ip in ips:
                        ep["switch_node"] = n
                        break

    # Final node cleanup
    for n, attrs in ng.nodes(data=True):
        hostname = attrs.get("hostname")
        norm = attrs.get("norm_hostname") or normalize_hostname(hostname)
        if norm:
            attrs["norm_hostname"] = norm

        ips = set(attrs.get("ips") or [])
        for value in [attrs.get("ip"), attrs.get("main_ip")]:
            if value and _is_ip_like(str(value)):
                ips.add(str(value))
        if ips:
            attrs["ips"] = sorted(ips)

    return ng


# Backwards-compatible alias
merge_graph_by_hostname = merge_by_hostname