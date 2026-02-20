from __future__ import annotations

import json
import os
from collections import deque
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx

from roland_discovery.classify import classify_device
from roland_discovery.graph.merge import merge_by_hostname
from roland_discovery.config import SnmpProfile
from roland_discovery.snmp.cdp import Neighbor, get_cdp_neighbors
from roland_discovery.snmp.client import SnmpV2cClient
from roland_discovery.snmp.system import get_sysdescr, get_sysname
from roland_discovery.snmp.ipmib import load_interface_ips, load_ip_to_ifname


def _snmp_factory(profile: Any, ip: str):
    """Return an SNMP client for `ip`."""
    snmp_fn = getattr(profile, "snmp", None)
    if callable(snmp_fn):
        return snmp_fn(ip)

    if isinstance(profile, SnmpProfile):
        return SnmpV2cClient(
            host=ip,
            community=profile.community,
            timeout=profile.timeout_s,
            retries=profile.retries,
        )

    if isinstance(profile, dict) and callable(profile.get("snmp")):
        return profile["snmp"](ip)

    raise TypeError(
        f"Unsupported SNMP profile type. Got: {type(profile)!r}"
    )


def _neighbors_to_dicts(nbs: Iterable[Neighbor]) -> List[Dict[str, Any]]:
    return [
        {
            "mgmt_ip": n.mgmt_ip,
            "remote_device": n.remote_device,
            "local_if": n.local_if,
            "remote_port": n.remote_port,
            "platform": n.platform,
            "capabilities": list(n.capabilities or []),
        }
        for n in nbs
    ]


def _save_state(path: str, g: nx.MultiGraph, q: Deque[Tuple[str, int]], visited: Set[str]) -> None:
    data = {
        "graph": nx.node_link_data(g),
        "queue": list(q),
        "visited": sorted(visited),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=_json_default)


def _json_default(o: Any):
    if is_dataclass(o):
        return asdict(o)
    if isinstance(o, Enum):
        return getattr(o, "value", None) or o.name
    return str(o)


def _load_state(path: str) -> Tuple[nx.MultiGraph, Deque[Tuple[str, int]], Set[str]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    g = nx.node_link_graph(data.get("graph", {}), directed=False, multigraph=True)
    q = deque(tuple(x) for x in data.get("queue", []))
    visited = set(data.get("visited", []))
    return g, q, visited


def _extract_vlan_id(ifname: str) -> Optional[int]:
    if not ifname:
        return None
    s = ifname.strip().lower()
    if s.startswith("vlan"):
        try:
            return int(s.replace("vlan", ""))
        except Exception:
            return None
    return None


def _orphan_svis(ip_to_ifname: Dict[str, str], uplink_trunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    allowed: Set[int] = set()
    for t in uplink_trunks:
        for vid in t.get("allowed_vlans", []) or []:
            try:
                allowed.add(int(vid))
            except Exception:
                continue

    flags: List[Dict[str, Any]] = []
    if not allowed:
        return flags

    for ip, ifn in ip_to_ifname.items():
        vid = _extract_vlan_id(ifn)
        if vid is None:
            continue
        if vid not in allowed:
            flags.append({"ip": ip, "ifname": ifn, "vlan": vid})
    return flags


def build_topology(
    seed: str,
    profile,
    max_depth: int = 1,
    max_nodes: int = 250,
    include_subnets: Optional[List[str]] = None,
    exclude_subnets: Optional[List[str]] = None,
    endpoints: bool = False,
    max_endpoints_per_device: int = 5000,
    merge_hostname: bool = True,
    ignore_hostname_prefixes: Optional[List[str]] = None,
    traverse_all: bool = False,
    traverse_roles: Optional[List[str]] = None,
    enable_l2: bool = False,
    max_edges: int = 5000,
    max_neighbors_per_node: int = 200,
    state_path: Optional[str] = None,
    resume_path: Optional[str] = None,
    state_every: int = 10,
    enable_ssh: bool = False,
    ssh_user: str = "",
    ssh_pass: str = "",
    ssh_timeout: int = 30,
    ssh_port: int = 22,
    ssh_debug: bool = False,
):
    ignore_hostname_prefixes = ignore_hostname_prefixes or ["axis"]
    traverse_roles = traverse_roles or ["switch", "router"]

    if resume_path:
        g, q, visited = _load_state(resume_path)
    else:
        g = nx.MultiGraph()
        q = deque([(seed, 0)])
        visited = set()

    ssh_profile = None
    ssh_source = "disabled"
    if enable_ssh:
        if ssh_debug:
            os.environ["ROLAND_SSH_DEBUG"] = "1"
            print("[roland] ssh debug enabled")
        from roland_discovery.ssh.client import SshProfile, load_ssh_profile_from_env, SshClient
        if ssh_user and ssh_pass:
            ssh_profile = SshProfile(
                username=ssh_user,
                password=ssh_pass,
                port=ssh_port,
                connect_timeout=ssh_timeout,
                command_timeout=ssh_timeout,
            )
            ssh_source = "cli"
        else:
            ssh_profile = load_ssh_profile_from_env()
            ssh_source = "env" if ssh_profile else "missing"
        if ssh_profile is None:
            print("[roland] WARN: --ssh enabled but no credentials found")
        else:
            print(f"[roland] ssh enabled (source: {ssh_source})")
            if ssh_debug and hasattr(ssh_profile, "log_path") and not ssh_profile.log_path:
                base_dir = os.path.dirname(state_path or "out")
                os.makedirs(base_dir, exist_ok=True)
                ssh_profile.log_path = os.path.join(base_dir, "ssh-paramiko.log")
                os.environ.setdefault("ROLAND_SSH_LOG", ssh_profile.log_path)

    edges_added = 0
    steps = 0

    while q:
        ip, depth = q.popleft()
        if ip in visited:
            continue
        if len(visited) >= max_nodes:
            print(f"[roland] max-nodes reached ({max_nodes}); stopping")
            break
        visited.add(ip)
        print(f"[roland] processing depth={depth} node={ip} visited={len(visited)} queue={len(q)}")

        if ip not in g:
            g.add_node(ip, ip=ip)

        # SNMP poll
        poll_status = "ok"
        poll_error = ""
        sysname = ""
        sysdescr = ""
        ip_to_ifname: Dict[str, str] = {}
        try:
            snmp = _snmp_factory(profile, ip)
            sysname = get_sysname(snmp) or ""
            sysdescr = get_sysdescr(snmp) or ""
            ip_to_ifname = load_ip_to_ifname(snmp)
            ips = load_interface_ips(snmp)
        except Exception as e:
            poll_status = "failed"
            poll_error = str(e)
            ips = set()
            snmp = None

        hostname = (sysname or ip).strip()
        role = classify_device(sysdescr or "", hostname)
        print(f"[DEBUG classify seed] {hostname} → sysdescr: {sysdescr[:100]} → role: {role}")
        g.nodes[ip].update(
            {
                "hostname": hostname,
                "sysdescr": sysdescr,
                "device_role": role,
                "poll_status": poll_status,
                "snmp_error": poll_error,
                "ips": sorted(ips),
                "ip_to_ifname": ip_to_ifname,
            }
        )
        if depth > 0:   
            print(f"[roland] Skipping SSH on depth={depth} node={ip} (known timeout issue)")
            g.nodes[ip].setdefault("ssh_status", "skipped-depth")
            continue  # skip SSH block
        # SSH enrichment
        if enable_ssh and ssh_profile is not None:
            from roland_discovery.ssh.enrich import (
                parse_show_ip_interface_brief,
                parse_show_arp,
                parse_cdp_neighbors_detail,
                collect_switching_catalog,
            )
            try:
                print(f"[roland] ssh enrich node={ip}")
                ssh = SshClient(ip, ssh_profile, debug=ssh_debug)
                ssh.connect()
                results = ssh.run_commands([
                    "show version",
                    "show ip interface brief",
                    "show arp",
                    "show cdp neighbors detail",
                    "show vlan brief",
                    "show interfaces trunk",
                    "show interfaces switchport",
                ])
                print(f"[DEBUG] Raw results keys: {list(results.keys())}")
                print(f"[DEBUG] show ip interface brief length: {len(results.get('show ip interface brief', ''))}")

                ip_int = parse_show_ip_interface_brief(results.get("show ip interface brief", ""))
                arp = parse_show_arp(results.get("show arp", ""))
                cdp_detail_raw = results.get("show cdp neighbors detail", "")
                cdp_detail = [asdict(x) for x in parse_cdp_neighbors_detail(cdp_detail_raw)]
                switching = collect_switching_catalog(ssh=None, results=results)
                ssh.close()

                g.nodes[ip].update(
                    {
                        "ssh_status": "ok",
                        "ssh_error": "",
                        "ssh_source": ssh_source,
                        "ssh_ip_interface_brief": ip_int,
                        "ssh_arp": arp,
                        "ssh_cdp_neighbors_detail": cdp_detail,
                        "ssh_switching": switching,
                    }
                )
            except Exception as e:
                err = f"{type(e).__name__}: {e!r}" if not str(e) else str(e)
                g.nodes[ip].update(
                    {
                        "ssh_status": "failed",
                        "ssh_error": err,
                        "ssh_source": ssh_source,
                    }
                )
                print(f"[roland] WARN: ssh failed node={ip}: {err}")
        else:
            g.nodes[ip].setdefault("ssh_status", "skipped")
            g.nodes[ip].setdefault("ssh_error", "")
            g.nodes[ip].setdefault("ssh_source", ssh_source)

        # Orphan SVI detection
        try:
            switching = g.nodes[ip].get("ssh_switching") or {}
            trunks = switching.get("trunks", {}) if isinstance(switching, dict) else {}
            uplink_ports: Set[str] = {ed.get("local_if") for _, _, ed in g.edges(ip, data=True) if ed.get("local_if")}
            uplink_trunks = []
            for p in sorted(uplink_ports):
                if p in trunks:
                    d = dict(trunks[p])
                    d["port"] = p
                    uplink_trunks.append(d)
            if uplink_trunks and ip_to_ifname:
                g.nodes[ip]["orphan_svis"] = _orphan_svis(ip_to_ifname, uplink_trunks)
            else:
                g.nodes[ip]["orphan_svis"] = []
        except Exception as e:
            print(f"[roland] orphan_svis calc failed for {ip}: {e}")
            g.nodes[ip]["orphan_svis"] = []

        if poll_status != "ok" or depth >= max_depth:
            continue

        # CDP neighbors → enqueue + add edges
        try:
            nbs = get_cdp_neighbors(snmp)
            g.nodes[ip]["cdp_neighbors_raw"] = _neighbors_to_dicts(nbs)

            print(f"[DEBUG] CDP neighbors for {hostname} ({ip}): {len(nbs)} found")

            for nb in nbs:
                remote_ip = nb.mgmt_ip
                if not remote_ip:
                    print(f"[DEBUG] Skipping neighbor {nb.remote_device} - no mgmt_ip")
                    continue
                    
                # ←←←← ADD THE DEBUG PRINT HERE ←←←←
                role = classify_device("", nb.remote_device)
                print(f"[DEBUG classify] {nb.remote_device} → role: {role}  (traverse? {role in traverse_roles})")                    

                # Debug print for every considered edge
                print(f"Considering edge from {hostname} ({ip}) → "
                      f"{nb.remote_device} @ {remote_ip} "
                      f"(local_if={nb.local_if}, remote_port={nb.remote_port}, platform={nb.platform})")

                if remote_ip in visited:
                    print(f"[DEBUG] Skipping {remote_ip} - already visited")
                    continue

                # Enqueue for deeper traversal if allowed
                role_obj = classify_device("", nb.remote_device)
                if traverse_all or role_obj.role in traverse_roles:
                    q.append((remote_ip, depth + 1))
                    print(f"[DEBUG] Enqueued {remote_ip} at depth {depth + 1} (role: {role_obj.role})")
                    q.append((remote_ip, depth + 1))
                    print(f"[DEBUG] Enqueued {remote_ip} at depth {depth + 1}")

                # Add the CDP edge
                g.add_edge(
                    ip,
                    remote_ip,
                    proto="cdp",               # consistent key for print_summary
                    local_if=nb.local_if,
                    remote_if=nb.remote_port,
                    remote_device=nb.remote_device,
                    platform=nb.platform,
                )
                edges_added += 1
                print(f"[DEBUG] Added CDP edge: {ip} → {remote_ip}")

                if edges_added >= max_edges:
                    print(f"[roland] max-edges reached ({max_edges}); stopping traversal")
                    q.clear()
                    break

        except Exception as e:
            g.nodes[ip]["cdp_error"] = str(e)
            print(f"[roland] CDP failed for {ip}: {e}")

        steps += 1
        if state_path and steps % state_every == 0:
            _save_state(state_path, g, q, visited)

    # Final summary table (before return)
    print("\n--- Summary (links) ---")
    print(f"{'PROTO':<6} {'SRC IP':<16} {'SRC HOSTNAME':<30} {'LOCAL IF':<22} {'DST IP':<16} {'DST HOSTNAME':<30} {'REMOTE IF':<22}")
    print("-" * 140)

    cdp_count = 0
    for u, v, d in g.edges(data=True):
        if d.get('proto') == 'cdp':
            print(f"{'CDP':<6} {u:<16} {g.nodes[u].get('hostname',''):<30} "
                  f"{d.get('local_if',''):<22} {v:<16} {g.nodes[v].get('hostname',''):<30} "
                  f"{d.get('remote_if',''):<22}")
            cdp_count += 1

    print(f"\nTotal CDP links: {cdp_count}")

    # Optional orphan SVIs on seed
    seed_node = g.nodes.get(seed, {})
    orphans = seed_node.get("orphan_svis", [])
    if orphans:
        print("\nOrphan SVIs detected on seed device:")
        for o in orphans:
            print(f"  - IP: {o.get('ip','?')}  VLAN: {o.get('vlan','?')}  Iface: {o.get('ifname','?')}")

    if merge_hostname:
        merge_by_hostname(g)

    return g