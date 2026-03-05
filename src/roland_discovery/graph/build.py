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


def deduplicate_graph(g: nx.MultiGraph) -> nx.MultiGraph:
    """Merge nodes by hostname and collapse duplicate edges."""
    by_hostname = {}
    for node_id, data in list(g.nodes(data=True)):
        hostname = data.get("hostname") or node_id
        if hostname not in by_hostname:
            by_hostname[hostname] = (node_id, data.copy())
        else:
            existing = by_hostname[hostname][1]
            if "ips" in data:
                ips = set(existing.get("ips", []))
                ips.update(data.get("ips", []))
                existing["ips"] = sorted(ips)
            if "ip_to_ifname" in data:
                existing.setdefault("ip_to_ifname", {}).update(data["ip_to_ifname"])

    clean_g = nx.MultiGraph()
    node_map = {}
    for hostname, (old_id, data) in by_hostname.items():
        clean_g.add_node(hostname, **data)
        node_map[old_id] = hostname

    seen_edges = set()
    for u, v, data in g.edges(data=True):
        new_u = node_map.get(u, u)
        new_v = node_map.get(v, v)
        key = tuple(sorted([new_u, new_v]))
        if key not in seen_edges:
            seen_edges.add(key)
            clean_g.add_edge(new_u, new_v, **data)

    return clean_g


def _snmp_factory(profile: Any, ip: str):
    snmp_fn = getattr(profile, "snmp", None)
    if callable(snmp_fn):
        return snmp_fn(ip)
    if isinstance(profile, SnmpProfile):
        return SnmpV2cClient(host=ip, community=profile.community, timeout=profile.timeout_s, retries=profile.retries)
    if isinstance(profile, dict) and callable(profile.get("snmp")):
        return profile["snmp"](ip)
    raise TypeError(f"Unsupported SNMP profile type. Got: {type(profile)!r}")


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
        ips = set()
        snmp = None

        try:
            snmp = _snmp_factory(profile, ip)
            sysname = get_sysname(snmp) or ""
            sysdescr = get_sysdescr(snmp) or ""
            ip_to_ifname = load_ip_to_ifname(snmp)
            ips = load_interface_ips(snmp)
        except Exception as e:
            poll_status = "failed"
            poll_error = str(e)
            print(f"[DEBUG] SNMP poll failed for {ip}: {poll_error}")

        hostname = (sysname or ip).strip()
        role = classify_device(sysdescr or "", hostname)
        print(f"[DEBUG classify seed] {hostname} → sysdescr: {sysdescr[:100]} → role: {role}")

        g.nodes[ip].update({
            "hostname": hostname,
            "sysdescr": sysdescr,
            "device_role": role,
            "poll_status": poll_status,
            "snmp_error": poll_error,
            "ips": sorted(ips),
            "ip_to_ifname": ip_to_ifname,
        })

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
                    "show version", "show ip interface brief", "show arp",
                    "show cdp neighbors detail", "show vlan brief",
                    "show interfaces trunk", "show interfaces switchport",
                ])

                # Extract hostname from show version output (fallback if SNMP failed)
                version_output = results.get("show version", "")
                if version_output:
                    # Look for common patterns: "hostname is XXX" or "Switch is running" lines
                    import re
                    hn_match = re.search(r'(?:hostname|name)\s*(?:is|:\s*)\s*(\S+)', version_output, re.IGNORECASE)
                    if not hn_match:
                        # Fallback: look for the first line with hostname-like string after "Switch"
                        hn_match = re.search(r'Switch\s+\S+\s+is\s+running.*?\s+(\S+\.srta\.com)', version_output, re.IGNORECASE)
                    if hn_match:
                        ssh_hostname = hn_match.group(1).strip()
                        # Only update if better than current (i.e. not IP)
                        current_hn = g.nodes[ip].get("hostname", "")
                        if ssh_hostname and ssh_hostname != ip and ssh_hostname != current_hn:
                            g.nodes[ip]["hostname"] = ssh_hostname
                            print(f"[DEBUG] SSH updated hostname from '{current_hn}' to '{ssh_hostname}'")

                ip_int = parse_show_ip_interface_brief(results.get("show ip interface brief", ""))
                arp = parse_show_arp(results.get("show arp", ""))
                cdp_detail_raw = results.get("show cdp neighbors detail", "")
                cdp_detail = [asdict(x) for x in parse_cdp_neighbors_detail(cdp_detail_raw)]
                switching = collect_switching_catalog(ssh=None, results=results)
                ssh.close()

                g.nodes[ip].update({
                    "ssh_status": "ok",
                    "ssh_error": "",
                    "ssh_source": ssh_source,
                    "ssh_ip_interface_brief": ip_int,
                    "ssh_arp": arp,
                    "ssh_cdp_neighbors_detail": cdp_detail,
                    "ssh_switching": switching,
                })
            except Exception as e:
                err = f"{type(e).__name__}: {e!r}" if not str(e) else str(e)
                g.nodes[ip].update({
                    "ssh_status": "failed",
                    "ssh_error": err,
                    "ssh_source": ssh_source,
                })
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

        # Allow traversal even if SNMP failed (as long as depth allows)
        if depth >= max_depth:
            print(f"[DEBUG] Max depth reached for {ip}")
            continue

        # CDP neighbors → enqueue + add edges
        try:
            print(f"[DEBUG] Starting CDP for {ip} - snmp={snmp is not None}, ssh_enabled={enable_ssh}")
            nbs = []

            if snmp is not None:
                print("[DEBUG] Trying SNMP CDP...")
                try:
                    raw_nbs = get_cdp_neighbors(snmp)
                    nbs = [asdict(nb) if is_dataclass(nb) else nb.__dict__ for nb in raw_nbs]
                    print(f"[DEBUG] SNMP CDP returned {len(nbs)} neighbors")
                except Exception as e:
                    print(f"[DEBUG] SNMP CDP failed: {e}")

            # Fallback to SSH if SNMP CDP failed or unavailable
            if not nbs and enable_ssh and ssh_profile is not None:
                print("[DEBUG] SNMP CDP unavailable or failed - falling back to SSH")
                try:
                    ssh = SshClient(ip, ssh_profile, debug=ssh_debug)
                    ssh.connect()
                    results = ssh.run_commands(["show cdp neighbors detail"])
                    cdp_raw = results.get("show cdp neighbors detail", "")
                    parsed_neighbors = parse_cdp_neighbors_detail(cdp_raw)
                    nbs = [asdict(n) if is_dataclass(n) else n.__dict__ for n in parsed_neighbors]
                    ssh.close()
                    print(f"[DEBUG] SSH CDP fallback returned {len(nbs)} neighbors")
                except Exception as e:
                    print(f"[DEBUG] SSH CDP fallback failed: {e}")

            g.nodes[ip]["cdp_neighbors_raw"] = nbs

            if not nbs:
                print("[DEBUG] No CDP neighbors found (SNMP or SSH)")
            else:
                print(f"[DEBUG] CDP neighbors for {hostname} ({ip}): {len(nbs)} found")
                for nb in nbs:
                    # Extract all needed values first (safe dict access)
                    remote_ip = nb.get("mgmt_ip") or nb.get("management_ip") or nb.get("ip") or nb.get("ip_address")
                    if not remote_ip:
                        print(f"[DEBUG] Skipping neighbor {nb.get('device_id', nb.get('remote_device', '?'))} - no remote_ip")
                        continue

                    remote_device = nb.get("device_id") or nb.get("remote_device", "?")
                    if remote_device.lower().startswith("axis"):
                        print(f"[DEBUG] Skipping Axis camera: {remote_device} @ {remote_ip}")
                        continue

                    local_if = nb.get("local_interface") or nb.get("local_if") or nb.get("localPort", "?")
                    remote_if = nb.get("remote_interface") or nb.get("remote_port") or nb.get("port", "?")
                    platform = nb.get("platform", "?")
                    role_obj = classify_device("", remote_device)

                    if remote_ip not in g:
                        g.add_node(remote_ip, **{
                            "ip": remote_ip,
                            "hostname": remote_device,
                            "platform": platform,
                            "device_role": role_obj,
                        })

                    edge_label = f"{local_if} → {remote_if}"
                    edge_title = f"{edge_label}\nRemote: {remote_device}\nPlatform: {platform}"

                    try:
                        g.add_edge(
                            ip,
                            remote_ip,
                            proto="cdp",
                            local_if=local_if,
                            remote_if=remote_if,
                            remote_device=remote_device,
                            platform=platform,
                            label=edge_label,
                            title=edge_title,
                        )
                        edges_added += 1
                        print(f"[DEBUG] Added CDP edge: {ip} → {remote_ip} ({edge_label})")
                    except Exception as e:
                        print(f"[ERROR] Failed to add edge {ip} → {remote_ip}: {e}")

                    if remote_ip not in visited and (traverse_all or role_obj.role in traverse_roles):
                        q.append((remote_ip, depth + 1))
                        print(f"[DEBUG] Enqueued {remote_ip} at depth {depth + 1}")

                    if edges_added >= max_edges:
                        print(f"[roland] max-edges reached; stopping")
                        q.clear()
                        break
                        
        except Exception as e:
            g.nodes[ip]["cdp_error"] = str(e)
            print(f"[roland] CDP block failed for {ip}: {type(e).__name__}: {e}")
            
        steps += 1
        if state_path and steps % state_every == 0:
            _save_state(state_path, g, q, visited)

    print("[INFO] Running final hostname deduplication...")
    g = deduplicate_graph(g)

    print(f"[DEBUG] Final graph: {len(g.nodes)} nodes, {len(g.edges)} edges")

    seed_node = g.nodes.get(seed, {})
    orphans = seed_node.get("orphan_svis", [])
    if orphans:
        print("\nOrphan SVIs detected on seed device:")
        for o in orphans:
            print(f" - IP: {o.get('ip','?')} VLAN: {o.get('vlan','?')} Iface: {o.get('ifname','?')}")

    if merge_hostname:
        merge_by_hostname(g)

    return g