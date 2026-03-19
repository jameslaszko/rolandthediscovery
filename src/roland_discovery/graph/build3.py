from __future__ import annotations
import json
import os
from collections import deque
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple
from heapq import heappush, heappop

import networkx as nx

from roland_discovery.classify import classify_device
from roland_discovery.graph.merge import merge_by_hostname
from roland_discovery.config import SnmpProfile
from roland_discovery.snmp.cdp import Neighbor, get_cdp_neighbors
from roland_discovery.snmp.client import SnmpV2cClient
from roland_discovery.snmp.system import get_sysdescr, get_sysname
from roland_discovery.snmp.ipmib import load_interface_ips, load_ip_to_ifname
from roland_discovery.ssh.client import SshClient, SshProfile, load_ssh_profile_from_env
from roland_discovery.ssh.enrich import (
    parse_show_ip_interface_brief,
    parse_show_arp,
    parse_cdp_neighbors_detail,
    collect_switching_catalog,
)
from roland_discovery.util.logging import log_raw_response


def get_or_create_node(g, ip, hostname=None, platform=None, role=None, sysdescr=None):
    """
    Get or create node with aggressive merging.
    - Merges by IP overlap first
    - Merges by normalized hostname
    - Never creates pure-IP nodes if the IP belongs to a known hostname node
    """
    hostname = (hostname or "").strip()
    if hostname in ("?", "", ip):
        hostname = None

    # Normalize hostname (strip (SSI...) suffixes, lower-case)
    norm_hostname = None
    if hostname:
        norm_hostname = hostname.split('(')[0].strip().lower()

    # 1. Merge by IP overlap
    for node_id in list(g.nodes):
        node_data = g.nodes[node_id]
        node_ips = node_data.get("ips", [])
        if ip in node_ips or ip == node_id:
            # Merge better hostname
            if norm_hostname and (not node_data.get("norm_hostname") or len(norm_hostname) > len(node_data["norm_hostname"])):
                node_data["norm_hostname"] = norm_hostname
                node_data["hostname"] = hostname or norm_hostname
            if platform and platform != "?":
                node_data["platform"] = platform
            if role:
                node_data["role"] = role
            if sysdescr:
                node_data["sysdescr"] = sysdescr
            if ip not in node_ips:
                node_data.setdefault("ips", []).append(ip)
            return node_id

    # 2. Merge by normalized hostname
    if norm_hostname:
        for node_id in list(g.nodes):
            if g.nodes[node_id].get("norm_hostname") == norm_hostname:
                node_data = g.nodes[node_id]
                if ip not in node_data.get("ips", []):
                    node_data.setdefault("ips", []).append(ip)
                if platform and platform != "?":
                    node_data["platform"] = platform
                if role:
                    node_data["role"] = role
                if sysdescr:
                    node_data["sysdescr"] = sysdescr
                return node_id

    # 3. Last resort: create pure-IP node
    print(f"[DEBUG] Creating pure-IP node for {ip} (no hostname found)")
    g.add_node(
        ip,
        hostname=ip,
        norm_hostname=ip.lower(),
        platform=platform or "?",
        role=role or "unknown",
        sysdescr=sysdescr or "",
        ips=[ip]
    )
    return ip


def deduplicate_graph(g: nx.MultiGraph) -> nx.MultiGraph:
    """Merge nodes by hostname and keep only one edge per unique physical link."""
    from difflib import SequenceMatcher

    def similar(a, b, threshold=0.82):
        return SequenceMatcher(None, (a or "").lower(), (b or "").lower()).ratio() >= threshold

    active = set(g.nodes())

    # Merge by shared IP
    ip_to_nodes = {}
    for node_id in list(active):
        ips = g.nodes[node_id].get("ips", [node_id])
        for ip in ips:
            ip_to_nodes.setdefault(ip, []).append(node_id)

    for ip, nodes_list in ip_to_nodes.items():
        nodes = [n for n in nodes_list if n in active]
        if len(nodes) <= 1:
            continue

        primary = max(nodes, key=lambda n: (len(g.nodes[n].get("ips", [])), 
                                            0 if g.nodes[n].get("hostname") != n else 1))
        primary_data = g.nodes[primary]

        for node_id in nodes:
            if node_id == primary:
                continue
            other = g.nodes[node_id]
            p_ips = set(primary_data.get("ips", []))
            p_ips.update(other.get("ips", []))
            primary_data["ips"] = sorted(p_ips)

            if len(other.get("hostname", "")) > len(primary_data.get("hostname", "")):
                primary_data["hostname"] = other["hostname"]
            for k in ["platform", "role", "sysdescr", "main_ip"]:
                if other.get(k) and other[k] not in ("?", "unknown", node_id):
                    primary_data[k] = other[k]

            g.remove_node(node_id)
            active.discard(node_id)

    # Fuzzy hostname merge
    processed = set()
    for node_id in list(active):
        if node_id not in active:
            continue
        hn = g.nodes[node_id].get("hostname") or node_id
        if hn in processed:
            continue

        group = [node_id]
        for other_id in list(active):
            if other_id == node_id or other_id not in active:
                continue
            ohn = g.nodes[other_id].get("hostname") or other_id
            if similar(hn, ohn):
                group.append(other_id)

        if len(group) > 1:
            primary = max(group, key=lambda n: len(g.nodes[n].get("ips", [])))
            primary_data = g.nodes[primary]
            for other_id in group:
                if other_id == primary:
                    continue
                other = g.nodes[other_id]
                p_ips = set(primary_data.get("ips", []))
                p_ips.update(other.get("ips", []))
                primary_data["ips"] = sorted(p_ips)
                g.remove_node(other_id)
                active.discard(other_id)
            processed.add(hn)

    # Rebuild clean graph
    clean = nx.MultiGraph()
    for n in active:
        clean.add_node(n, **g.nodes[n])
    for u, v, d in g.edges(data=True):
        if u in active and v in active:
            clean.add_edge(u, v, **d)

    return clean


def _snmp_factory(profile: Any, ip: str):
    if isinstance(profile, SnmpProfile):
        return SnmpV2cClient(host=ip, community=profile.community, timeout=60, retries=5)
    raise TypeError(f"Unsupported SNMP profile type. Got: {type(profile)!r}")


def _save_state(path: str, g: nx.MultiGraph, q: Deque[Tuple[str, int]], visited: Set[str]) -> None:
    data = {
        "graph": nx.node_link_data(g),
        "queue": list(q),
        "visited": sorted(visited),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


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

    if resume_path and os.path.exists(resume_path):
        g, q, visited = _load_state(resume_path)
        print(f"[INFO] Resumed with {len(q)} items in queue and {len(visited)} visited nodes")
    else:
        g = nx.MultiGraph()
        q = deque([(seed, 0)])
        visited = set()

    # === SEED NODE SETUP ===
    seed_hostname = seed
    seed_platform = "cisco_ios"
    seed_role = "switch"

    poll_status = "ok"
    poll_error = ""
    sysname = ""
    sysdescr = ""
    ip_to_ifname: Dict[str, str] = {}
    ips = set()
    snmp = None

    try:
        snmp = _snmp_factory(profile, seed)
        if not snmp._check_snmp_health():
            raise RuntimeError("SNMP health check failed - skipping all SNMP queries for seed")
        sysname = get_sysname(snmp) or ""
        sysdescr = get_sysdescr(snmp) or ""
        ip_to_ifname = load_ip_to_ifname(snmp)
        ips = load_interface_ips(snmp)
        if sysname:
            seed_hostname = sysname.strip()
    except Exception as e:
        poll_status = "failed"
        poll_error = str(e)
        print(f"[DEBUG] SNMP poll failed for seed {seed}: {poll_error}")
        sysname = ""
        sysdescr = ""
        ip_to_ifname = {}
        ips = set()

    seed_node_key = get_or_create_node(
        g, seed, hostname=seed_hostname, platform=seed_platform, role=seed_role
    )
    g.nodes[seed_node_key].update({
        "is_seed": True,
        "discovery_depth": 0,
        "poll_status": poll_status,
        "snmp_error": poll_error,
        "sysdescr": sysdescr,
        "ips": sorted(ips),
        "ip_to_ifname": ip_to_ifname,
    })

    # Main IP heuristic
    all_ips = g.nodes[seed_node_key].get("ips", [])
    main_ip = seed
    if all_ips:
        loopbacks = [addr for addr in all_ips if "Lo" in ip_to_ifname.get(addr, "")]
        if loopbacks:
            main_ip = loopbacks[0]
        else:
            svis = []
            for addr in all_ips:
                ifname = ip_to_ifname.get(addr, "")
                if ifname.startswith("Vl"):
                    try:
                        vlan = int(ifname.replace("Vl", ""))
                        svis.append((vlan, addr))
                    except:
                        pass
            if svis:
                svis.sort()
                main_ip = svis[0][1]
    g.nodes[seed_node_key]["main_ip"] = main_ip

    # SSH profile setup
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
            if not snmp._check_snmp_health():
                raise RuntimeError("SNMP health check failed - skipping all SNMP queries")
            sysname = get_sysname(snmp) or ""
            sysdescr = get_sysdescr(snmp) or ""
            ip_to_ifname = load_ip_to_ifname(snmp)
            ips = load_interface_ips(snmp)
        except Exception as e:
            poll_status = "failed"
            poll_error = str(e)
            print(f"[DEBUG] SNMP poll failed for {ip}: {poll_error}")

        node_hostname = (sysname or ip).strip()

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
                version_output = results.get("show version", "")
                if version_output:
                    import re
                    hn_match = re.search(r'(?:hostname|name)\s*(?:is|:\s*)\s*(\S+)', version_output, re.IGNORECASE)
                    if hn_match:
                        ssh_hn = hn_match.group(1).strip()
                        if ssh_hn and len(ssh_hn) > len(node_hostname):
                            node_hostname = ssh_hn
                            print(f"[DEBUG] SSH overrode hostname to: {ssh_hn}")

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

        # Update node
        role = classify_device(sysdescr or "", node_hostname)
        g.nodes[ip].update({
            "hostname": node_hostname,
            "sysdescr": sysdescr,
            "device_role": role,
            "poll_status": poll_status,
            "snmp_error": poll_error,
            "ips": sorted(ips),
            "ip_to_ifname": ip_to_ifname,
        })

        # Main IP heuristic
        all_ips = g.nodes[ip].get("ips", [])
        main_ip = ip
        if all_ips:
            loopbacks = [addr for addr in all_ips if "Lo" in ip_to_ifname.get(addr, "")]
            if loopbacks:
                main_ip = loopbacks[0]
            else:
                svis = []
                for addr in all_ips:
                    ifname = ip_to_ifname.get(addr, "")
                    if ifname.startswith("Vl"):
                        try:
                            vlan = int(ifname.replace("Vl", ""))
                            svis.append((vlan, addr))
                        except:
                            pass
                if svis:
                    svis.sort()
                    main_ip = svis[0][1]
        g.nodes[ip]["main_ip"] = main_ip

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

        if depth >= max_depth:
            print(f"[DEBUG] Max depth reached for {ip}")
            continue

        # CDP neighbors
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

            if not nbs and enable_ssh and ssh_profile is not None:
                print("[DEBUG] SNMP CDP unavailable - falling back to SSH")
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
                print("[DEBUG] No CDP neighbors found")
            else:
                print(f"[DEBUG] CDP neighbors for {node_hostname} ({ip}): {len(nbs)} found")
                for nb in nbs:
                    remote_ip = nb.get("mgmt_ip") or nb.get("ip")
                    if not remote_ip:
                        continue

                    remote_device_from_cdp = nb.get("device_id") or nb.get("remote_device", "?")
                    remote_platform = nb.get("platform", "?")
                    remote_sysdescr = nb.get("sysdescr", "")

                    fallback_hostname = remote_device_from_cdp.strip()

                    remote_node_key = get_or_create_node(
                        g,
                        remote_ip,
                        hostname=fallback_hostname,
                        platform=remote_platform,
                        role=classify_device(remote_sysdescr, fallback_hostname)
                    )

                    remote_device = nb.get("device_id") or nb.get("remote_device", "?")
                    if remote_device.lower().startswith("axis"):
                        print(f"[DEBUG] Skipping Axis camera: {remote_device} @ {remote_ip}")
                        continue

                    local_if = nb.get("local_interface") or nb.get("local_if", "?")
                    remote_if = nb.get("remote_interface") or nb.get("remote_port") or nb.get("port", "?")
                    platform = nb.get("platform", "?")

                    vlan_info = ""
                    link_type = "unknown"
                    switching = g.nodes[ip].get("ssh_switching") or {}
                    swp = switching.get("switchports") or {}
                    if local_if in swp:
                        port_data = swp[local_if]
                        if isinstance(port_data, dict):
                            mode = port_data.get("mode", "").lower()
                            if "trunk" in mode:
                                link_type = "trunk"
                                allowed = port_data.get("trunk_allowed_vlans") or port_data.get("allowed_vlans", "")
                                vlan_info = f" (trunk, allowed: {allowed or 'all'})"
                            elif "access" in mode or port_data.get("access_vlan"):
                                link_type = "access"
                                vlan = port_data.get("access_vlan", "")
                                vlan_info = f" (access VLAN {vlan})" if vlan else " (access)"
                    else:
                        link_type = "routed"
                        vlan_info = " (routed L3 uplink)"

                    if "HUB_" in remote_device or remote_device.endswith(".srta.com"):
                        vlan_info = " (core uplink - routed L3)" if link_type == "routed" else vlan_info
                        link_type = "trunk"

                    edge_label = f"{local_if} → {remote_if}"
                    if vlan_info:
                        edge_label += vlan_info

                    edge_title = f"{edge_label}\nRemote: {remote_device}\nPlatform: {platform}\nType: Routed L3 core uplink"

                    g.add_edge(
                        ip,
                        remote_node_key,
                        proto="cdp",
                        local_if=local_if,
                        remote_if=remote_if,
                        remote_device=remote_device,
                        platform=platform,
                        label=f"{edge_label} ({fallback_hostname})",
                        title=edge_title,
                        link_type=link_type
                    )

                    print(f"[EDGE] {local_if} → {remote_if} | type={link_type} | vlan_info='{vlan_info}'")
                    edges_added += 1

                    # === STRONGER ENQUEUING ===
                    if remote_ip not in visited:
                        if traverse_all or "HUB_" in remote_device.upper() or "HUB_" in fallback_hostname.upper():
                            q.append((remote_ip, depth + 1))
                            print(f"[DEBUG] Enqueued {remote_ip} at depth {depth + 1} from {ip}")
                        elif depth < max_depth - 1 and classify_device(remote_sysdescr, fallback_hostname).role in traverse_roles:
                            q.append((remote_ip, depth + 1))
                            print(f"[DEBUG] Enqueued {remote_ip} at depth {depth + 1} from {ip} (role match)")

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