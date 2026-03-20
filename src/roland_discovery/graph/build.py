from __future__ import annotations

import json
import os
import re
from collections import deque
from dataclasses import asdict, is_dataclass
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

import networkx as nx

from roland_discovery.classify import DeviceClass, classify_device
from roland_discovery.config import SnmpProfile
from roland_discovery.graph.merge import merge_by_hostname, normalize_hostname
from roland_discovery.snmp.cdp import get_cdp_neighbors
from roland_discovery.snmp.client import SnmpV2cClient
from roland_discovery.snmp.ipmib import load_interface_ips, load_ip_to_ifname
from roland_discovery.snmp.system import get_sysdescr, get_sysname
from roland_discovery.ssh.client import SshClient, SshProfile, load_ssh_profile_from_env

    
def _normalize_ifname(ifname: Optional[str]) -> str:
    if not ifname:
        return ""
    s = ifname.lower().replace(" ", "")

    # normalize common Cisco prefixes
    s = s.replace("tengigabitethernet", "te")
    s = s.replace("gigabitethernet", "gi")
    s = s.replace("fastethernet", "fa")

    return s

def _snmp_factory(profile: Any, ip: str):
    communities = [profile.community]

    # add SRT fallback
    if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192."):
        communities.append("srtanwc75n3t44")

    for comm in communities:
        try:
            client = SnmpV2cClient(host=ip, community=comm, timeout=60, retries=2)
            if client._check_snmp_health():
                return client
        except:
            continue

    raise RuntimeError(f"All SNMP communities failed for {ip}")

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


def _is_ip_like(value: Optional[str]) -> bool:
    if not value:
        return False
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value.strip()))


def _class_to_role_attrs(role: Any) -> Dict[str, str]:
    if isinstance(role, DeviceClass):
        return {
            "device_role": role.role or "unknown",
            "device_vendor": role.vendor or "unknown",
            "device_family": role.family or "unknown",
        }
    if isinstance(role, str):
        return {
            "device_role": role or "unknown",
            "device_vendor": "unknown",
            "device_family": "unknown",
        }
    return {
        "device_role": "unknown",
        "device_vendor": "unknown",
        "device_family": "unknown",
    }


def _choose_better_hostname(current: Optional[str], candidate: Optional[str], ip: str) -> Optional[str]:
    cur = (current or "").strip()
    cand = (candidate or "").strip()

    if not cand:
        return cur or None
    if cand == ip:
        return cur or None
    if not cur:
        return cand
    if cur == ip:
        return cand

    cur_norm = normalize_hostname(cur)
    cand_norm = normalize_hostname(cand)

    # Prefer non-IP, normalized, shorter/cleaner hostname
    if cur_norm and not cand_norm:
        return cur
    if cand_norm and not cur_norm:
        return cand

    if "(" in cur and "(" not in cand:
        return cand
    if "(" in cand and "(" not in cur:
        return cur

    return cand if len(cand) > len(cur) else cur


def get_or_create_node(
    g: nx.MultiGraph,
    ip: str,
    hostname: Optional[str] = None,
    platform: Optional[str] = None,
    role: Any = None,
    sysdescr: Optional[str] = None,
) -> str:
    """
    Safe node resolver.

    Rules:
    - Prefer an existing node with the same normalized hostname.
    - Otherwise prefer an existing node whose main_ip or node id exactly matches the IP.
    - Do NOT merge just because the IP appears somewhere in a broad ips list.
    - Fall back to a raw IP node.
    """
    hostname = (hostname or "").strip()
    if hostname in ("", "?", ip):
        hostname = None

    norm_hostname = normalize_hostname(hostname)
    role_attrs = _class_to_role_attrs(role)

    # 1) Exact node id
    if ip in g.nodes:
        node_id = ip
        node = g.nodes[node_id]
        if hostname:
            node["hostname"] = _choose_better_hostname(node.get("hostname"), hostname, ip) or ip
        if norm_hostname:
            node["norm_hostname"] = norm_hostname
        if platform and platform != "?":
            node["platform"] = platform
        if sysdescr:
            node["sysdescr"] = sysdescr
        for k, v in role_attrs.items():
            if v and v != "unknown":
                node[k] = v
        node.setdefault("ips", [])
        if ip not in node["ips"]:
            node["ips"].append(ip)
        if not node.get("main_ip"):
            node["main_ip"] = ip
        return node_id

    # 2) Same normalized hostname
    if norm_hostname:
        for node_id, attrs in g.nodes(data=True):
            if attrs.get("norm_hostname") == norm_hostname:
                node = g.nodes[node_id]
                node["hostname"] = _choose_better_hostname(node.get("hostname"), hostname, ip) or node.get("hostname") or ip
                if platform and platform != "?":
                    node["platform"] = platform
                if sysdescr:
                    node["sysdescr"] = sysdescr
                for k, v in role_attrs.items():
                    if v and v != "unknown":
                        node[k] = v
                node.setdefault("ips", [])
                if ip not in node["ips"]:
                    node["ips"].append(ip)
                if not node.get("main_ip"):
                    node["main_ip"] = ip
                return node_id

    # 3) Exact main_ip match only
    for node_id, attrs in g.nodes(data=True):
        if attrs.get("main_ip") == ip:
            node = g.nodes[node_id]
            if hostname:
                node["hostname"] = _choose_better_hostname(node.get("hostname"), hostname, ip) or ip
            if norm_hostname:
                node["norm_hostname"] = norm_hostname
            if platform and platform != "?":
                node["platform"] = platform
            if sysdescr:
                node["sysdescr"] = sysdescr
            for k, v in role_attrs.items():
                if v and v != "unknown":
                    node[k] = v
            node.setdefault("ips", [])
            if ip not in node["ips"]:
                node["ips"].append(ip)
            return node_id

    # 4) Create raw IP-backed node
    g.add_node(
        ip,
        ip=ip,
        main_ip=ip,
        hostname=hostname or ip,
        norm_hostname=norm_hostname or ip.lower(),
        platform=platform or "?",
        sysdescr=sysdescr or "",
        ips=[ip],
        **role_attrs,
    )
    return ip


def _merge_ip_inventory(existing: List[str], new_ips: Set[str], anchor_ip: str) -> List[str]:
    merged = set(existing or [])
    for value in new_ips or set():
        if value:
            merged.add(value)
    if anchor_ip:
        merged.add(anchor_ip)
    return sorted(merged)


def _pick_main_ip(ip: str, ips: List[str], ip_to_ifname: Dict[str, str]) -> str:
    all_ips = list(ips or [])
    if not all_ips:
        return ip

    loopbacks = [addr for addr in all_ips if "Lo" in ip_to_ifname.get(addr, "")]
    if loopbacks:
        return loopbacks[0]

    svis = []
    for addr in all_ips:
        ifname = ip_to_ifname.get(addr, "")
        if ifname.startswith("Vl"):
            try:
                vlan = int(ifname.replace("Vl", ""))
                svis.append((vlan, addr))
            except Exception:
                pass
    if svis:
        svis.sort()
        return svis[0][1]

    return ip

def _invert_ip_to_ifname(ip_to_ifname: Dict[str, str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for ip, ifname in (ip_to_ifname or {}).items():
        out.setdefault(_normalize_ifname(ifname), []).append(ip)
    return out

def _interface_ips(ifname: str, ip_to_ifname: Dict[str, str]) -> List[str]:
    inv = _invert_ip_to_ifname(ip_to_ifname)
    return inv.get(_normalize_ifname(ifname), [])

def _norm_ifname(value: Optional[str]) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", "", value.strip().lower())


def deduplicate_graph(g: nx.MultiGraph) -> nx.MultiGraph:
    """
    Only remove truly duplicate edges.
    Do NOT merge nodes here.
    """
    clean = nx.MultiGraph()
    clean.graph.update(g.graph)

    for n, attrs in g.nodes(data=True):
        clean.add_node(n, **attrs)

    seen: Set[Tuple[Tuple[str, str], Tuple[str, str], str]] = set()

    for u, v, attrs in g.edges(data=True):
        if u == v:
            continue

        proto = str(attrs.get("proto") or "").strip().lower()
        local_if = _norm_ifname(attrs.get("local_if"))
        remote_if = _norm_ifname(attrs.get("remote_if"))

        endpoints = tuple(sorted([str(u).lower(), str(v).lower()]))
        interfaces = tuple(sorted([local_if, remote_if]))

        sig = (endpoints, interfaces, proto)
        if sig in seen:
            continue
        seen.add(sig)

        clean.add_edge(u, v, **attrs)

    return clean

def enrich_edge_l3_data(g: nx.MultiGraph) -> nx.MultiGraph:
    for u, v, attrs in g.edges(data=True):
        local_if = attrs.get("local_if", "")
        remote_if = attrs.get("remote_if", "")

        local_ip_to_ifname = g.nodes[u].get("ip_to_ifname") or {}
        remote_ip_to_ifname = g.nodes[v].get("ip_to_ifname") or {}

        local_if_ips = _interface_ips(local_if, local_ip_to_ifname)
        remote_if_ips = _interface_ips(remote_if, remote_ip_to_ifname)

        link_type = attrs.get("link_type", "unknown")

        if link_type == "routed" or local_if_ips or remote_if_ips:
            attrs["link_type"] = "routed"

            l3_bits = []
            if local_if_ips:
                l3_bits.append(f"local IPs: {', '.join(sorted(local_if_ips))}")
            if remote_if_ips:
                l3_bits.append(f"remote IPs: {', '.join(sorted(remote_if_ips))}")

            vlan_info = f" (L3: {' | '.join(l3_bits)})" if l3_bits else " (routed L3)"
            attrs["vlan_info"] = vlan_info

            edge_label = f"{local_if} → {remote_if}{vlan_info}"
            attrs["label"] = f"{edge_label} ({attrs.get('remote_device', '?')})"

            edge_title_lines = [
                edge_label,
                f"Remote: {attrs.get('remote_device', '?')}",
                f"Platform: {attrs.get('platform', '?')}",
                f"Type: routed",
            ]
            if local_if_ips:
                edge_title_lines.append(f"Local interface IPs: {', '.join(sorted(local_if_ips))}")
            if remote_if_ips:
                edge_title_lines.append(f"Remote interface IPs: {', '.join(sorted(remote_if_ips))}")

            attrs["title"] = "\n".join(edge_title_lines)
            
            if link_type == "routed" or local_if_ips or remote_if_ips:
                print(f"[L3-ENRICH] {u} {local_if} -> {v} {remote_if} | local={local_if_ips} remote={remote_if_ips}")

    return g


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

    # Seed bootstrap
    seed_hostname = seed
    seed_platform = "cisco_ios"
    seed_role = "switch"

    poll_status = "ok"
    poll_error = ""
    sysname = ""
    sysdescr = ""
    ip_to_ifname: Dict[str, str] = {}
    ips: Set[str] = set()
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

    seed_class = classify_device(sysdescr or "", seed_hostname)
    seed_node_key = get_or_create_node(
        g,
        seed,
        hostname=seed_hostname,
        platform=seed_platform,
        role=seed_class if seed_class else seed_role,
        sysdescr=sysdescr,
    )

    g.nodes[seed_node_key].update(
        {
            "is_seed": True,
            "discovery_depth": 0,
            "poll_status": poll_status,
            "snmp_error": poll_error,
            "sysdescr": sysdescr,
            "hostname": seed_hostname or seed,
            "norm_hostname": normalize_hostname(seed_hostname) or seed.lower(),
            "ip": seed,
            "ips": _merge_ip_inventory(g.nodes[seed_node_key].get("ips", []), ips, seed),
            "ip_to_ifname": ip_to_ifname,
        }
    )
    g.nodes[seed_node_key]["main_ip"] = _pick_main_ip(seed, g.nodes[seed_node_key]["ips"], ip_to_ifname)

    # SSH profile
    ssh_profile = None
    ssh_source = "disabled"
    if enable_ssh:
        if ssh_debug:
            os.environ["ROLAND_SSH_DEBUG"] = "1"
            print("[roland] ssh debug enabled")

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
            g.add_node(ip, ip=ip, main_ip=ip, hostname=ip, norm_hostname=ip.lower(), ips=[ip])

        # SNMP poll
        poll_status = "ok"
        poll_error = ""
        sysname = ""
        sysdescr = ""
        ip_to_ifname = {}
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
        node_class = classify_device(sysdescr or "", node_hostname)
        local_node_key = get_or_create_node(
            g,
            ip,
            hostname=node_hostname,
            platform=g.nodes[ip].get("platform") if ip in g.nodes else None,
            role=node_class,
            sysdescr=sysdescr,
        )

        # SSH enrichment
        if enable_ssh and ssh_profile is not None:
            from roland_discovery.ssh.enrich import (
                collect_switching_catalog,
                parse_cdp_neighbors_detail,
                parse_show_arp,
                parse_show_ip_interface_brief,
            )
            try:
                print(f"[roland] ssh enrich node={ip}")
                ssh = SshClient(ip, ssh_profile, debug=ssh_debug)
                ssh.connect()
                results = ssh.run_commands(
                    [
                        "show version",
                        "show ip interface brief",
                        "show arp",
                        "show cdp neighbors detail",
                        "show vlan brief",
                        "show interfaces trunk",
                        "show interfaces switchport",
                    ]
                )
                version_output = results.get("show version", "")
                if version_output:
                    hn_match = re.search(r"(?:hostname|name)\s*(?:is|:\s*)\s*(\S+)", version_output, re.IGNORECASE)
                    if hn_match:
                        ssh_hn = hn_match.group(1).strip()
                        if ssh_hn and len(ssh_hn) > len(node_hostname):
                            node_hostname = ssh_hn
                            print(f"[DEBUG] SSH overrode hostname to: {ssh_hn}")
                            local_node_key = get_or_create_node(
                                g,
                                ip,
                                hostname=node_hostname,
                                platform=g.nodes[local_node_key].get("platform"),
                                role=node_class,
                                sysdescr=sysdescr,
                            )

                ip_int = parse_show_ip_interface_brief(results.get("show ip interface brief", ""))
                arp = parse_show_arp(results.get("show arp", ""))
                cdp_detail_raw = results.get("show cdp neighbors detail", "")
                cdp_detail = [asdict(x) for x in parse_cdp_neighbors_detail(cdp_detail_raw)]
                switching = collect_switching_catalog(ssh=None, results=results)
                ssh.close()

                g.nodes[local_node_key].update(
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
                g.nodes[local_node_key].update(
                    {
                        "ssh_status": "failed",
                        "ssh_error": err,
                        "ssh_source": ssh_source,
                    }
                )
                print(f"[roland] WARN: ssh failed node={ip}: {err}")
        else:
            g.nodes[local_node_key].setdefault("ssh_status", "skipped")
            g.nodes[local_node_key].setdefault("ssh_error", "")
            g.nodes[local_node_key].setdefault("ssh_source", ssh_source)

        # Update node
        role_attrs = _class_to_role_attrs(node_class)
        g.nodes[local_node_key].update(
            {
                "hostname": node_hostname,
                "norm_hostname": normalize_hostname(node_hostname) or ip.lower(),
                "sysdescr": sysdescr,
                "poll_status": poll_status,
                "snmp_error": poll_error,
                "ip": ip,
                "ips": _merge_ip_inventory(g.nodes[local_node_key].get("ips", []), ips, ip),
                "ip_to_ifname": ip_to_ifname,
                **role_attrs,
            }
        )
        g.nodes[local_node_key]["main_ip"] = _pick_main_ip(ip, g.nodes[local_node_key]["ips"], ip_to_ifname)

        if depth == 0:
            g.nodes[local_node_key]["is_seed"] = True
            g.nodes[local_node_key]["discovery_depth"] = 0
        else:
            g.nodes[local_node_key]["discovery_depth"] = min(
                depth,
                int(g.nodes[local_node_key].get("discovery_depth", depth)),
            )

        # Orphan SVI detection
        try:
            switching = g.nodes[local_node_key].get("ssh_switching") or {}
            trunks = switching.get("trunks", {}) if isinstance(switching, dict) else {}
            uplink_ports: Set[str] = {
                ed.get("local_if")
                for _, _, ed in g.edges(local_node_key, data=True)
                if ed.get("local_if")
            }
            uplink_trunks = []
            for p in sorted(uplink_ports):
                if p in trunks:
                    d = dict(trunks[p])
                    d["port"] = p
                    uplink_trunks.append(d)

            if uplink_trunks and ip_to_ifname:
                g.nodes[local_node_key]["orphan_svis"] = _orphan_svis(ip_to_ifname, uplink_trunks)
            else:
                g.nodes[local_node_key]["orphan_svis"] = []
        except Exception as e:
            print(f"[roland] orphan_svis calc failed for {ip}: {e}")
            g.nodes[local_node_key]["orphan_svis"] = []

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
                from roland_discovery.ssh.enrich import parse_cdp_neighbors_detail

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

            g.nodes[local_node_key]["cdp_neighbors_raw"] = nbs

            if not nbs:
                print("[DEBUG] No CDP neighbors found")
            else:
                print(f"[DEBUG] CDP neighbors for {node_hostname} ({ip}): {len(nbs)} found")

                for nb in nbs:
                    remote_ip = nb.get("mgmt_ip") or nb.get("ip")
                    if not remote_ip:
                        continue

                    remote_device = (nb.get("device_id") or nb.get("remote_device") or "?").strip()
                    if remote_device.lower().startswith("axis"):
                        print(f"[DEBUG] Skipping Axis camera: {remote_device} @ {remote_ip}")
                        continue

                    remote_platform = nb.get("platform", "?")
                    remote_sysdescr = nb.get("sysdescr", "")
                    remote_class = classify_device(remote_sysdescr, remote_device)

                    remote_node_key = get_or_create_node(
                        g,
                        remote_ip,
                        hostname=remote_device,
                        platform=remote_platform,
                        role=remote_class,
                        sysdescr=remote_sysdescr,
                    )

                    local_if = nb.get("local_interface") or nb.get("local_if", "?")
                    remote_if = nb.get("remote_interface") or nb.get("remote_port") or nb.get("port", "?")
                    platform = nb.get("platform", "?")

                    vlan_info = ""
                    link_type = "unknown"
                    switching = g.nodes[local_node_key].get("ssh_switching") or {}
                    swp = switching.get("switchports") or {}
                    local_ip_to_ifname = g.nodes[local_node_key].get("ip_to_ifname") or {}
                    remote_ip_to_ifname = g.nodes[remote_node_key].get("ip_to_ifname") or {}

                    local_if_ips = _invert_ip_to_ifname(local_ip_to_ifname).get(_normalize_ifname(local_if), [])
                    remote_if_ips = _invert_ip_to_ifname(remote_ip_to_ifname).get(_normalize_ifname(remote_if), [])

                    norm_local = _normalize_ifname(local_if)
                    norm_remote = _normalize_ifname(remote_if)

                    swp_norm = {
                        _normalize_ifname(k): v
                        for k, v in swp.items()
                    }

                    # 1) Explicit L3 evidence wins first
                    if norm_local == "mgmt0" or norm_remote == "mgmt0" or local_if_ips or remote_if_ips:
                        link_type = "routed"

                    # 2) Explicit switchport evidence next
                    elif norm_local in swp_norm:
                        port_data = swp_norm[norm_local]
                        if isinstance(port_data, dict):
                            mode = str(port_data.get("mode", "")).lower()
                            if "trunk" in mode:
                                link_type = "trunk"
                                allowed = port_data.get("trunk_allowed_vlans") or port_data.get("allowed_vlans", "")
                                vlan_info = f" (trunk, allowed: {allowed or 'all'})"
                            elif "access" in mode or port_data.get("access_vlan"):
                                link_type = "access"
                                vlan = port_data.get("access_vlan", "")
                                vlan_info = f" (access VLAN {vlan})" if vlan else " (access)"

                    # 3) Final fallback stays unknown; do not force trunk

                    if link_type == "routed":
                        l3_bits = []
                        if local_if_ips:
                            l3_bits.append(f"local IPs: {', '.join(sorted(local_if_ips))}")
                        if remote_if_ips:
                            l3_bits.append(f"remote IPs: {', '.join(sorted(remote_if_ips))}")
                        vlan_info = f" (L3: {' | '.join(l3_bits)})" if l3_bits else " (routed L3)"

                    edge_label = f"{local_if} → {remote_if}"
                    if vlan_info:
                        edge_label += vlan_info

                    edge_title_lines = [
                        edge_label,
                        f"Remote: {remote_device}",
                        f"Platform: {platform}",
                        f"Type: {link_type}",
                    ]
                    if local_if_ips:
                        edge_title_lines.append(f"Local interface IPs: {', '.join(sorted(local_if_ips))}")
                    if remote_if_ips:
                        edge_title_lines.append(f"Remote interface IPs: {', '.join(sorted(remote_if_ips))}")

                    edge_title = "\n".join(edge_title_lines)

                    g.add_edge(
                        local_node_key,
                        remote_node_key,
                        proto="cdp",
                        local_if=local_if,
                        remote_if=remote_if,
                        remote_device=remote_device,
                        platform=platform,
                        label=f"{edge_label} ({remote_device})",
                        title=edge_title,
                        link_type=link_type,
                    )

                    print(f"[EDGE] {local_if} → {remote_if} | type={link_type} | vlan_info='{vlan_info}'")
                    edges_added += 1

                    remote_role = remote_class.role if isinstance(remote_class, DeviceClass) else "unknown"
                    if remote_ip not in visited:
                        if traverse_all or "HUB_" in remote_device.upper():
                            q.append((remote_ip, depth + 1))
                            print(f"[DEBUG] Enqueued {remote_ip} at depth {depth + 1} from {ip}")
                        elif depth < max_depth - 1 and remote_role in traverse_roles:
                            q.append((remote_ip, depth + 1))
                            print(f"[DEBUG] Enqueued {remote_ip} at depth {depth + 1} from {ip} (role match)")

                    if edges_added >= max_edges:
                        print("[roland] max-edges reached; stopping")
                        q.clear()
                        break

        except Exception as e:
            g.nodes[local_node_key]["cdp_error"] = str(e)
            print(f"[roland] CDP block failed for {ip}: {type(e).__name__}: {e}")

        steps += 1
        if state_path and steps % state_every == 0:
            _save_state(state_path, g, q, visited)

    print("[INFO] Running final edge deduplication...")
    g = deduplicate_graph(g)

    if merge_hostname:
        print("[INFO] Running final hostname merge...")
        g = merge_by_hostname(g)

    print("[INFO] Enriching final L3 edge data...")
    g = enrich_edge_l3_data(g)

    print(f"[DEBUG] Final graph: {len(g.nodes)} nodes, {len(g.edges)} edges")

    seed_node = g.nodes.get(seed, {})
    if not seed_node:
        # seed may have been merged into a hostname-backed node
        for n, attrs in g.nodes(data=True):
            if attrs.get("main_ip") == seed or seed in (attrs.get("ips") or []):
                seed_node = attrs
                break

    orphans = seed_node.get("orphan_svis", [])
    if orphans:
        print("\nOrphan SVIs detected on seed device:")
        for o in orphans:
            print(f" - IP: {o.get('ip','?')} VLAN: {o.get('vlan','?')} Iface: {o.get('ifname','?')}")

    return g