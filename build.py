from __future__ import annotations

import json
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
    """Return an SNMP client for `ip`.

    Supported:
      - SnmpProfile dataclass (roland_discovery.config.SnmpProfile)
      - Legacy dict profile containing a callable under key "snmp"
      - Any object exposing a callable `snmp(ip)`
    """
    # Preferred: explicit factory method on profile
    snmp_fn = getattr(profile, "snmp", None)
    if callable(snmp_fn):
        return snmp_fn(ip)

    # SnmpProfile dataclass (common path in this repo)
    if isinstance(profile, SnmpProfile):
        # Note: SnmpV2cClient uses parameter name `timeout` (seconds)
        return SnmpV2cClient(
            host=ip,
            community=profile.community,
            timeout=profile.timeout_s,
            retries=profile.retries,
        )

    # Legacy dict profile: {"snmp": callable}
    if isinstance(profile, dict) and callable(profile.get("snmp")):
        return profile["snmp"](ip)

    raise TypeError(
        "Unsupported SNMP profile type. Expected SnmpProfile, dict with 'snmp' callable, or object with snmp(ip) method. "
        f"Got: {type(profile)!r}"
    )


def _neighbors_to_dicts(nbs: Iterable[Neighbor]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for n in nbs:
        out.append(
            {
                "mgmt_ip": n.mgmt_ip,
                "remote_device": n.remote_device,
                "local_if": n.local_if,
                "remote_port": n.remote_port,
                "platform": n.platform,
                "capabilities": list(n.capabilities or []),
            }
        )
    return out


def _save_state(path: str, g: nx.MultiGraph, q: Deque[Tuple[str, int]], visited: Set[str]) -> None:
    data = {
        "graph": nx.node_link_data(g),
        "queue": list(q),
        "visited": sorted(visited),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=_json_default)


def _json_default(o: Any):
    """Best-effort JSON serializer for graph/state exports.

    Discovery graphs include rich objects in attributes (e.g., DeviceClass
    dataclass) that are not JSON-serializable by default.
    """
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
    """Flag SVIs whose VLAN isn't allowed on any uplink trunk."""
    # build allowed vlan union across uplinks
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
    ssh_timeout: int = 10,
    ssh_port: int = 22,
):
    """Discover a L3 mgmt-IP topology using CDP + optional SSH enrichment.

    Notes:
    - Traversal is mgmt-IP only (remote_ip) with safeguards (max_depth/max_nodes/max_edges).
    - SSH enrichment is best-effort and does NOT affect traversal.
    """

    ignore_hostname_prefixes = ignore_hostname_prefixes or ["axis"]
    traverse_roles = traverse_roles or ["switch", "router"]

    # State init
    if resume_path:
        g, q, visited = _load_state(resume_path)
    else:
        g = nx.MultiGraph()
        q = deque([(seed, 0)])
        visited = set()

    # SSH profile
    ssh_profile = None
    ssh_source = "disabled"
    if enable_ssh:
        from roland_discovery.ssh.client import SshProfile, load_ssh_profile_from_env

        if ssh_user and ssh_pass:
            ssh_profile = SshProfile(
                username=ssh_user,
                password=ssh_pass,
                port=ssh_port,
                connect_timeout=ssh_timeout,
                banner_timeout=ssh_timeout,
                auth_timeout=ssh_timeout,
                command_timeout=ssh_timeout,
            )
            ssh_source = "cli"
        else:
            ssh_profile = load_ssh_profile_from_env()
            ssh_source = "env" if ssh_profile else "missing"

        if ssh_profile is None:
            print(
                "[roland] WARN: --ssh enabled but no credentials found "
                "(set ROLAND_SSH_USER / ROLAND_SSH_PASS or pass --ssh-user/--ssh-pass)"
            )

    # main.py already logs the credential source (env vs cli). If we log the
    # source here too, it can be misleading because build_topology only sees the
    # resolved username/password, not their origin.
    if enable_ssh and not quiet:
        print("[roland] ssh enabled")

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

        print(
            f"[roland] processing depth={depth} node={ip} "
            f"visited={len(visited)}/{max_nodes} queue={len(q)}"
        )

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
        g.nodes[ip].update(
            {
                "hostname": sysname or ip,
                "sysdescr": sysdescr,
                "device_role": role,
                "poll_status": poll_status,
                # exporter expects snmp_error
                "snmp_error": poll_error,
                "ips": sorted(ips),
                "ip_to_ifname": ip_to_ifname,
            }
        )

        # SSH enrichment
        if enable_ssh and ssh_profile is not None:
            from roland_discovery.ssh.client import SshClient
            from roland_discovery.ssh.enrich import (
                parse_show_ip_interface_brief,
                parse_show_arp,
                parse_cdp_neighbors_detail,
                collect_switching_catalog,
            )

            try:
                print(f"[roland] ssh connect node={ip}")
                ssh = SshClient(ip, ssh_profile)
                ssh.connect()

                show_ip_int_br = ssh.exec("show ip interface brief")
                ip_int = parse_show_ip_interface_brief(show_ip_int_br)

                show_arp = ssh.exec("show arp")
                arp = parse_show_arp(show_arp)

                show_cdp_detail = ssh.exec("show cdp neighbors detail")
                cdp_detail = [asdict(x) for x in parse_cdp_neighbors_detail(show_cdp_detail)]

                switching = collect_switching_catalog(ssh)

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
                # Some Paramiko exceptions stringify to an empty message.
                msg = str(e).strip()
                if not msg:
                    msg = type(e).__name__
                else:
                    msg = f"{type(e).__name__}: {msg}"
                g.nodes[ip].update(
                    {
                        "ssh_status": "failed",
                        "ssh_error": msg,
                        "ssh_source": ssh_source,
                    }
                )
                print(f"[roland] WARN: ssh failed node={ip}: {msg}")
        else:
            g.nodes[ip].setdefault("ssh_status", "skipped")
            g.nodes[ip].setdefault("ssh_error", "")
            g.nodes[ip].setdefault("ssh_source", ssh_source)

        # Build uplink trunk catalog + orphan SVI flags (requires SSH switching data)
        try:
            switching = g.nodes[ip].get("ssh_switching") or {}
            trunks = (switching.get("trunks") or {}) if isinstance(switching, dict) else {}

            # Determine "uplinks" as local_port values of edges to other discovered network devices.
            uplink_ports: Set[str] = set()
            for _, nb_ip, ed in g.edges(ip, data=True):
                if not isinstance(ed, dict):
                    continue
                lp = ed.get("local_if")
                if lp:
                    uplink_ports.add(lp)

            uplink_trunks: List[Dict[str, Any]] = []
            for p in sorted(uplink_ports):
                if p in trunks:
                    d = dict(trunks[p])
                    d["port"] = p
                    uplink_trunks.append(d)

            if uplink_trunks and ip_to_ifname:
                g.nodes[ip]["orphan_svis"] = _orphan_svis(ip_to_ifname, uplink_trunks)
            else:
                g.nodes[ip]["orphan_svis"] = []
        except Exception:
            g.nodes[ip]["orphan_svis"] = []

        # If SNMP failed, do not spider.
        if poll_status != "ok":
            continue
        if depth >= max_depth:
            continue

        # CDP neighbors
        try:
            nbs = get_cdp_neighbors(snmp)
        except Exception as e:
            g.nodes[ip]["cdp_error"] = str(e)
            continue

        if len(nbs) > max_neighbors_per_node:
            nbs = list(nbs)[:max_neighbors_per_node]

        enqueued = 0
        for nb in nbs:
            # Neighbor field names differ across versions. Prefer current SNMP CDP model:
            # Neighbor(local_if, remote_device, remote_port, mgmt_ip, ...)
            remote_name = (
                getattr(nb, "remote_device", None)
                or getattr(nb, "remote_name", None)
                or getattr(nb, "device_name", None)
                or ""
            )

            # ignore hostname prefixes (cameras etc)
            if remote_name:
                rlow = remote_name.lower()
                if any(rlow.startswith(p.lower()) for p in ignore_hostname_prefixes):
                    continue

            remote_ip = getattr(nb, "mgmt_ip", None) or getattr(nb, "remote_ip", None)
            if not remote_ip:
                continue

            if remote_ip not in g:
                g.add_node(remote_ip, ip=remote_ip, hostname=remote_name or remote_ip)

            g.add_edge(
                ip,
                remote_ip,
                protocol="cdp",
                local_if=getattr(nb, "local_if", None) or getattr(nb, "local_port", None),
                remote_if=getattr(nb, "remote_port", None) or getattr(nb, "remote_if", None),
                remote_name=remote_name,
                remote_mgmt_ip=remote_ip,
                # Neighbor models vary by version; these fields may not exist.
                platform=(
                    getattr(nb, "platform", None)
                    or getattr(nb, "remote_platform", None)
                    or ""
                ),
                capabilities=list(getattr(nb, "capabilities", []) or []),
                confidence=1.0,
                evidence=f"cdp {ip}:{getattr(nb, 'local_if', None) or getattr(nb, 'local_port', '')} -> {remote_ip}:{getattr(nb, 'remote_port', None) or getattr(nb, 'remote_if', '')}",
            )
            edges_added += 1
            if edges_added >= max_edges:
                print(f"[roland] max-edges reached ({max_edges}); stopping")
                q.clear()
                break

            # spider decision
            if remote_ip in visited:
                continue
            if traverse_all:
                q.append((remote_ip, depth + 1))
                enqueued += 1
            else:
                # Only traverse likely network devices
                # - if capabilities include Router/Switch
                caps = set(
                    (c or "").lower()
                    for c in (getattr(nb, "capabilities", []) or [])
                )
                if "router" in caps or "switch" in caps:
                    q.append((remote_ip, depth + 1))
                    enqueued += 1

        print(
            f"[roland] polled node={ip} neighbors={len(nbs)} enqueued={enqueued} queue={len(q)}"
        )

        steps += 1
        if state_path and state_every > 0 and steps % state_every == 0:
            _save_state(state_path, g, q, visited)

    # Final state save
    if state_path:
        _save_state(state_path, g, q, visited)

    # Optionally merge by hostname (keeps graph smaller)
    if merge_hostname:
        g = merge_by_hostname(g)

    return g
