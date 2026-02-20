import argparse
import os

from roland_discovery.config import SnmpProfile
from roland_discovery.graph.build import build_topology
from roland_discovery.export.json_export import export_json
from roland_discovery.export.dot_export import export_dot
from roland_discovery.export.html_export import export_html
from roland_discovery.report.summary import print_summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--seed", required=True, help="Seed device management IP")
    p.add_argument("--community", default=os.getenv("ROLAND_SNMP_COMMUNITY"), help="SNMPv2c community")
    p.add_argument("--depth", type=int, default=1, help="Neighbor BFS depth (mgmt IP only traversal)")
    p.add_argument("--max-edges", type=int, default=5000, help="Stop discovery after this many edges are added")
    p.add_argument("--max-neighbors-per-node", type=int, default=200, help="Cap neighbors processed per device (protects from CDP floods)")
    p.add_argument("--state", default=None, help="Write discovery state JSON here (for resume)")
    p.add_argument("--resume", default=None, help="Resume discovery from a prior --state file")

    p.add_argument("--ssh", action="store_true", help="Enable SSH enrichment (best effort)")
    p.add_argument("--ssh-user", default=None, help="SSH username (or env ROLAND_SSH_USER)")
    p.add_argument("--ssh-pass", default=None, help="SSH password (or env ROLAND_SSH_PASS)")
    p.add_argument("--ssh-timeout", type=int, default=10, help="SSH timeout seconds")
    p.add_argument("--ssh-port", type=int, default=22, help="SSH TCP port")

    p.add_argument(
        "--ssh-debug",
        action="store_true",
        help="Print SSH algorithm/options attempted (helps diagnose legacy Cisco SSH negotiation)",
    )


    p.add_argument("--l2", action="store_true", help="Collect L2 MAC counts (best-effort; may require community@vlan)")
    p.add_argument("--max-nodes", type=int, default=250, help="Hard stop for traversed mgmt IP nodes")
    p.add_argument("--include-subnet", action="append", default=[], help="CIDR to allow traversal (repeatable)")
    p.add_argument("--exclude-subnet", action="append", default=[], help="CIDR to block traversal (repeatable)")
    p.add_argument("--endpoints", action="store_true", help="Discover endpoints via MAC tables (Q-BRIDGE-MIB)")
    p.add_argument("--max-endpoints-per-device", type=int, default=5000, help="Cap endpoints per device")
    p.add_argument("--summary", action="store_true", help="Print a summary table of discovered links")
    p.add_argument("--out", default="out/topology.json")
    p.add_argument("--dot", default="out/topology.dot")
    p.add_argument("--html", default=None, help="Write interactive HTML graph (pyvis), e.g. out/topology.html")
    p.add_argument("--no-merge-hostname", action="store_true", help="Do not merge nodes with the same sysName (hostname)")
    p.add_argument("--ignore-hostname-prefix", action="append", default=["axis"], help="Ignore neighbors whose remote device name starts with this prefix (repeatable). Default: axis")
    p.add_argument("--include-axis", action="store_true", help="Do not ignore Axis devices (disables the default axis ignore prefix)")
    p.add_argument("--traverse-all", action="store_true", help="Spider into all discovered neighbors (including unknown/non-network devices)")
    p.add_argument("--traverse-role", action="append", default=None, help="Allowed device_role(s) to spider into (repeatable). Default: switch, router")
    args = p.parse_args()

    if not args.community:
        raise SystemExit("SNMP community required (or set ROLAND_SNMP_COMMUNITY)")

    profile = SnmpProfile(community=args.community)
    if args.resume and not os.path.exists(args.resume):
        raise SystemExit(f"resume file not found: {args.resume}")

    # SSH credential handling
    ssh_user_cli = (args.ssh_user or "").strip()
    ssh_pass_cli = (args.ssh_pass or "").strip()
    ssh_user_env = (os.getenv("ROLAND_SSH_USER", "") or "").strip()
    ssh_pass_env = (os.getenv("ROLAND_SSH_PASS", "") or "").strip()

    ssh_user = ssh_user_cli or ssh_user_env
    ssh_pass = ssh_pass_cli or ssh_pass_env
    ssh_source = "cli" if (ssh_user_cli and ssh_pass_cli) else ("env" if (ssh_user_env and ssh_pass_env) else "missing")

    if args.ssh:
        # Fail-fast: if the user explicitly asked for SSH, require credentials.
        if not ssh_user or not ssh_pass:
            raise SystemExit(
                "--ssh was requested but no SSH credentials were found. "
                "Provide --ssh-user/--ssh-pass or set ROLAND_SSH_USER/ROLAND_SSH_PASS."
            )
        print(f"[roland] ssh enabled (credentials source: {ssh_source})")

    g = build_topology(
        args.seed,
        profile,
        max_depth=args.depth,
        max_nodes=args.max_nodes,
        include_subnets=args.include_subnet,
        exclude_subnets=args.exclude_subnet,
        endpoints=args.endpoints,
        max_endpoints_per_device=args.max_endpoints_per_device,
        merge_hostname=(not args.no_merge_hostname),
        ignore_hostname_prefixes=([] if args.include_axis else (args.ignore_hostname_prefix or [])),
        traverse_all=args.traverse_all,
        traverse_roles=args.traverse_role,
        enable_l2=args.l2,
        enable_ssh=args.ssh,
        ssh_user=ssh_user,
        ssh_pass=ssh_pass,
        ssh_timeout=args.ssh_timeout,
        ssh_port=args.ssh_port,
        ssh_debug=args.ssh_debug,
        max_edges=args.max_edges,
        max_neighbors_per_node=args.max_neighbors_per_node,
        state_path=args.state,
        resume_path=args.resume,

    )

    export_json(g, args.out)
    export_dot(g, args.dot)
    if args.html:
        export_html(g, args.html)

    if args.summary:
        print_summary(g)

    print("Discovery complete")
