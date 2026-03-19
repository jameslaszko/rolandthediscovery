import argparse
import os
import json
from roland_discovery.config import SnmpProfile
from roland_discovery.graph.build import build_topology
from roland_discovery.export.json_export import export_json
from roland_discovery.export.dot_export import export_dot
from roland_discovery.export.html_export import export_html
from roland_discovery.report.summary import print_summary


def main():
    p = argparse.ArgumentParser(description="Roland Network Discovery Tool")

    p.add_argument("--seed", help="Seed device management IP")
    p.add_argument("--community", default=os.getenv("ROLAND_SNMP_COMMUNITY"),
                   help="SNMPv2c community string")

    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--max-edges", type=int, default=5000)
    p.add_argument("--max-nodes", type=int, default=300)
    p.add_argument("--state", default="out/state.json")
    p.add_argument("--resume", help="Resume from state file")

    p.add_argument("--ssh", action="store_true")
    p.add_argument("--ssh-user", default=None)
    p.add_argument("--ssh-pass", default=None)
    p.add_argument("--ssh-timeout", type=int, default=15)
    p.add_argument("--ssh-port", type=int, default=22)
    p.add_argument("--ssh-debug", action="store_true")

    p.add_argument("--l2", action="store_true")
    p.add_argument("--endpoints", action="store_true")
    p.add_argument("--max-endpoints-per-device", type=int, default=5000)
    p.add_argument("--summary", action="store_true")
    p.add_argument("--out", default="out/topology.json")
    p.add_argument("--dot", default="out/topology.dot")
    p.add_argument("--html", default=None)
    p.add_argument("--no-merge-hostname", action="store_true")
    p.add_argument("--ignore-hostname-prefix", action="append", default=["axis"])
    p.add_argument("--include-axis", action="store_true")
    p.add_argument("--traverse-all", action="store_true")
    p.add_argument("--traverse-role", action="append", default=None)

    args = p.parse_args()

    resuming = bool(args.resume)

    if resuming:
        if not os.path.exists(args.resume):
            raise SystemExit(f"Resume file not found: {args.resume}")
        print(f"[INFO] Resuming from {args.resume}")

        # Load seed from state
        with open(args.resume, "r", encoding="utf-8") as f:
            state = json.load(f)
            saved_seed = state.get("seed") or state.get("graph", {}).get("nodes", [{}])[0].get("id")
            if not args.seed and saved_seed:
                args.seed = saved_seed
                print(f"[INFO] Loaded seed: {args.seed}")

        # Load community from state or env (fallback to known value)
        if not args.community:
            args.community = state.get("community") or os.getenv("ROLAND_SNMP_COMMUNITY") or "srtanwc75n3t"
            print(f"[INFO] Loaded community: {args.community}")
    else:
        if not args.seed:
            p.error("--seed is required")

    if not args.community:
        raise SystemExit("SNMP community is required.")

    profile = SnmpProfile(community=args.community)

    # SSH setup
    ssh_user = (args.ssh_user or os.getenv("ROLAND_SSH_USER", "")).strip()
    ssh_pass = (args.ssh_pass or os.getenv("ROLAND_SSH_PASS", "")).strip()

    if args.ssh and (not ssh_user or not ssh_pass):
        raise SystemExit("--ssh requested but no credentials provided.")

    # Build topology
    g = build_topology(
        seed=args.seed,
        profile=profile,
        max_depth=args.depth,
        max_nodes=args.max_nodes,
        max_edges=args.max_edges,
        state_path=args.state,
        resume_path=args.resume,
        enable_ssh=args.ssh,
        ssh_user=ssh_user,
        ssh_pass=ssh_pass,
        ssh_timeout=args.ssh_timeout,
        ssh_port=args.ssh_port,
        ssh_debug=args.ssh_debug,
        merge_hostname=not args.no_merge_hostname,
        ignore_hostname_prefixes=[] if args.include_axis else args.ignore_hostname_prefix,
        traverse_all=args.traverse_all,
        traverse_roles=args.traverse_role,
        endpoints=args.endpoints,
        max_endpoints_per_device=args.max_endpoints_per_device,
    )

    print(f"[INFO] Final graph: {len(g.nodes)} nodes, {len(g.edges)} edges")

    os.makedirs("out", exist_ok=True)
    export_json(g, args.out)
    export_dot(g, args.dot)

    if args.html:
        export_html(g, args.html)
        print(f"[INFO] HTML saved to {args.html}")

    if args.summary:
        print_summary(g)

    print("Discovery complete.")


if __name__ == "__main__":
    main()