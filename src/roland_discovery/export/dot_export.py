import os

def _label(node_id: str, attrs: dict) -> str:
    ip = attrs.get("ip") or ""
    ips = attrs.get("ips") or []
    if (not ip) and ips:
        ip = ips[0]
    hn = attrs.get("hostname") or ""
    if hn and ip:
        return f"{hn}\\n{ip}"
    if hn:
        return hn
    return ip or node_id

def export_dot(g, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("graph roland {\\n")

        for n, attrs in g.nodes(data=True):
            lbl = _label(n, attrs).replace('"', '\\\\\"')
            f.write(f'  "{n}" [label="{lbl}"];\\n')

        for u, v, k, attrs in g.edges(keys=True, data=True):
            lbl = f"{attrs.get('protocol','?')} {attrs.get('local_if','?')} <-> {attrs.get('remote_if','?')}".replace('"', '\\\\\"')
            f.write(f'  "{u}" -- "{v}" [label="{lbl}"];\\n')

        f.write("}\\n")
