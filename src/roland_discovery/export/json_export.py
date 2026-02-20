import json
from pathlib import Path
from dataclasses import asdict, is_dataclass
from enum import Enum

import networkx as nx


def export_json(g: nx.Graph, path: str) -> None:
    """Export the discovered graph to a simple JSON format.

    Supports Graph/DiGraph as well as MultiGraph/MultiDiGraph.
    """

    out = {"nodes": [], "edges": []}

    for n, attrs in g.nodes(data=True):
        out["nodes"].append({"id": n, **attrs})

    # MultiGraph/MultiDiGraph supports keys=True; plain graphs do not.
    try:
        for u, v, k, attrs in g.edges(keys=True, data=True):
            out["edges"].append({"source": u, "target": v, "key": k, **attrs})
    except TypeError:
        for u, v, attrs in g.edges(data=True):
            out["edges"].append({"source": u, "target": v, **attrs})

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, indent=2, default=_json_default), encoding="utf-8")


def _json_default(o):
    """Best-effort serializer for graph export."""
    if is_dataclass(o):
        return asdict(o)
    if isinstance(o, Enum):
        return getattr(o, "value", None) or o.name
    return str(o)
