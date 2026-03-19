from __future__ import annotations
import os
import re
from pyvis.network import Network


def _inject_search_ui(path: str) -> None:
    """Inject search box and tooltip styling into PyVis HTML."""
    try:
        html = open(path, "r", encoding="utf-8").read()
    except Exception:
        return

    css = """<style>
        .vis-tooltip { white-space: pre-line; font-family: monospace; font-size: 12px; padding: 8px; background: #fff; border: 1px solid #ccc; border-radius: 6px; }
        #rolandSearch { position: fixed; top: 12px; left: 12px; z-index: 9999; padding: 8px 10px; border-radius: 10px; border: 1px solid #ccc; background: #fff; font-family: system-ui,Segoe UI,Arial,sans-serif; box-shadow: 0 2px 10px rgba(0,0,0,0.12); }
        #rolandSearch input { width: 320px; padding: 6px 8px; border-radius: 8px; border: 1px solid #bbb; }
        #rolandSearch .hint { font-size: 12px; color: #555; margin-top: 6px; }
    </style>"""

    ui = """<div id="rolandSearch">
        <div><input id="rolandSearchBox" type="text" placeholder="Search hostname / IP ..."></div>
        <div class="hint">Enter to zoom • Esc to clear</div>
        <div id="rolandFilters" style="margin-top:8px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
            <label style="font-size:12px;"><input id="rolandHideLeaf" type="checkbox"> hide leaf</label>
            <label style="font-size:12px;"><input id="rolandHideUnpolled" type="checkbox"> hide unpolled</label>
            <label style="font-size:12px;"><input id="rolandHideFailed" type="checkbox"> hide failed</label>
            <label style="font-size:12px;"><input id="rolandOnlyInfra" type="checkbox"> only infra</label>
            <label style="font-size:12px;"><input id="rolandFocus" type="checkbox"> focus selected</label>
        </div>
    </div>"""

    js = """<script>
    (function(){
        function byId(id){return document.getElementById(id);}
        var box = byId('rolandSearchBox');
        if(!box) return;
        function findMatch(q){
            q = (q||'').toLowerCase().trim();
            if(!q) return null;
            var all = nodes.get();
            for(var i=0;i<all.length;i++){
                var n = all[i];
                var label = (n.label||'').toLowerCase();
                var title = (n.title||'').toLowerCase();
                if(label.indexOf(q) !== -1 || title.indexOf(q) !== -1){
                    return n.id;
                }
            }
            return null;
        }
        function focusNode(id){
            if(id == null) return;
            try{
                network.selectNodes([id]);
                network.focus(id, {scale: 1.6, animation: {duration: 400, easingFunction: 'easeInOutQuad'}});
            } catch(e){}
        }
        function applyFilters(){
            var hideLeaf = byId('rolandHideLeaf') && byId('rolandHideLeaf').checked;
            var hideUnpolled = byId('rolandHideUnpolled') && byId('rolandHideUnpolled').checked;
            var hideFailed = byId('rolandHideFailed') && byId('rolandHideFailed').checked;
            var onlyInfra = byId('rolandOnlyInfra') && byId('rolandOnlyInfra').checked;
            var focus = byId('rolandFocus') && byId('rolandFocus').checked;
            if(focus) return;
            var all = nodes.get();
            for(var i=0;i<all.length;i++){
                var n = all[i];
                var hidden = false;
                var deg = n.roland_degree || 0;
                var status = n.roland_status || '';
                var role = (n.roland_role || '').toLowerCase();
                if(hideLeaf && deg <= 1) hidden = true;
                if(hideUnpolled && status === 'unpolled') hidden = true;
                if(hideFailed && status === 'failed') hidden = true;
                if(onlyInfra && !(role === 'switch' || role === 'router')) hidden = true;
                nodes.update({id:n.id, hidden:hidden});
            }
        }
        function wire(id){
            var el = byId(id);
            if(!el) return;
            el.addEventListener('change', function(){
                if(id === 'rolandFocus' && el.checked){
                    try{ network.unselectAll(); }catch(e){}
                } else if(id === 'rolandFocus' && !el.checked){
                    var all = nodes.get();
                    for(var i=0;i<all.length;i++){ nodes.update({id: all[i].id, hidden:false}); }
                }
                applyFilters();
            });
        }
        wire('rolandHideLeaf');
        wire('rolandHideUnpolled');
        wire('rolandHideFailed');
        wire('rolandOnlyInfra');
        wire('rolandFocus');
        applyFilters();
        box.addEventListener('keydown', function(ev){
            if(ev.key === 'Enter'){
                var id = findMatch(box.value);
                focusNode(id);
            } else if(ev.key === 'Escape'){
                box.value = '';
                try{ network.unselectAll(); }catch(e){}
            }
        });
        try{
            network.on("selectNode", function(params){
                var focus = byId('rolandFocus') && byId('rolandFocus').checked;
                if(!focus) return;
                var sel = params.nodes && params.nodes[0];
                if(sel == null) return;
                var neigh = network.getConnectedNodes(sel);
                neigh.push(sel);
                var all = nodes.get();
                for(var i=0;i<all.length;i++){
                    var id = all[i].id;
                    var keep = neigh.indexOf(id) !== -1;
                    nodes.update({id:id, hidden: !keep});
                }
                try{ network.focus(sel, {scale: 1.8, animation: {duration: 400, easingFunction: 'easeInOutQuad'}}); }catch(e){}
            });
            network.on("deselectNode", function(){
                var focus = byId('rolandFocus') && byId('rolandFocus').checked;
                if(!focus) return;
                var all = nodes.get();
                for(var i=0;i<all.length;i++){ nodes.update({id: all[i].id, hidden:false}); }
                applyFilters();
            });
        }catch(e){}
    })();
    </script>"""

    html2 = html.replace("<body>", "<body>\n" + css + "\n" + ui + "\n", 1)
    if "</body>" in html2:
        html2 = html2.replace("</body>", js + "\n</body>", 1)
    if html2 != html:
        try:
            open(path, "w", encoding="utf-8").write(html2)
        except Exception:
            pass


def _node_label(attrs: dict, node_id: str) -> str:
    hn = attrs.get("hostname")
    main_ip = attrs.get("main_ip") or node_id
    label = hn if hn and hn != main_ip else main_ip
    ips = attrs.get("ips", [])
    if len(ips) > 1:
        label += f" ({len(ips)} IPs)"
    return label


def _node_title(attrs: dict, node_id: str) -> str:
    parts = []
    hn = attrs.get("hostname")
    main_ip = attrs.get("main_ip")
    if hn:
        parts.append(f"Hostname: {hn}")
    if main_ip:
        parts.append(f"Main/Mgmt IP: {main_ip}")  # Highlighted

    # All IPs
    ips = attrs.get("ips", [])
    if ips and len(ips) > 1:
        shown = ", ".join(ips[:10])
        extra = f" (+{len(ips)-10} more)" if len(ips) > 10 else ""
        parts.append(f"All IPs: {shown}{extra}")

    ps = attrs.get("poll_status")
    if ps:
        parts.append(f"Poll: {ps}")
    ss = attrs.get("ssh_status")
    if ss:
        parts.append(f"SSH: {ss}")
    if attrs.get("snmp_error"):
        parts.append(f"SNMP error: {attrs.get('snmp_error')}")
    if attrs.get("ssh_error"):
        parts.append(f"SSH error: {attrs.get('ssh_error')}")
    if attrs.get("sysdescr"):
        parts.append(f"sysDescr: {attrs.get('sysdescr')}")

    if attrs.get("endpoint_count") is not None:
        parts.append(f"Endpoints: {attrs.get('endpoint_count')}")

    if attrs.get("unknown"):
        parts.append("Unknown node (no mgmt IP)")

    if attrs.get("confidence") is not None:
        parts.append(f"confidence={attrs.get('confidence')}")

    if attrs.get("evidence"):
        parts.append(str(attrs.get('evidence')))

    orphan = attrs.get("orphan_svis") or []
    if isinstance(orphan, list) and orphan:
        parts.append("---")
        parts.append("WARN: SVI VLAN not seen on uplink trunks")
        for item in orphan[:10]:
            if isinstance(item, dict):
                parts.append(f" {item.get('ifname')} ({item.get('ip')}) vlan={item.get('vlan')}")
        if len(orphan) > 10:
            parts.append(f" ... ({len(orphan) - 10} more)")

    switching = attrs.get("ssh_switching") or {}
    if isinstance(switching, dict) and (switching.get("vlans") or switching.get("trunks") or switching.get("switchports")):
        parts.append("---")
        vlans = switching.get("vlans") or {}
        trunks = switching.get("trunks") or {}
        swp = switching.get("switchports") or {}
        if isinstance(vlans, dict):
            parts.append(f"VLANs configured: {len(vlans)}")
        if isinstance(trunks, dict):
            parts.append(f"Trunk ports: {len(trunks)}")
        if isinstance(swp, dict):
            modes = []
            for port_data in swp.values():
                if isinstance(port_data, dict):
                    mode = port_data.get('mode', '').lower()
                    if mode:
                        modes.append(mode)
                    elif port_data.get('access_vlan') or port_data.get('voice_vlan'):
                        modes.append('access')
                    else:
                        modes.append('unknown')
            access = modes.count('access')
            trunk = modes.count('trunk')
            other = len(modes) - access - trunk
            parts.append(f"Switchport modes: access={access} trunk={trunk} other={other}")

    return "\n".join(parts) if parts else node_id


def _edge_label(attrs: dict) -> str:
    if "label" in attrs:
        return attrs["label"]
    lif = attrs.get("local_if", "?")
    rif = attrs.get("remote_if", "?")
    return f"{lif} → {rif}"


def _edge_title(attrs: dict) -> str:
    if "title" in attrs:
        return attrs["title"]
    parts = []
    proto = attrs.get("proto", "cdp")
    parts.append(f"Protocol: {proto.upper()}")
    if attrs.get("local_if"):
        parts.append(f"Local IF: {attrs.get('local_if')}")
    if attrs.get("remote_if"):
        parts.append(f"Remote IF: {attrs.get('remote_if')}")
    if attrs.get("remote_device"):
        parts.append(f"Remote: {attrs.get('remote_device')}")
    if attrs.get("platform"):
        parts.append(f"Platform: {attrs.get('platform')}")
    return "\n".join(parts) if parts else "CDP link"


def export_html(g, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    net = Network(height="900px", width="100%", directed=False, notebook=False)
    net.barnes_hut()

    # Nodes
    for n, attrs in g.nodes(data=True):
        label = _node_label(attrs, n)
        title = _node_title(attrs, n)
        size = 18
        if attrs.get("poll_status") == "failed":
            size = 14
        if attrs.get("unknown"):
            size = 12
        color = "#ff6666" if attrs.get("poll_status") == "failed" else \
                "#ffcc66" if attrs.get("ssh_status") == "failed" else \
                "#cccccc" if attrs.get("poll_status") == "unpolled" else \
                "#66cc66"
        net.add_node(n, label=label, title=title, size=size, color=color)

    # Edges
    for u, v, data in g.edges(data=True):
        local_if = data.get('local_if', '?')
        remote_if = data.get('remote_if', '?')
        label = data.get("label") or f"{local_if} → {remote_if}"
        if "vlan_info" in data and data["vlan_info"]:
            label += data["vlan_info"]
        title = data.get("title") or f"{label}\nProtocol: cdp\nRemote device: {data.get('remote_device', '?')}\nPlatform: {data.get('platform', '?')}\nType: {data.get('link_type', 'unknown')}"
        link_type = data.get("link_type", "unknown")
        color = "#ffa500" if link_type == "access" else \
                "#4a8cff" if link_type == "routed" else \
                "#b200ff" if link_type == "trunk" else \
                "#999999"
        width = 3 if link_type == "trunk" else 2 if link_type == "routed" else 1.5
        net.add_edge(
            u, v,
            label=label,
            title=title,
            arrows="to",
            font={"size": 11, "align": "middle"},
            color={"color": color, "highlight": color}
        )

    net.show_buttons(filter_=["physics"])
    net.write_html(path)
    _inject_search_ui(path)