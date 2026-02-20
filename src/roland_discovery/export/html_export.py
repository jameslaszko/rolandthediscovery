from __future__ import annotations

import os
import re
from pyvis.network import Network


def _inject_search_ui(path: str) -> None:
    """Inject a simple search box and tooltip styling into the generated PyVis HTML."""
    try:
        html = open(path, "r", encoding="utf-8").read()
    except Exception:
        return

    # Add tooltip CSS for \n line breaks
    css = "<style>\n.vis-tooltip{white-space:pre-line;}\n#rolandSearch{position:fixed;top:12px;left:12px;z-index:9999;padding:8px 10px;border-radius:10px;border:1px solid #ccc;background:#fff;font-family:system-ui,Segoe UI,Arial,sans-serif;box-shadow:0 2px 10px rgba(0,0,0,0.12);}\n#rolandSearch input{width:320px;padding:6px 8px;border-radius:8px;border:1px solid #bbb;}\n#rolandSearch .hint{font-size:12px;color:#555;margin-top:6px;}\n</style>"
    ui = "<div id=\"rolandSearch\"><div><input id=\"rolandSearchBox\" type=\"text\" placeholder=\"Search hostname / IP ...\"></div><div class=\"hint\">Enter to zoom • Esc to clear</div><div id=\"rolandFilters\" style=\"margin-top:8px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;\"><label style=\"font-size:12px;\"><input id=\"rolandHideLeaf\" type=\"checkbox\"> hide leaf</label><label style=\"font-size:12px;\"><input id=\"rolandHideUnpolled\" type=\"checkbox\"> hide unpolled</label><label style=\"font-size:12px;\"><input id=\"rolandHideFailed\" type=\"checkbox\"> hide failed</label><label style=\"font-size:12px;\"><input id=\"rolandOnlyInfra\" type=\"checkbox\"> only infra</label><label style=\"font-size:12px;\"><input id=\"rolandFocus\" type=\"checkbox\"> focus selected</label></div></div>"

    # Insert UI right after <body>
    html2 = html
    if "<body>" in html2 and "rolandSearchBox" not in html2:
        html2 = html2.replace("<body>", "<body>\n" + css + "\n" + ui + "\n", 1)
    elif "<body" in html2 and "rolandSearchBox" not in html2:
        # fallback: insert after first body tag close
        html2 = re.sub(r"(<body[^>]*>)", r"\1\n" + css + "\n" + ui + "\n", html2, count=1)

    # Add JS that uses the existing `network` and `nodes` DataSet (PyVis creates these globals)
    js = """<script>
(function(){
  function byId(id){return document.getElementById(id);}
  var box = byId('rolandSearchBox');
  if(!box) return;

  function findMatch(q){
    q = (q||'').toLowerCase().trim();
    if(!q) return null;
    // `nodes` is a vis.DataSet created by pyvis
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

    // when focusing, we defer to selection handler
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
      // if focus enabled, selection handler controls visibility
      if(id === 'rolandFocus' && el.checked){
        try{ network.unselectAll(); }catch(e){}
      } else if(id === 'rolandFocus' && !el.checked){
        // unhide all first
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

  // Focus selected neighborhood
  try{
    network.on("selectNode", function(params){
      var focus = byId('rolandFocus') && byId('rolandFocus').checked;
      if(!focus) return;
      var sel = params.nodes && params.nodes[0];
      if(sel == null) return;
      // compute neighborhood
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
      // restore by filters
      var all = nodes.get();
      for(var i=0;i<all.length;i++){ nodes.update({id: all[i].id, hidden:false}); }
      applyFilters();
    });
  }catch(e){}

})();
</script>"""
    if "</body>" in html2 and "rolandSearchBox" in html2 and "network.focus" not in html2:
        html2 = html2.replace("</body>", js + "\n</body>", 1)

    if html2 != html:
        try:
            open(path, "w", encoding="utf-8").write(html2)
        except Exception:
            pass


def _node_label(attrs: dict, node_id: str) -> str:
    ip = attrs.get("ip") or ""
    hn = attrs.get("hostname") or ""
    if hn and ip:
        return f"{hn}\n{ip}"
    if hn:
        return hn
    return ip or node_id

def _node_title(attrs: dict, node_id: str) -> str:
    parts = []
    ip = attrs.get("ip")
    hn = attrs.get("hostname")
    if hn:
        parts.append(f"Hostname: {hn}")
    if ip:
        parts.append(f"IP: {ip}")
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
    ips = attrs.get("ips")
    if ips:
        parts.append("Known IPs: " + ", ".join(ips))
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
        for item in orphan[:20]:
            if isinstance(item, dict):
                parts.append(f"  {item.get('ifname')} ({item.get('ip')}) vlan={item.get('vlan')}")
        if len(orphan) > 20:
            parts.append(f"  ... ({len(orphan) - 20} more)")

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
            modes = [v.get('mode') for v in swp.values() if isinstance(v, dict)]
            parts.append(f"Switchport modes: access={modes.count('access')} trunk={modes.count('trunk')} other={len(modes) - modes.count('access') - modes.count('trunk')}")
    return "\n".join(parts) if parts else node_id

def _edge_label(attrs: dict) -> str:
    proto = attrs.get("protocol", "?")
    lif = attrs.get("local_if", "?")
    rif = attrs.get("remote_if", "?")
    return f"{proto} {lif} ↔ {rif}"

def _edge_title(attrs: dict) -> str:
    proto = attrs.get("protocol", "?")
    rn = attrs.get("remote_name", "")
    lif = attrs.get("local_if", "?")
    rif = attrs.get("remote_if", "?")
    rip = attrs.get("remote_mgmt_ip", "")
    parts = [f"Protocol: {proto}", f"Local IF: {lif}", f"Remote IF: {rif}"]
    if rn:
        parts.append(f"Remote name: {rn}")
    if rip:
        parts.append(f"Remote mgmt IP: {rip}")
    if attrs.get("confidence") is not None:
        parts.append(f"confidence={attrs.get('confidence')}")
    if attrs.get("evidence"):
        parts.append(str(attrs.get('evidence')))
    return "\n".join(parts)
def export_html(g, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    net = Network(height="900px", width="100%", directed=False, notebook=False)
    net.barnes_hut()

    for n, attrs in g.nodes(data=True):
        label = _node_label(attrs, n)
        title = _node_title(attrs, n)
        size = 18
        if attrs.get("poll_status") == "failed":
            size = 14
        if attrs.get("unknown"):
            size = 12
        # Color legend:
        #   red:    SNMP failed
        #   yellow: SNMP ok, SSH attempted but failed
        #   green:  SNMP ok (SSH ok or skipped)
        #   grey:   unpolled/placeholder
        color = None
        ps = attrs.get("poll_status")
        ss = attrs.get("ssh_status")
        orphan = attrs.get("orphan_svis") or []
        if ps == "failed":
            color = "#ff6666"
        elif ps == "unpolled":
            color = "#cccccc"
        elif ps == "ok" and ss == "failed":
            color = "#ffcc66"
        elif ps == "ok" and isinstance(orphan, list) and orphan:
            color = "#ffdd55"
        elif ps == "ok":
            color = "#66cc66"
        net.add_node(n, label=label, title=title, size=size, color=color)

    for u, v, k, attrs in g.edges(keys=True, data=True):
        net.add_edge(u, v, title=_edge_title(attrs), label=_edge_label(attrs))

    net.show_buttons(filter_=["physics"])
    net.write_html(path)
    _inject_search_ui(path)
