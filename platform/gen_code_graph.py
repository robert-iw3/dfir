#!/usr/bin/env python3
"""
gen_code_graph.py - generate the platform's dependency/link graph.

Scans platform/ and emits, from source (so it never drifts):
  * code_graph.json  - machine-readable nodes + edges
  * CODE_GRAPH.md    - human guide: tiers and services, namespace/depends_on wiring,
                       which script runs which, the API surface, which UI page calls
                       which endpoint, and which UAT proves which service.

The load-bearing view here is the SERVICE topology: which container shares whose network
namespace (that is what the mesh's enforcement hangs on), what depends on what, and which
deployment script or repair drives which container. The fastest way to answer "what breaks
if I change this".

Usage:  gen_code_graph.py            # (re)write code_graph.json + CODE_GRAPH.md
        gen_code_graph.py --check    # exit 1 if either is stale (drift guard)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GRAPH_JSON = ROOT / "code_graph.json"
GRAPH_MD = ROOT / "CODE_GRAPH.md"
# The graph is written where the docs live and read from where the code lives — the two
# separated when the private track became the root. Paths in the output stay relative to SCAN.
SCAN = ROOT / "platform" if (ROOT / "platform").is_dir() else ROOT

TIERS = ("enclave", "dmz", "workstation", "agent")
_SKIP_DIRS = {"node_modules", "__pycache__", ".git", "archive", "img", "results",
              "secrets", "certs", "state", "private", "dist", "build"}

# Containers named in scripts resolve to compose services: ir-<tier>_<service>_1.
_CONTAINER = re.compile(r"\bir-(enclave|dmz|workstation|agent)_([a-z0-9-]+)_1\b")
# In-repo script invocations: `bash <path>.sh`, `sh <path>.sh`, `. <path>.sh`.
_SCRIPT_CALL = re.compile(r"(?:bash|sh|\.)\s+[\"']?[^\s\"';|&]*?([a-z0-9_./-]+\.sh)\b")
_URLS = re.compile(r'path\(\s*"([^"]*)"\s*,\s*views\.([A-Za-z0-9_]+)\.as_view')
_API_METHOD = re.compile(r"^\s*([A-Za-z0-9_]+):.*?[\"'`]/([^\"'`)]*)", re.M)
_API_CALL = re.compile(r"\bapi\.([A-Za-z0-9_]+)\s*\(")


def _walk(subdir: str, exts: tuple):
    base = SCAN / subdir
    if not base.exists():
        return
    for p in sorted(base.rglob("*")):
        if p.suffix not in exts or not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(SCAN).parts):
            continue
        yield p


def compose_topology():
    """Services per tier from the compose files: image, networks, netns sharing,
    depends_on. Parsed with a line scanner rather than a YAML library so the generator
    runs anywhere python3 does."""
    tiers = {}
    for tier in TIERS:
        files = [SCAN / "deploy" / tier / "docker-compose.yml"]
        mh = SCAN / "deploy" / tier / "docker-compose.multihost.yml"
        if mh.exists():
            files.append(mh)
        services = {}
        for f in files:
            if not f.exists():
                continue
            cur = None
            in_services = False
            in_networks_list = False
            for raw in f.read_text().splitlines():
                line = raw.rstrip()
                if re.match(r"^services:\s*$", line):
                    in_services = True
                    continue
                if re.match(r"^[a-z]", line):  # a new top-level key ends services:
                    in_services = False
                if not in_services:
                    continue
                m = re.match(r"^  ([a-z0-9-]+):\s*$", line)
                if m:
                    cur = m.group(1)
                    services.setdefault(cur, {"image": None, "networks": [],
                                              "shares_netns_of": None, "depends_on": []})
                    in_networks_list = False
                    continue
                if cur is None:
                    continue
                stripped = line.strip()
                m = re.match(r"^image:\s*(\S+)", stripped)
                if m and not services[cur]["image"]:
                    services[cur]["image"] = m.group(1)
                m = re.match(r'^network_mode:\s*"?service:([a-z0-9-]+)"?', stripped)
                if m:
                    services[cur]["shares_netns_of"] = m.group(1)
                m = re.match(r"^depends_on:\s*\[([^\]]*)\]", stripped)
                if m:
                    services[cur]["depends_on"] = [d.strip() for d in m.group(1).split(",") if d.strip()]
                if re.match(r"^networks:\s*$", stripped):
                    in_networks_list = True
                    continue
                if in_networks_list:
                    m = re.match(r"^-?\s*([a-z0-9-]+):?\s*$", stripped)
                    if m and re.match(r"^\s{6,}", raw):
                        if m.group(1) not in services[cur]["networks"]:
                            services[cur]["networks"].append(m.group(1))
                        continue
                    if not raw.startswith(" " * 6):
                        in_networks_list = False
                m = re.match(r"^networks:\s*\[([^\]]*)\]", stripped)
                if m:
                    services[cur]["networks"] = [n.strip() for n in m.group(1).split(",") if n.strip()]
        if services:
            tiers[tier] = services
    return tiers


def script_graph():
    """Which shell script runs which, and which containers each drives."""
    scripts = {}
    all_sh = {p.name: p.relative_to(SCAN).as_posix()
              for sub in ("deploy", "hashicorp", "troubleshooting", "test", "dmz",
                          "collector", "re-workstation", "workstation", "ci")
              for p in _walk(sub, (".sh",))}
    for sub in ("deploy", "hashicorp", "troubleshooting", "test", "ci"):
        for p in _walk(sub, (".sh",)):
            rel = p.relative_to(SCAN).as_posix()
            text = p.read_text(errors="replace")
            runs = sorted({all_sh[Path(m.group(1)).name]
                           for m in _SCRIPT_CALL.finditer(text)
                           if Path(m.group(1)).name in all_sh
                           and all_sh[Path(m.group(1)).name] != rel})
            drives = sorted({f"{m.group(1)}/{m.group(2)}" for m in _CONTAINER.finditer(text)})
            if runs or drives:
                scripts[rel] = {"runs": runs, "drives": drives}
    return scripts


def api_surface():
    """Route -> view class, from backend/cases/urls.py."""
    f = SCAN / "backend" / "cases" / "urls.py"
    if not f.exists():
        return {}
    return {m.group(1): m.group(2) for m in _URLS.finditer(f.read_text())}


def frontend_pages():
    """UI page -> api.js methods it calls -> the paths those methods hit."""
    api_js = SCAN / "frontend" / "src" / "api.js"
    method_paths = {}
    if api_js.exists():
        for m in _API_METHOD.finditer(api_js.read_text()):
            method_paths.setdefault(m.group(1), "/" + m.group(2).split("?")[0].split("${")[0])
    pages = {}
    for p in _walk("frontend/src/pages", (".jsx",)):
        methods = sorted({m.group(1) for m in _API_CALL.finditer(p.read_text())})
        if methods:
            pages[p.stem] = {m: method_paths.get(m, "?") for m in methods}
    return pages


def uat_coverage():
    """Which UAT touches which service — the proof map."""
    cover = {}
    for p in sorted((SCAN / "test").glob("uat_*.sh")):
        touched = sorted({f"{m.group(1)}/{m.group(2)}"
                          for m in _CONTAINER.finditer(p.read_text(errors="replace"))})
        cover[p.name] = touched
    return cover


def build():
    tiers = compose_topology()
    scripts = script_graph()
    api = api_surface()
    pages = frontend_pages()
    uats = uat_coverage()

    edges = []
    for tier, services in tiers.items():
        for name, svc in services.items():
            if svc["shares_netns_of"]:
                edges.append({"from": f"{tier}/{name}", "to": f"{tier}/{svc['shares_netns_of']}",
                              "kind": "shares_netns"})
            for dep in svc["depends_on"]:
                edges.append({"from": f"{tier}/{name}", "to": f"{tier}/{dep}",
                              "kind": "depends_on"})
    for script, info in scripts.items():
        for target in info["runs"]:
            edges.append({"from": script, "to": target, "kind": "runs"})
        for svc in info["drives"]:
            edges.append({"from": script, "to": svc, "kind": "drives"})
    for uat, touched in uats.items():
        for svc in touched:
            edges.append({"from": f"test/{uat}", "to": svc, "kind": "proves"})

    return {
        "tiers": tiers,
        "scripts": scripts,
        "api": api,
        "frontend_pages": pages,
        "uat_coverage": uats,
        "edges": edges,
    }


def render_md(g) -> str:
    out = []
    a = out.append
    a("# Code graph — components, wiring, and what proves what")
    a("")
    a("Generated by [`gen_code_graph.py`](gen_code_graph.py) from source — regenerate after")
    a("adding a service, a script, an endpoint or a UAT; `--check` fails when this file is")
    a("stale. Machine-readable form: [`code_graph.json`](code_graph.json).")
    a("")
    a("Every path below is relative to [`platform/`](platform/).")
    a("")
    a("## Services by tier")
    a("")
    a("`netns` names the service whose network namespace a container joins — the sidecar")
    a("wiring the mesh's enforcement hangs on. A service whose sidecar is not in its")
    a("namespace is unproxied, however healthy it looks.")
    for tier, services in g["tiers"].items():
        a("")
        a(f"### {tier} (`deploy/{tier}/docker-compose.yml`)")
        a("")
        a("| Service | Image | Networks | netns | depends_on |")
        a("|---|---|---|---|---|")
        for name, svc in services.items():
            a("| `{}` | {} | {} | {} | {} |".format(
                name,
                f"`{svc['image']}`" if svc["image"] else "build",
                ", ".join(svc["networks"]) or "—",
                f"`service:{svc['shares_netns_of']}`" if svc["shares_netns_of"] else "own",
                ", ".join(svc["depends_on"]) or "—"))
    a("")
    a("## Script graph — who runs what, who drives which container")
    a("")
    a("| Script | Runs | Drives |")
    a("|---|---|---|")
    for script, info in g["scripts"].items():
        a("| `{}` | {} | {} |".format(
            script,
            "<br>".join(f"`{r}`" for r in info["runs"]) or "—",
            "<br>".join(f"`{d}`" for d in info["drives"]) or "—"))
    a("")
    a("## API surface (`backend/cases/urls.py`)")
    a("")
    a("| Route | View |")
    a("|---|---|")
    for route, view in g["api"].items():
        a(f"| `/api/{route}` | `{view}` |")
    a("")
    a("## UI pages and the endpoints they call")
    a("")
    a("| Page | api.js methods (path) |")
    a("|---|---|")
    for page, methods in g["frontend_pages"].items():
        calls = "<br>".join(f"`{m}` → `/api{p}`" if p != "?" else f"`{m}`"
                            for m, p in methods.items())
        a(f"| `{page}` | {calls} |")
    a("")
    a("## UAT coverage — which test proves which service")
    a("")
    a("| UAT | Services exercised |")
    a("|---|---|")
    for uat, touched in g["uat_coverage"].items():
        a("| `{}` | {} |".format(uat, ", ".join(f"`{t}`" for t in touched) or "—"))
    a("")
    return "\n".join(out)


def main() -> int:
    g = build()
    js = json.dumps(g, indent=1, sort_keys=True) + "\n"
    md = render_md(g)
    if "--check" in sys.argv:
        stale = []
        if not GRAPH_JSON.exists() or GRAPH_JSON.read_text() != js:
            stale.append(GRAPH_JSON.name)
        if not GRAPH_MD.exists() or GRAPH_MD.read_text() != md:
            stale.append(GRAPH_MD.name)
        if stale:
            print(f"stale: {', '.join(stale)} — run gen_code_graph.py", file=sys.stderr)
            return 1
        print("code graph is current")
        return 0
    GRAPH_JSON.write_text(js)
    GRAPH_MD.write_text(md)
    e = g["edges"]
    print(f"wrote {GRAPH_JSON.name} + {GRAPH_MD.name}: "
          f"{sum(len(s) for s in g['tiers'].values())} services, "
          f"{len(g['scripts'])} scripts, {len(g['api'])} routes, {len(e)} edges")
    return 0


if __name__ == "__main__":
    sys.exit(main())
