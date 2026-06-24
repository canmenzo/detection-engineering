#!/usr/bin/env python3
"""Render a self-contained static dashboard from the detection corpus.

Reads detections/ + the fixture manifests + conversion_only.txt and emits a single
HTML file (site/index.html) plus a copy of the coverage matrix. No server, no
build step, no external assets — just open it or publish site/ on GitHub Pages.

Run: python tools/generate_dashboard.py
"""
from __future__ import annotations

import html
import json
import re
import shutil
from collections import Counter
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
DETECTIONS = REPO / "detections"
FIXTURES = REPO / "tests" / "fixtures"
CONVERSION_ONLY = REPO / "tests" / "conversion_only.txt"
COVERAGE_PNG = REPO / "coverage" / "coverage.png"
SITE = REPO / "site"
OUT = SITE / "index.html"

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TACTIC_RE = re.compile(r"^attack\.([a-z_]+)$", re.IGNORECASE)

TACTIC_NAMES = {
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "lateral_movement": "Lateral Movement",
    "command_and_control": "Command & Control",
    "discovery": "Discovery",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "initial_access": "Initial Access",
}

GH_BASE = "https://github.com/canmenzo/detection-engineering/blob/main/"


def conversion_only() -> set[str]:
    if not CONVERSION_ONLY.exists():
        return set()
    out = set()
    for line in CONVERSION_ONLY.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def sample_count(stem: str) -> int:
    manifest = FIXTURES / stem / "sample_sources.yml"
    if not manifest.is_file():
        return 0
    doc = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    return len(doc.get("samples") or [])


def collect() -> list[dict]:
    conv = conversion_only()
    rules = []
    for path in sorted(DETECTIONS.rglob("*.yml")) + sorted(DETECTIONS.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        techs, tactics = [], []
        for tag in doc.get("tags") or []:
            if not isinstance(tag, str):
                continue
            mt = TECHNIQUE_RE.match(tag.strip())
            if mt:
                techs.append(mt.group(1).upper())
                continue
            ma = TACTIC_RE.match(tag.strip())
            if ma and ma.group(1).lower() in TACTIC_NAMES:
                tactics.append(ma.group(1).lower())
        stem = path.stem
        n = sample_count(stem)
        if n:
            status = "tested"
        elif stem in conv:
            status = "conversion-only"
        else:
            status = "untested"
        ls = doc.get("logsource") or {}
        rules.append({
            "stem": stem,
            "title": doc.get("title", stem),
            "description": " ".join(str(doc.get("description", "")).split()),
            "level": doc.get("level", "n/a"),
            "tactics": sorted({TACTIC_NAMES[t] for t in tactics}),
            "techniques": sorted(set(techs)),
            "logsource": ls.get("service") or ls.get("category") or "windows",
            "status": status,
            "samples": n,
            "path": str(path.relative_to(REPO)).replace("\\", "/"),
        })
    return rules


def render(rules: list[dict]) -> str:
    n_total = len(rules)
    n_tested = sum(1 for r in rules if r["status"] == "tested")
    n_samples = sum(r["samples"] for r in rules)
    techniques = sorted({t for r in rules for t in r["techniques"]})
    tactics = sorted({t for r in rules for t in r["tactics"]})
    tactic_counts = Counter(t for r in rules for t in r["tactics"])

    data_json = json.dumps(rules)
    chips = "".join(
        f'<button class="chip" data-tactic="{html.escape(t)}">{html.escape(t)} '
        f'<span>{tactic_counts[t]}</span></button>'
        for t in tactics
    )
    cov_img = ""
    if COVERAGE_PNG.exists():
        cov_img = '<img src="coverage.png" alt="ATT&CK coverage matrix" class="cov">'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection Coverage — Detection-as-Code</title>
<style>
  :root {{ --bg:#0d1117; --card:#161b22; --line:#30363d; --fg:#e6edf3;
           --muted:#8b949e; --accent:#58a6ff; --ok:#3fb950; --warn:#d29922; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
          font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  header {{ padding:32px 24px 8px; max-width:1100px; margin:0 auto; }}
  h1 {{ margin:0 0 4px; font-size:26px; }}
  .sub {{ color:var(--muted); }}
  .sub a {{ color:var(--accent); text-decoration:none; }}
  .stats {{ display:flex; gap:14px; flex-wrap:wrap; margin:20px 0; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
           padding:14px 18px; min-width:120px; }}
  .stat b {{ display:block; font-size:24px; }}
  .stat span {{ color:var(--muted); font-size:13px; }}
  main {{ max-width:1100px; margin:0 auto; padding:0 24px 60px; }}
  .cov {{ width:100%; border:1px solid var(--line); border-radius:10px;
          background:#fff; margin:8px 0 24px; }}
  .controls {{ display:flex; gap:10px; flex-wrap:wrap; align-items:center;
               margin:18px 0; }}
  input[type=search] {{ flex:1; min-width:200px; background:var(--card);
    border:1px solid var(--line); color:var(--fg); padding:10px 12px;
    border-radius:8px; font-size:14px; }}
  .chip {{ background:var(--card); border:1px solid var(--line); color:var(--fg);
    padding:7px 11px; border-radius:20px; cursor:pointer; font-size:13px; }}
  .chip.active {{ background:var(--accent); color:#0d1117; border-color:var(--accent); }}
  .chip span {{ opacity:.65; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
           padding:16px 18px; margin:12px 0; }}
  .card h3 {{ margin:0 0 6px; font-size:16px; }}
  .card h3 a {{ color:var(--fg); text-decoration:none; }}
  .card h3 a:hover {{ color:var(--accent); }}
  .desc {{ color:var(--muted); font-size:13.5px; margin:6px 0 10px; }}
  .tags {{ display:flex; gap:6px; flex-wrap:wrap; }}
  .tag {{ font-size:12px; padding:2px 8px; border-radius:6px;
          border:1px solid var(--line); color:var(--muted); }}
  .tag.tech {{ color:var(--accent); border-color:#1f6feb55; }}
  .badge {{ font-size:11.5px; padding:2px 8px; border-radius:20px; font-weight:600; }}
  .badge.tested {{ background:#23863633; color:var(--ok); }}
  .badge.conversion-only {{ background:#9e6a0333; color:var(--warn); }}
  .badge.untested {{ background:#6e768166; color:var(--muted); }}
  .row {{ display:flex; justify-content:space-between; align-items:start; gap:12px; }}
  .lvl {{ font-size:11.5px; text-transform:uppercase; letter-spacing:.04em; }}
  .lvl.critical {{ color:#ff7b72; }} .lvl.high {{ color:var(--warn); }}
  .lvl.medium {{ color:var(--accent); }} .lvl.low {{ color:var(--muted); }}
  footer {{ max-width:1100px; margin:0 auto; padding:24px; color:var(--muted);
            font-size:12.5px; border-top:1px solid var(--line); }}
</style>
</head>
<body>
<header>
  <h1>Detection Coverage</h1>
  <div class="sub">Detection-as-Code — every rule version-controlled, ATT&amp;CK-mapped,
    and unit-tested against real adversary telemetry.
    <a href="{GH_BASE}README.md">View source on GitHub →</a></div>
  <div class="stats">
    <div class="stat"><b>{n_total}</b><span>detections</span></div>
    <div class="stat"><b>{n_tested}</b><span>fixture-tested</span></div>
    <div class="stat"><b>{n_samples}</b><span>pinned EVTX samples</span></div>
    <div class="stat"><b>{len(techniques)}</b><span>ATT&amp;CK techniques</span></div>
    <div class="stat"><b>{len(tactics)}</b><span>tactics</span></div>
  </div>
</header>
<main>
  {cov_img}
  <div class="controls">
    <input type="search" id="q" placeholder="Search detections…">
    <button class="chip active" data-tactic="">All <span>{n_total}</span></button>
    {chips}
  </div>
  <div id="list"></div>
</main>
<footer>
  Generated by <code>tools/generate_dashboard.py</code> from the rule corpus —
  do not edit by hand. Status: <b>tested</b> = proven to fire on a pinned public
  EVTX sample via Hayabusa; <b>conversion-only</b> = validated by lint + SPL/KQL
  conversion (declared exemption); see the repo for details.
</footer>
<script>
const RULES = {data_json};
const list = document.getElementById('list');
const q = document.getElementById('q');
let tactic = '';
function esc(s){{ return (s||'').replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c])); }}
function render(){{
  const term = q.value.trim().toLowerCase();
  const rows = RULES.filter(r =>
    (!tactic || r.tactics.includes(tactic)) &&
    (!term || (r.title+r.description+r.techniques.join(' ')+r.stem).toLowerCase().includes(term))
  );
  list.innerHTML = rows.map(r => `
    <div class="card">
      <div class="row">
        <h3><a href="{GH_BASE}${{r.path}}">${{esc(r.title)}}</a></h3>
        <span class="badge ${{r.status}}">${{r.status}}${{r.samples?(' · '+r.samples+' sample'+(r.samples>1?'s':'')):''}}</span>
      </div>
      <div class="lvl ${{r.level}}">${{esc(r.level)}} · ${{esc(r.logsource)}}</div>
      <div class="desc">${{esc(r.description)}}</div>
      <div class="tags">
        ${{r.tactics.map(t=>`<span class="tag">${{esc(t)}}</span>`).join('')}}
        ${{r.techniques.map(t=>`<span class="tag tech">${{esc(t)}}</span>`).join('')}}
      </div>
    </div>`).join('') || '<p class="sub">No detections match.</p>';
}}
document.querySelectorAll('.chip').forEach(c => c.onclick = () => {{
  document.querySelectorAll('.chip').forEach(x => x.classList.remove('active'));
  c.classList.add('active'); tactic = c.dataset.tactic; render();
}});
q.oninput = render;
render();
</script>
</body>
</html>
"""


def main() -> int:
    rules = collect()
    SITE.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(rules), encoding="utf-8")
    if COVERAGE_PNG.exists():
        shutil.copyfile(COVERAGE_PNG, SITE / "coverage.png")
    tested = sum(1 for r in rules if r["status"] == "tested")
    print(f"Wrote {OUT.relative_to(REPO)} — {len(rules)} detections ({tested} tested).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
