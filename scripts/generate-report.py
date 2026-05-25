#!/usr/bin/env python3
"""Generate an HTML report from bumblebee inventory.ndjson.

Requires Python 3.10+.

Usage:
    python3 scripts/generate-report.py                         # defaults
    python3 scripts/generate-report.py inventory.ndjson        # explicit input
    python3 scripts/generate-report.py -o report.html          # explicit output
    python3 scripts/generate-report.py scan.ndjson -o out.html # both
"""

import json
import collections
import html as html_mod
import sys
import argparse

# ── Ecosystem colours ──
ECO_COLORS = {
    "go": "#00ADD8",
    "npm": "#CB3837",
    "pypi": "#306998",
    "rubygems": "#CC342D",
    "browser-extension": "#FF9500",
    "editor-extension": "#8B5CF6",
    "mcp": "#10B981",
    "unknown": "#6B7280",
}

# ── Helpers ──

def esc(s):
    return html_mod.escape(str(s))


def bar_html(pct, color, min_pct=2.5):
    pct = max(pct, min_pct)
    return (
        f'<div class="bar-track">'
        f'<div class="bar" style="width:{pct:.1f}%;'
        f"background:linear-gradient(90deg,{color},{color}bb)\">"
        f'<span class="bar-glow" style="background:{color}"></span>'
        f"</div></div>"
    )


# ── Main generator ──

def generate_report(ndjson_path: str, output_path: str) -> None:
    # ── Load data ──
    packages: list[dict] = []
    summary: dict | None = None

    with open(ndjson_path) as f:
        for line in f:
            r = json.loads(line)
            if r["record_type"] == "package":
                packages.append(r)
            elif r["record_type"] == "scan_summary":
                summary = r

    if not summary:
        print("Error: no scan_summary record found", file=sys.stderr)
        sys.exit(1)

    if not packages:
        print("Error: no package records found", file=sys.stderr)
        sys.exit(1)

    # ── Compute aggregates ──
    ecosystems = collections.Counter()
    source_types = collections.Counter()
    projects = collections.Counter()
    confidence_levels = collections.Counter()
    direct_deps = 0
    lifecycle_script_pkgs: list[dict] = []
    unique_by_eco: dict[str, set[str]] = collections.defaultdict(set)
    multi_version: dict[tuple, dict[str, list]] = collections.defaultdict(
        lambda: collections.defaultdict(list)
    )

    for p in packages:
        eco = p.get("ecosystem", "unknown")
        ecosystems[eco] += 1
        source_types[p.get("source_type", "unknown")] += 1

        proj = p.get("project_path", "unknown")
        proj = proj.replace("/Users/", "~/").replace("/home/", "~/")
        projects[proj] += 1

        confidence_levels[p.get("confidence", "unknown")] += 1

        if p.get("direct_dependency"):
            direct_deps += 1

        if p.get("has_lifecycle_scripts"):
            lifecycle_script_pkgs.append(
                {
                    "name": p.get("package_name"),
                    "ecosystem": eco,
                    "project": proj,
                    "scripts": p.get("lifecycle_scripts", []),
                }
            )

        unique_by_eco[eco].add(p.get("normalized_name", ""))

        name = p.get("normalized_name", "")
        ver = p.get("version", "?")
        multi_version[(eco, name)][ver].append(proj)

    multi_pkgs = {k: v for k, v in multi_version.items() if len(v) > 1}
    top_multi = sorted(multi_pkgs.items(), key=lambda x: -len(x[1]))[:25]
    eco_order = [e for e, _ in ecosystems.most_common()]

    # ── Group scan roots by kind ──
    root_kinds_map: dict[str, list[str]] = collections.OrderedDict()
    for root in summary["roots"]:
        rk = root["kind"]
        path = root["path"].replace("/Users/", "~/").replace("/home/", "~/")
        root_kinds_map.setdefault(rk, []).append(path)

    # ── Build table rows ──

    # Ecosystems
    max_eco = max(ecosystems.values())
    eco_rows = ""
    for eco in eco_order:
        cnt = ecosystems[eco]
        unique = len(unique_by_eco[eco])
        pct = cnt / max_eco * 100
        color = ECO_COLORS.get(eco, "#6B7280")
        eco_rows += f"""
          <tr>
            <td><span class="eco-dot" style="--dot-color:{color}"></span><span class="eco-name">{esc(eco)}</span></td>
            <td class="num">{cnt:,}</td>
            <td class="num">{unique:,}</td>
            <td class="bar-cell">{bar_html(pct, color)}</td>
          </tr>"""

    # Source types
    src_rows = ""
    max_src = max(source_types.values())
    for src, cnt in source_types.most_common():
        pct = cnt / max_src * 100
        src_rows += f"""
          <tr>
            <td><code>{esc(src)}</code></td>
            <td class="num">{cnt:,}</td>
            <td class="bar-cell">{bar_html(pct, "#64748b")}</td>
          </tr>"""

    # Confidence
    conf_rows = ""
    max_conf = max(confidence_levels.values())
    conf_colors = {"high": "#10b981", "medium": "#f59e0b", "low": "#ef4444"}
    for lvl, cnt in confidence_levels.most_common():
        color = conf_colors.get(lvl, "#6B7280")
        pct = cnt / max_conf * 100
        conf_rows += f"""
          <tr>
            <td><span class="conf-badge" style="--badge-bg:{color}">{esc(lvl)}</span></td>
            <td class="num">{cnt:,}</td>
            <td class="num">{cnt / len(packages) * 100:.1f}%</td>
            <td class="bar-cell">{bar_html(pct, color)}</td>
          </tr>"""

    # Top projects
    proj_rows = ""
    max_proj = max(projects.values())
    for proj, cnt in projects.most_common(25):
        pct = cnt / max_proj * 100
        short = proj.split("/")[-1] if len(proj) > 60 else proj
        proj_rows += f"""
          <tr>
            <td class="proj-cell" title="{esc(proj)}">
              <span class="proj-short">{esc(short)}</span>
              <span class="proj-full">{esc(proj)}</span>
            </td>
            <td class="num">{cnt:,}</td>
            <td class="bar-cell">{bar_html(pct, "#d97706")}</td>
          </tr>"""

    # Multi-version
    multi_rows = ""
    for (eco, name), versions in top_multi:
        ver_list = sorted(versions.keys())[:3]
        ver_str = ", ".join(ver_list)
        if len(versions) > 3:
            ver_str += f" … +{len(versions) - 3} more"
        color = ECO_COLORS.get(eco, "#6B7280")
        multi_rows += f"""
          <tr>
            <td><span class="eco-dot" style="--dot-color:{color}"></span><span class="eco-name">{esc(eco)}</span></td>
            <td><code>{esc(name)}</code></td>
            <td class="num">{len(versions)}</td>
            <td class="versions">{esc(ver_str)}</td>
          </tr>"""

    # Lifecycle scripts
    lifecycle_rows = ""
    for pkg in sorted(lifecycle_script_pkgs, key=lambda x: x["name"]):
        color = ECO_COLORS.get(pkg["ecosystem"], "#6B7280")
        scripts_html = " ".join(
            f'<span class="script-tag">{esc(s)}</span>' for s in pkg["scripts"]
        )
        lifecycle_rows += f"""
          <tr>
            <td><span class="eco-dot" style="--dot-color:{color}"></span><span class="eco-name">{esc(pkg["ecosystem"])}</span></td>
            <td><code>{esc(pkg["name"])}</code></td>
            <td class="scripts-cell">{scripts_html}</td>
            <td class="proj-cell" title="{esc(pkg["project"])}"><span class="proj-short">{esc(pkg["project"].split("/")[-1])}</span><span class="proj-full">{esc(pkg["project"])}</span></td>
          </tr>"""

    # Scan roots
    root_icons = {
        "user_package_root": "📦",
        "editor_extension_root": "🧩",
        "mcp_config_root": "🔌",
        "browser_extension_root": "🌐",
        "homebrew_root": "🍺",
    }
    scan_roots_html = ""
    for rk, paths in root_kinds_map.items():
        icon = root_icons.get(rk, "📁")
        items = "".join(f"<li><code>{esc(p)}</code></li>" for p in paths)
        scan_roots_html += f"""
          <div class="root-card">
            <div class="root-card-header">
              <span class="root-icon">{icon}</span>
              <span class="root-title">{esc(rk.replace('_', ' ').title())}</span>
              <span class="root-count">{len(paths)}</span>
            </div>
            <ul>{items}</ul>
          </div>"""

    duration_s = summary["duration_ms"] / 1000

    # ── Assemble HTML ──
    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bumblebee Inventory Report — {esc(summary["endpoint"]["hostname"])}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=Karla:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
/* ══════════════════════════════════════════
   DARK TOKENS (default)
   ══════════════════════════════════════════ */
:root {{
  --bg: #08080a;
  --surface: #101014;
  --surface2: #18181e;
  --surface3: #202028;
  --border: #28283a;
  --border-hi: #38384a;
  --text: #e8e8ec;
  --text2: #8e8ea6;
  --text3: #5a5a72;
  --amber: #f0a830;
  --amber-light: #ffd666;
  --amber-dim: #8a6010;
  --red: #ef4444;
  --radius: 8px;
  --radius-lg: 14px;
  --font-display: 'Syne', sans-serif;
  --font-body: 'Karla', sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
  --hex-opacity: 0.025;
  --grain-opacity: 0.04;
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.3);
  --shadow-md: 0 4px 16px rgba(0,0,0,0.4);
  --table-hover-bg: rgba(240,168,48,0.04);
  --code-bg: var(--surface3);
  --code-color: #c4c4dc;
  --script-tag-bg: rgba(239,68,68,0.1);
  --script-tag-border: rgba(239,68,68,0.2);
  --script-tag-color: #f87171;
  --warning-bg: rgba(239,68,68,0.06);
  --warning-border: rgba(239,68,68,0.15);
  --warning-text: #f87171;
  --warning-strong: #fca5a5;
  --section-line: linear-gradient(90deg, var(--border), transparent);
}}

/* ══════════════════════════════════════════
   LIGHT TOKENS
   ══════════════════════════════════════════ */
[data-theme="light"] {{
  --bg: #f8f5ee;
  --surface: #ffffff;
  --surface2: #f0ece4;
  --surface3: #e6e0d6;
  --border: #d8d0c4;
  --border-hi: #c4baa8;
  --text: #1a1816;
  --text2: #6b6358;
  --text3: #9a9088;
  --amber: #c88820;
  --amber-light: #a06810;
  --amber-dim: #f0c060;
  --hex-opacity: 0.03;
  --grain-opacity: 0.02;
  --shadow-sm: 0 1px 3px rgba(0,0,0,0.06);
  --shadow-md: 0 4px 16px rgba(0,0,0,0.08);
  --table-hover-bg: rgba(200,136,32,0.06);
  --code-bg: var(--surface2);
  --code-color: #4a4238;
  --script-tag-bg: rgba(220,50,50,0.08);
  --script-tag-border: rgba(220,50,50,0.15);
  --script-tag-color: #c03030;
  --warning-bg: rgba(220,50,50,0.05);
  --warning-border: rgba(220,50,50,0.12);
  --warning-text: #b83030;
  --warning-strong: #901818;
  --section-line: linear-gradient(90deg, var(--border), transparent);
}}

[data-theme="light"] body::before {{
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='56' height='100'%3E%3Cpath d='M28 66L0 50L0 16L28 0L56 16L56 50L28 66L28 100' fill='none' stroke='%23c88820' stroke-width='1'/%3E%3Cpath d='M28 0L28 34L0 50L0 84L28 100L56 84L56 50L28 34' fill='none' stroke='%23c88820' stroke-width='1'/%3E%3C/svg%3E");
}}

/* ══════════════════════════════════════════
   BASE
   ══════════════════════════════════════════ */
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}

body {{
  font-family: var(--font-body);
  background: var(--bg);
  color: var(--text);
  line-height: 1.55;
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
  transition: background 0.35s ease, color 0.35s ease;
}}

/* ── Hex grid background ── */
body::before {{
  content: '';
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  opacity: var(--hex-opacity);
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='56' height='100'%3E%3Cpath d='M28 66L0 50L0 16L28 0L56 16L56 50L28 66L28 100' fill='none' stroke='%23f0a830' stroke-width='1'/%3E%3Cpath d='M28 0L28 34L0 50L0 84L28 100L56 84L56 50L28 34' fill='none' stroke='%23f0a830' stroke-width='1'/%3E%3C/svg%3E");
  background-size: 56px 100px;
}}

/* Noise grain overlay */
body::after {{
  content: '';
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  opacity: var(--grain-opacity);
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='1'/%3E%3C/svg%3E");
  background-repeat: repeat;
  background-size: 256px;
}}

.container {{
  position: relative;
  z-index: 1;
  max-width: 1140px;
  margin: 0 auto;
  padding: 0 28px 100px;
}}

/* ══════════════════════════════════════════
   SCROLL PROGRESS BAR
   ══════════════════════════════════════════ */
.scroll-progress {{
  position: fixed;
  top: 0; left: 0;
  width: 0%;
  height: 2px;
  background: var(--amber);
  z-index: 1000;
  transition: none;
  pointer-events: none;
}}

/* ══════════════════════════════════════════
   THEME TOGGLE
   ══════════════════════════════════════════ */
.theme-toggle {{
  position: fixed;
  top: 20px; right: 24px;
  z-index: 999;
  width: 40px; height: 40px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--surface);
  color: var(--text2);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 0.25s, border-color 0.25s, color 0.25s, box-shadow 0.25s;
  box-shadow: var(--shadow-sm);
}}

.theme-toggle:hover {{
  border-color: var(--amber);
  color: var(--amber);
  box-shadow: var(--shadow-md);
}}

.theme-toggle svg {{
  width: 18px; height: 18px;
  transition: transform 0.35s cubic-bezier(0.34,1.56,0.64,1);
}}

.theme-toggle:hover svg {{
  transform: rotate(30deg);
}}

.theme-toggle .icon-sun {{ display: none; }}
.theme-toggle .icon-moon {{ display: block; }}
[data-theme="light"] .theme-toggle .icon-sun {{ display: block; }}
[data-theme="light"] .theme-toggle .icon-moon {{ display: none; }}

/* ══════════════════════════════════════════
   PAGE OUTLINE (scroll-spy mini-TOC)
   ══════════════════════════════════════════ */
.page-outline {{
  position: fixed;
  right: 28px;
  top: 50%;
  transform: translateY(-50%);
  z-index: 998;
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
  opacity: 0;
  transition: opacity 0.4s ease;
  pointer-events: none;
}}

.page-outline.visible {{
  opacity: 1;
  pointer-events: auto;
}}

.outline-item {{
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  padding: 4px 0;
  transition: opacity 0.2s;
  text-decoration: none;
}}

.outline-item:hover {{ opacity: 1 !important; }}

.outline-label {{
  font-family: var(--font-mono);
  font-size: 0.6rem;
  font-weight: 500;
  color: var(--text3);
  letter-spacing: 0.02em;
  white-space: nowrap;
  opacity: 0;
  transform: translateX(6px);
  transition: opacity 0.2s, transform 0.2s;
}}

.outline-item:hover .outline-label {{
  opacity: 1;
  transform: translateX(0);
}}

.outline-bar {{
  width: 16px;
  height: 2px;
  border-radius: 1px;
  background: var(--border-hi);
  transition: width 0.25s cubic-bezier(0.16,1,0.3,1), background 0.25s, height 0.25s;
}}

.outline-item.active .outline-bar {{
  width: 28px;
  height: 3px;
  background: var(--amber);
}}

.outline-item.active .outline-label {{
  color: var(--amber);
  opacity: 1;
  transform: translateX(0);
}}

.outline-item.passed .outline-bar {{
  background: var(--amber);
  opacity: 0.35;
}}

@media (max-width: 1100px) {{
  .page-outline {{ display: none; }}
}}

/* ══════════════════════════════════════════
   HEADER
   ══════════════════════════════════════════ */
.header {{
  padding: 64px 0 48px;
  position: relative;
  text-align: center;
}}

.header-badge {{
  display: inline-flex;
  align-items: center;
  gap: 10px;
  background: linear-gradient(135deg, var(--amber-dim) 0%, color-mix(in srgb, var(--amber-dim) 60%, transparent) 100%);
  border: 1px solid var(--amber);
  border-radius: 100px;
  padding: 8px 20px 8px 12px;
  margin-bottom: 24px;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  font-weight: 500;
  color: var(--amber-light);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}}

[data-theme="light"] .header-badge {{
  color: #6b4800;
}}

.header-badge svg {{
  width: 20px; height: 20px;
}}

.header h1 {{
  font-family: var(--font-display);
  font-size: 3.2rem;
  font-weight: 800;
  letter-spacing: -0.04em;
  line-height: 1.1;
  color: var(--text);
  margin-bottom: 16px;
}}

.header h1 em {{
  font-style: normal;
  background: linear-gradient(135deg, var(--amber-light), var(--amber), #e07020);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}}

[data-theme="light"] .header h1 em {{
  background: linear-gradient(135deg, #a06810, var(--amber), #e07020);
  -webkit-background-clip: text;
  background-clip: text;
}}

.header-meta {{
  display: flex;
  justify-content: center;
  flex-wrap: wrap;
  gap: 6px 20px;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--text3);
  margin-top: 8px;
}}

.header-meta span {{
  display: inline-flex;
  align-items: center;
  gap: 6px;
}}

.header-meta .sep {{
  color: var(--border-hi);
}}

/* ══════════════════════════════════════════
   KPI STRIP
   ══════════════════════════════════════════ */
.kpi-strip {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1px;
  background: var(--border);
  border-radius: var(--radius-lg);
  overflow: hidden;
  margin: 0 0 52px;
  border: 1px solid var(--border);
  transition: border-color 0.35s;
}}

.kpi {{
  background: var(--surface);
  padding: 28px 20px 24px;
  position: relative;
  overflow: hidden;
  transition: background 0.35s;
}}

.kpi::before {{
  content: '';
  position: absolute;
  top: 0; left: 0;
  width: 100%; height: 2px;
  background: linear-gradient(90deg, transparent, var(--amber), transparent);
  opacity: 0;
  transition: opacity 0.3s;
}}

.kpi::after {{
  content: '';
  position: absolute;
  top: 0; right: 0;
  width: 80px; height: 80px;
  background: radial-gradient(circle at top right, var(--amber), transparent 70%);
  opacity: 0;
  transition: opacity 0.3s;
  pointer-events: none;
}}

.kpi:hover::before {{ opacity: 1; }}
.kpi:hover::after {{ opacity: 0.04; }}

.kpi .value {{
  font-family: var(--font-mono);
  font-size: 1.7rem;
  font-weight: 600;
  color: var(--text);
  display: block;
  line-height: 1.2;
}}

.kpi .value.amber {{ color: var(--amber); }}
.kpi .value.red {{ color: var(--red); }}

.kpi .label {{
  font-size: 0.68rem;
  color: var(--text3);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  font-weight: 600;
  margin-top: 6px;
  display: block;
}}

/* ══════════════════════════════════════════
   SECTIONS — numbered via counter
   ══════════════════════════════════════════ */
body {{
}}

.section {{
  margin: 52px 0;
  opacity: 0;
  transform: translateY(16px);
  animation: fadeUp 0.5s ease forwards;
}}

.section:nth-of-type(1) {{ animation-delay: 0.05s; }}
.section:nth-of-type(2) {{ animation-delay: 0.12s; }}
.section:nth-of-type(3) {{ animation-delay: 0.19s; }}
.section:nth-of-type(4) {{ animation-delay: 0.26s; }}
.section:nth-of-type(5) {{ animation-delay: 0.33s; }}
.section:nth-of-type(6) {{ animation-delay: 0.40s; }}
.section:nth-of-type(7) {{ animation-delay: 0.47s; }}

@keyframes fadeUp {{
  to {{ opacity: 1; transform: translateY(0); }}
}}

.section-head {{
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin-bottom: 6px;
  flex-wrap: wrap;
}}

.section-num {{
  font-family: var(--font-mono);
  font-size: 0.72rem;
  font-weight: 600;
  color: var(--amber);
  letter-spacing: 0.02em;
  user-select: none;
  opacity: 0.6;
}}

.section-titles {{
  display: contents;
}}

.section-titles h2 {{
  font-family: var(--font-display);
  font-size: 1.05rem;
  font-weight: 700;
  letter-spacing: -0.01em;
  color: var(--text);
}}

.section-titles .section-tag {{
  font-family: var(--font-mono);
  font-size: 0.65rem;
  color: var(--text3);
  background: var(--surface2);
  padding: 3px 10px;
  border-radius: 100px;
  letter-spacing: 0.04em;
}}

.section-rule {{
  border: none;
  height: 1px;
  background: var(--section-line);
  margin: 10px 0 0;
}}

.section-intro {{
  font-size: 0.8rem;
  color: var(--text3);
  margin: 8px 0 16px;
  padding-left: 0;
}}

/* ══════════════════════════════════════════
   TABLES
   ══════════════════════════════════════════ */
.table-wrap {{
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  transition: border-color 0.35s;
}}

table {{
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  background: var(--surface);
  transition: background 0.35s;
}}

th {{
  text-align: left;
  padding: 11px 16px;
  font-family: var(--font-mono);
  font-size: 0.62rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text3);
  background: var(--surface2);
  border-bottom: 1px solid var(--border);
  font-weight: 500;
  transition: background 0.35s, color 0.35s;
}}

th.num {{
  text-align: right;
}}

td {{
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  font-size: 0.84rem;
  vertical-align: middle;
  transition: background 0.2s, border-color 0.35s;
}}

tr:last-child td {{ border-bottom: none; }}

tbody tr {{
  transition: background 0.15s, box-shadow 0.2s;
}}

tbody tr:hover {{
  background: var(--table-hover-bg);
  box-shadow: inset 2px 0 0 var(--amber);
}}

.num {{
  text-align: right;
  font-family: var(--font-mono);
  font-size: 0.78rem;
  font-weight: 500;
  white-space: nowrap;
  color: var(--text);
}}

code {{
  font-family: var(--font-mono);
  font-size: 0.78rem;
  background: var(--code-bg);
  padding: 2px 7px;
  border-radius: 4px;
  color: var(--code-color);
  transition: background 0.35s, color 0.35s;
}}

/* ── Bars ── */
.bar-cell {{ min-width: 120px; }}

.bar-track {{
  background: var(--surface3);
  border-radius: 3px;
  height: 18px;
  overflow: hidden;
  position: relative;
  transition: background 0.35s;
}}

.bar {{
  height: 100%;
  border-radius: 3px;
  position: relative;
  transition: width 0.8s cubic-bezier(0.16,1,0.3,1);
}}

.bar-glow {{
  position: absolute;
  right: 0; top: 0; bottom: 0;
  width: 30px;
  filter: blur(8px);
  opacity: 0.35;
  pointer-events: none;
}}

/* ── Ecosystem dot ── */
.eco-dot {{
  display: inline-block;
  width: 10px; height: 10px;
  border-radius: 2px;
  background: var(--dot-color);
  margin-right: 10px;
  vertical-align: middle;
  transform: rotate(45deg);
  flex-shrink: 0;
}}

.eco-name {{
  vertical-align: middle;
  font-weight: 500;
}}

/* ── Confidence badge ── */
.conf-badge {{
  display: inline-block;
  font-family: var(--font-mono);
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 4px 12px;
  border-radius: 4px;
  color: #fff;
  background: var(--badge-bg);
}}

/* ── Project paths ── */
.proj-cell {{
  max-width: 260px;
  overflow: hidden;
  cursor: default;
}}

.proj-cell .proj-short {{
  display: inline;
  font-family: var(--font-mono);
  font-size: 0.78rem;
  color: var(--text2);
}}

.proj-cell .proj-full {{
  display: none;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  word-break: break-all;
  color: var(--text2);
  line-height: 1.5;
}}

.proj-cell:hover .proj-short {{ display: none; }}
.proj-cell:hover .proj-full {{ display: inline; }}

/* ── Versions ── */
.versions {{
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--text3);
  max-width: 260px;
  line-height: 1.5;
}}

/* ── Script tags ── */
.scripts-cell {{ white-space: nowrap; }}

.script-tag {{
  display: inline-block;
  font-family: var(--font-mono);
  font-size: 0.65rem;
  font-weight: 500;
  background: var(--script-tag-bg);
  color: var(--script-tag-color);
  border: 1px solid var(--script-tag-border);
  padding: 2px 8px;
  border-radius: 3px;
  margin-right: 4px;
  transition: background 0.35s, color 0.35s, border-color 0.35s;
}}

/* ── Warning banner ── */
.warning-banner {{
  background: var(--warning-bg);
  border: 1px solid var(--warning-border);
  border-radius: var(--radius);
  padding: 14px 20px;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 0.82rem;
  color: var(--warning-text);
  transition: background 0.35s, border-color 0.35s, color 0.35s;
}}

.warning-banner .warn-icon {{
  font-size: 1.1rem;
  flex-shrink: 0;
}}

.warning-banner strong {{
  color: var(--warning-strong);
}}

/* ── Scan roots ── */
.roots-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 12px;
}}

.root-card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 18px 20px;
  transition: border-color 0.2s, background 0.35s;
}}

.root-card:hover {{
  border-color: var(--border-hi);
}}

.root-card-header {{
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}}

.root-icon {{
  font-size: 1rem;
}}

.root-title {{
  font-family: var(--font-display);
  font-size: 0.78rem;
  font-weight: 700;
  color: var(--text);
  text-transform: uppercase;
  letter-spacing: 0.03em;
  flex: 1;
}}

.root-count {{
  font-family: var(--font-mono);
  font-size: 0.65rem;
  color: var(--text3);
  background: var(--surface3);
  padding: 2px 8px;
  border-radius: 100px;
}}

.root-card ul {{
  list-style: none;
  padding: 0;
}}

.root-card li {{
  padding: 5px 0;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--text3);
  word-break: break-all;
  border-top: 1px solid var(--border);
}}

.root-card li:first-child {{ border-top: none; }}

.root-card li code {{
  background: none;
  padding: 0;
  font-size: 0.72rem;
}}

/* ══════════════════════════════════════════
   FOOTER
   ══════════════════════════════════════════ */
.footer {{
  text-align: center;
  padding: 40px 0 0;
  margin-top: 72px;
  border-top: 1px solid var(--border);
  font-family: var(--font-mono);
  font-size: 0.68rem;
  color: var(--text3);
  display: flex;
  justify-content: center;
  flex-wrap: wrap;
  gap: 6px 16px;
  transition: border-color 0.35s;
}}

.footer .sep {{ color: var(--border-hi); }}

/* ══════════════════════════════════════════
   RESPONSIVE
   ══════════════════════════════════════════ */
@media (max-width: 768px) {{
  .kpi-strip {{ grid-template-columns: repeat(2, 1fr); }}
  .header h1 {{ font-size: 2.2rem; }}
  .container {{ padding: 0 16px 60px; }}
}}

@media (max-width: 480px) {{
  .kpi-strip {{ grid-template-columns: 1fr 1fr; }}
  .header h1 {{ font-size: 1.8rem; }}
  .bar-cell {{ min-width: 80px; }}
  .theme-toggle {{ top: 12px; right: 12px; width: 36px; height: 36px; }}
}}
</style>
</head>
<body>

<!-- Scroll progress -->
<div class="scroll-progress" id="scrollProgress"></div>

<!-- Theme toggle -->
<button class="theme-toggle" id="themeToggle" aria-label="Toggle theme">
  <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
  </svg>
  <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
  </svg>
</button>

<div class="container">

  <!-- Header -->
  <header class="header">
    <div class="header-badge">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 2L15.09 8.26L22 9.27L17 14.14L18.18 21.02L12 17.77L5.82 21.02L7 14.14L2 9.27L8.91 8.26L12 2Z"/>
      </svg>
      Inventory Report
    </div>
    <h1>Bumblebee <em>Inventory</em></h1>
    <div class="header-meta">
      <span>{esc(summary["endpoint"]["hostname"])}</span>
      <span class="sep">·</span>
      <span>{esc(summary["endpoint"]["os"])}/{esc(summary["endpoint"]["arch"])}</span>
      <span class="sep">·</span>
      <span>{esc(summary["scan_time"][:19].replace("T", " "))}</span>
      <span class="sep">·</span>
      <span>{duration_s:.1f}s</span>
      <span class="sep">·</span>
      <span>profile: {esc(summary["profile"])}</span>
    </div>
  </header>

  <!-- KPI strip -->
  <div class="kpi-strip">
    <div class="kpi">
      <span class="value amber">{len(packages):,}</span>
      <span class="label">Total Packages</span>
    </div>
    <div class="kpi">
      <span class="value">{sum(len(v) for v in unique_by_eco.values()):,}</span>
      <span class="label">Unique Names</span>
    </div>
    <div class="kpi">
      <span class="value">{len(ecosystems)}</span>
      <span class="label">Ecosystems</span>
    </div>
    <div class="kpi">
      <span class="value">{len(projects)}</span>
      <span class="label">Projects</span>
    </div>
    <div class="kpi">
      <span class="value">{direct_deps:,}</span>
      <span class="label">Direct Deps</span>
    </div>
    <div class="kpi">
      <span class="value red">{len(lifecycle_script_pkgs)}</span>
      <span class="label">Lifecycle Scripts</span>
    </div>
    <div class="kpi">
      <span class="value">{len(multi_pkgs)}</span>
      <span class="label">Multi-Version</span>
    </div>
    <div class="kpi">
      <span class="value">{summary["files_considered"]:,}</span>
      <span class="label">Files Scanned</span>
    </div>
  </div>

  <!-- 01. Ecosystems -->
  <section class="section" id="sec-ecosystems">
    <div class="section-head">
      <span class="section-num">01</span>
      <div class="section-titles">
        <h2>Packages by Ecosystem</h2>
        <span class="section-tag">{len(ecosystems)} ecosystems</span>
      </div>
    </div>
    <hr class="section-rule">
    <p class="section-intro">What&rsquo;s on this machine &mdash; a breakdown of every package discovered, grouped by language and runtime.</p>
    <div class="table-wrap"><table>
      <thead><tr><th>Ecosystem</th><th class="num">Total</th><th class="num">Unique</th><th>Distribution</th></tr></thead>
      <tbody>{eco_rows}</tbody>
    </table></div>
  </section>

  <!-- 02. Lifecycle Scripts -->
  <section class="section" id="sec-lifecycle">
    <div class="section-head">
      <span class="section-num">02</span>
      <div class="section-titles">
        <h2>Lifecycle Scripts</h2>
        <span class="section-tag">{len(lifecycle_script_pkgs)} packages with install-time hooks</span>
      </div>
    </div>
    <hr class="section-rule">
    <p class="section-intro">What&rsquo;s dangerous &mdash; packages that run arbitrary code when installed or updated.</p>
    <div class="warning-banner">
      <span class="warn-icon">⚠</span>
      <span>These packages execute <strong>arbitrary code</strong> at install time (preinstall, postinstall, prepare). Review them for supply-chain risk.</span>
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th>Ecosystem</th><th>Package</th><th>Scripts</th><th>Project</th></tr></thead>
      <tbody>{lifecycle_rows}</tbody>
    </table></div>
  </section>

  <!-- 03. Version Sprawl -->
  <section class="section" id="sec-versions">
    <div class="section-head">
      <span class="section-num">03</span>
      <div class="section-titles">
        <h2>Version Sprawl</h2>
        <span class="section-tag">{len(multi_pkgs)} packages with multiple versions</span>
      </div>
    </div>
    <hr class="section-rule">
    <p class="section-intro">What&rsquo;s outdated &mdash; packages pinned to many different versions across projects, increasing patching burden.</p>
    <div class="table-wrap"><table>
      <thead><tr><th>Ecosystem</th><th>Package</th><th class="num">Versions</th><th>Sample</th></tr></thead>
      <tbody>{multi_rows}</tbody>
    </table></div>
  </section>

  <!-- 04. Top Projects -->
  <section class="section" id="sec-projects">
    <div class="section-head">
      <span class="section-num">04</span>
      <div class="section-titles">
        <h2>Top Projects</h2>
        <span class="section-tag">{len(projects)} total</span>
      </div>
    </div>
    <hr class="section-rule">
    <p class="section-intro">Where complexity concentrates &mdash; projects with the deepest dependency trees.</p>
    <div class="table-wrap"><table>
      <thead><tr><th>Project</th><th class="num">Packages</th><th>Distribution</th></tr></thead>
      <tbody>{proj_rows}</tbody>
    </table></div>
  </section>

  <!-- 05. Confidence -->
  <section class="section" id="sec-confidence">
    <div class="section-head">
      <span class="section-num">05</span>
      <div class="section-titles">
        <h2>Confidence Levels</h2>
      </div>
    </div>
    <hr class="section-rule">
    <p class="section-intro">How reliable is this data &mdash; detection confidence assigned to each package record.</p>
    <div class="table-wrap"><table>
      <thead><tr><th>Level</th><th class="num">Count</th><th class="num">Share</th><th>Distribution</th></tr></thead>
      <tbody>{conf_rows}</tbody>
    </table></div>
  </section>

  <!-- 06. Detection Sources -->
  <section class="section" id="sec-sources">
    <div class="section-head">
      <span class="section-num">06</span>
      <div class="section-titles">
        <h2>Detection Sources</h2>
        <span class="section-tag">{len(source_types)} sources</span>
      </div>
    </div>
    <hr class="section-rule">
    <p class="section-intro">How packages were found &mdash; lockfiles, module caches, manifests, and extension metadata.</p>
    <div class="table-wrap"><table>
      <thead><tr><th>Source</th><th class="num">Count</th><th>Distribution</th></tr></thead>
      <tbody>{src_rows}</tbody>
    </table></div>
  </section>

  <!-- 07. Scan Roots -->
  <section class="section" id="sec-roots">
    <div class="section-head">
      <span class="section-num">07</span>
      <div class="section-titles">
        <h2>Scan Roots</h2>
        <span class="section-tag">{len(summary["roots"])} directories</span>
      </div>
    </div>
    <hr class="section-rule">
    <p class="section-intro">Reference &mdash; every directory bumblebee crawled during this scan.</p>
    <div class="roots-grid">{scan_roots_html}</div>
  </section>

  <!-- Footer -->
  <footer class="footer">
    <span>bumblebee {esc(summary["scanner_version"])}</span>
    <span class="sep">·</span>
    <span>schema v{esc(summary["schema_version"])}</span>
    <span class="sep">·</span>
    <span>run {esc(summary["run_id"][:12])}</span>
    <span class="sep">·</span>
    <span>{summary["files_considered"]:,} files in {duration_s:.1f}s</span>
  </footer>

  <!-- Page outline (scroll-spy) -->
  <nav class="page-outline" id="pageOutline">
    <a class="outline-item" href="#sec-ecosystems" data-section="sec-ecosystems">
      <span class="outline-label">Ecosystems</span>
      <span class="outline-bar"></span>
    </a>
    <a class="outline-item" href="#sec-lifecycle" data-section="sec-lifecycle">
      <span class="outline-label">Lifecycle</span>
      <span class="outline-bar"></span>
    </a>
    <a class="outline-item" href="#sec-versions" data-section="sec-versions">
      <span class="outline-label">Versions</span>
      <span class="outline-bar"></span>
    </a>
    <a class="outline-item" href="#sec-projects" data-section="sec-projects">
      <span class="outline-label">Projects</span>
      <span class="outline-bar"></span>
    </a>
    <a class="outline-item" href="#sec-confidence" data-section="sec-confidence">
      <span class="outline-label">Confidence</span>
      <span class="outline-bar"></span>
    </a>
    <a class="outline-item" href="#sec-sources" data-section="sec-sources">
      <span class="outline-label">Sources</span>
      <span class="outline-bar"></span>
    </a>
    <a class="outline-item" href="#sec-roots" data-section="sec-roots">
      <span class="outline-label">Roots</span>
      <span class="outline-bar"></span>
    </a>
  </nav>

</div>

<script>
(function() {{
  // ── Theme toggle ──
  var html = document.documentElement;
  var toggle = document.getElementById('themeToggle');
  var stored = localStorage.getItem('bumblebee-theme');
  if (stored) html.setAttribute('data-theme', stored);

  toggle.addEventListener('click', function() {{
    var current = html.getAttribute('data-theme');
    var next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('bumblebee-theme', next);
  }});

  // ── Scroll progress ──
  var bar = document.getElementById('scrollProgress');
  function updateProgress() {{
    var scrollTop = window.scrollY;
    var docHeight = document.documentElement.scrollHeight - window.innerHeight;
    var pct = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
    bar.style.width = pct + '%';
  }}
  window.addEventListener('scroll', updateProgress, {{ passive: true }});
  updateProgress();

  // ── Page outline scroll-spy ──
  var outline = document.getElementById('pageOutline');
  var outlineItems = outline.querySelectorAll('.outline-item');
  var sectionIds = [];
  outlineItems.forEach(function(item) {{
    sectionIds.push(item.getAttribute('data-section'));
  }});

  function updateOutline() {{
    var scrollTop = window.scrollY;
    var viewportMid = scrollTop + window.innerHeight * 0.35;
    var activeId = null;

    // Find which section is currently in view
    for (var i = sectionIds.length - 1; i >= 0; i--) {{
      var sec = document.getElementById(sectionIds[i]);
      if (sec && sec.offsetTop <= viewportMid) {{
        activeId = sectionIds[i];
        break;
      }}
    }}

    // Show/hide outline (hide when near top)
    if (scrollTop > 300) {{
      outline.classList.add('visible');
    }} else {{
      outline.classList.remove('visible');
    }}

    // Update active/passed states
    var activeFound = false;
    outlineItems.forEach(function(item) {{
      var id = item.getAttribute('data-section');
      item.classList.remove('active', 'passed');
      if (id === activeId) {{
        item.classList.add('active');
        activeFound = true;
      }} else if (!activeFound) {{
        item.classList.add('passed');
      }}
    }});
  }}
  window.addEventListener('scroll', updateOutline, {{ passive: true }});
  updateOutline();
}})();
</script>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"Report written to {output_path} ({len(html):,} bytes)")


# ── CLI entry point ──
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate an HTML report from bumblebee inventory.ndjson",
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="inventory.ndjson",
        help="Path to inventory.ndjson (default: inventory.ndjson)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="report.html",
        help="Output HTML file path (default: report.html)",
    )
    args = parser.parse_args()
    generate_report(args.input, args.output)
