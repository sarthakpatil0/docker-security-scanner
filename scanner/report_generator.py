"""
report_generator.py
-------------------
Generates formatted output from scan results:
  - Console (colorful terminal output)
  - HTML report (self-contained, no external dependencies)
"""

import json
from datetime import datetime


# ─────────────────────────────────────────────
#  Terminal colors (ANSI codes)
# ─────────────────────────────────────────────

class Color:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    GREY   = "\033[90m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": Color.RED,
    "HIGH":     Color.RED,
    "MEDIUM":   Color.YELLOW,
    "LOW":      Color.CYAN,
    "INFO":     Color.GREY,
    "UNKNOWN":  Color.GREY,
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
    "UNKNOWN":  "⚫",
}


# ─────────────────────────────────────────────
#  Console Report
# ─────────────────────────────────────────────

def print_console_report(results: dict):
    print("\n" + "═" * 60)
    print(f"{Color.BOLD}🔒  DOCKER SECURITY SCAN REPORT{Color.RESET}")
    print("═" * 60)
    print(f"  Scanned at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if results.get("image"):
        print(f"  Image:      {results['image']}")
    if results.get("dockerfile"):
        print(f"  Dockerfile: {results['dockerfile']}")
    print()

    # --- Image scan results ---
    img = results.get("image_scan")
    if img:
        if img["status"] == "trivy_not_found":
            print(f"{Color.YELLOW}⚠️  Trivy not installed:{Color.RESET}")
            print(f"   {img['message']}\n")
        elif img["status"] == "error":
            print(f"{Color.RED}❌  Image scan error:{Color.RESET} {img['message']}\n")
        else:
            summary = img.get("summary", {})
            total   = img.get("total", 0)
            print(f"{Color.BOLD}📦 Image Vulnerabilities — {results['image']}{Color.RESET}")
            print(f"   Total: {total} vulnerabilities found")
            _print_summary_bar(summary)

            vulns = img.get("vulnerabilities", [])
            shown = 0
            for v in vulns:
                if v["severity"] in ("CRITICAL", "HIGH") and shown < 20:
                    col = SEVERITY_COLOR.get(v["severity"], "")
                    em  = SEVERITY_EMOJI.get(v["severity"], "")
                    print(f"\n  {em} {col}{v['severity']}{Color.RESET}  {Color.BOLD}{v['id']}{Color.RESET}")
                    print(f"     Package:    {v['package']} {v['installed']}")
                    print(f"     Fixed in:   {v['fixed_in']}")
                    print(f"     CVSS Score: {v['cvss_score']}")
                    print(f"     {v['title']}")
                    shown += 1

            if total > shown:
                remaining = total - shown
                print(f"\n  {Color.GREY}... and {remaining} more (MEDIUM/LOW). Use --output report.html for full report.{Color.RESET}")
            print()

    # --- Dockerfile lint results ---
    lint = results.get("lint_results")
    if lint:
        if lint["status"] == "error":
            print(f"{Color.RED}❌  Dockerfile lint error:{Color.RESET} {lint['message']}\n")
        else:
            total   = lint.get("total", 0)
            summary = lint.get("summary", {})
            print(f"{Color.BOLD}📋 Dockerfile Findings — {results['dockerfile']}{Color.RESET}")
            print(f"   Total: {total} issues found")
            _print_summary_bar(summary)

            for f in lint.get("findings", []):
                col = SEVERITY_COLOR.get(f["severity"], "")
                em  = SEVERITY_EMOJI.get(f["severity"], "")
                loc = f"  Line {f['line_num']}:" if f.get("line_num") else " "
                print(f"\n  {em} {col}{f['severity']}{Color.RESET}  [{f['rule_id']}] {Color.BOLD}{f['title']}{Color.RESET}")
                print(f"     {f['message']}")
                if f.get("line_num"):
                    print(f"     {Color.GREY}Line {f['line_num']}: {f.get('line_text', '')}{Color.RESET}")
                if f.get("fix"):
                    print(f"     {Color.GREEN}Fix: {f['fix']}{Color.RESET}")
            print()

    # --- Overall verdict ---
    _print_verdict(results)
    print("═" * 60 + "\n")


def _print_summary_bar(summary: dict):
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"):
        count = summary.get(sev, 0)
        if count:
            col = SEVERITY_COLOR.get(sev, "")
            parts.append(f"{col}{sev}: {count}{Color.RESET}")
    print("   " + "  |  ".join(parts) if parts else "   None found ✅")
    print()


def _print_verdict(results: dict):
    critical = 0
    high     = 0

    img = results.get("image_scan") or {}
    if img.get("status") == "ok":
        critical += img.get("summary", {}).get("CRITICAL", 0)
        high     += img.get("summary", {}).get("HIGH", 0)

    lint = results.get("lint_results") or {}
    if lint.get("status") == "ok":
        critical += lint.get("summary", {}).get("CRITICAL", 0)
        high     += lint.get("summary", {}).get("HIGH", 0)

    if critical > 0:
        print(f"{Color.RED}{Color.BOLD}⛔  VERDICT: FAIL — {critical} CRITICAL issue(s) found. Fix before deploying!{Color.RESET}")
    elif high > 0:
        print(f"{Color.YELLOW}{Color.BOLD}⚠️   VERDICT: WARN — {high} HIGH severity issue(s). Review recommended.{Color.RESET}")
    else:
        print(f"{Color.GREEN}{Color.BOLD}✅  VERDICT: PASS — No critical or high severity issues found.{Color.RESET}")


# ─────────────────────────────────────────────
#  HTML Report
# ─────────────────────────────────────────────

def generate_report(results: dict, output_path: str):
    """Generate a self-contained HTML security report."""

    scan_time  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    image_name = results.get("image", "N/A")
    dockerfile = results.get("dockerfile", "N/A")
    risk       = results.get("risk", {})

    img  = results.get("image_scan") or {}
    lint = results.get("lint_results") or {}

    # Build risk score section
    score       = risk.get("score", "N/A")
    grade       = risk.get("grade", "?")
    label       = risk.get("label", "Unknown")
    risk_color  = risk.get("color", "#8b949e")
    risk_desc   = risk.get("description", "")
    avg_cvss    = risk.get("avg_cvss", 0)
    filled      = int(score / 5) * 5 if isinstance(score, int) else 0
    rec_rows    = "".join(
        f"<tr><td style='color:#58a6ff;font-weight:700'>#{r['priority']}</td>"
        f"<td>{_esc(r['action'])}</td>"
        f"<td style='color:#8b949e'>{_esc(r['why'])}</td></tr>"
        for r in risk.get("recommendations", [])
    )
    b            = risk.get("breakdown", {})
    sev_val      = b.get("severity_penalty",   {}).get("value", 0) if isinstance(b.get("severity_penalty"),   dict) else b.get("severity_penalty",   0)
    cvss_val     = b.get("cvss_penalty",        {}).get("value", 0) if isinstance(b.get("cvss_penalty"),        dict) else b.get("cvss_penalty",        0)
    fix_val      = b.get("fixability_penalty",  {}).get("value", 0) if isinstance(b.get("fixability_penalty"), dict) else b.get("fixability_penalty",  0)
    mult_val     = b.get("dockerfile_multiplier", {}).get("value", 1.0)
    total_pen    = b.get("total_penalty", 0)

    # Build vuln rows
    vuln_rows = ""
    if img.get("status") == "ok":
        for v in img.get("vulnerabilities", []):
            badge = _html_badge(v["severity"])
            refs  = " ".join(f'<a href="{r}" target="_blank">🔗</a>' for r in v.get("references", []))
            vuln_rows += f"""
            <tr>
                <td>{badge}</td>
                <td><code>{v['id']}</code></td>
                <td>{v['package']}</td>
                <td>{v['installed']}</td>
                <td>{v['fixed_in']}</td>
                <td>{v['cvss_score']}</td>
                <td>{v['title'][:80]}</td>
                <td>{refs}</td>
            </tr>"""

    # Build lint rows
    lint_rows = ""
    if lint.get("status") == "ok":
        for f in lint.get("findings", []):
            badge   = _html_badge(f["severity"])
            line    = f"Line {f['line_num']}" if f.get("line_num") else "—"
            snippet = f"<code>{_esc(f.get('line_text',''))}</code>" if f.get("line_text") else "—"
            fix     = _esc(f.get("fix", ""))
            lint_rows += f"""
            <tr>
                <td>{badge}</td>
                <td><b>[{f['rule_id']}]</b> {_esc(f['title'])}</td>
                <td>{_esc(f['message'])}</td>
                <td>{line}<br>{snippet}</td>
                <td class="fix-col">{fix}</td>
            </tr>"""

    img_summary  = _html_summary_pills(img.get("summary", {}))
    lint_summary = _html_summary_pills(lint.get("summary", {}))
    total_vulns  = img.get("total", 0)
    total_lint   = lint.get("total", 0)

    # Verdict
    critical = (img.get("summary", {}).get("CRITICAL", 0) +
                lint.get("summary", {}).get("CRITICAL", 0))
    high     = (img.get("summary", {}).get("HIGH", 0) +
                lint.get("summary", {}).get("HIGH", 0))
    if critical > 0:
        verdict_class, verdict_text = "fail", f"⛔ FAIL — {critical} critical issue(s)"
    elif high > 0:
        verdict_class, verdict_text = "warn", f"⚠️ WARN — {high} high severity issue(s)"
    else:
        verdict_class, verdict_text = "pass", "✅ PASS"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Docker Security Report — {image_name}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }}
  header {{ background: linear-gradient(135deg, #1f2937 0%, #111827 100%); padding: 2rem 2.5rem; border-bottom: 1px solid #30363d; }}
  header h1 {{ font-size: 1.8rem; color: #58a6ff; }}
  header p  {{ color: #8b949e; margin-top: .3rem; font-size: .9rem; }}
  .verdict  {{ display: inline-block; margin-top: 1rem; padding: .5rem 1.2rem; border-radius: 6px; font-weight: 700; font-size: 1rem; }}
  .verdict.pass {{ background: #0d3a1e; color: #3fb950; border: 1px solid #3fb950; }}
  .verdict.warn {{ background: #3a2900; color: #e3b341; border: 1px solid #e3b341; }}
  .verdict.fail {{ background: #3a0d0d; color: #f85149; border: 1px solid #f85149; }}
  main {{ padding: 2rem 2.5rem; max-width: 1400px; }}
  section {{ margin-bottom: 2.5rem; }}
  h2 {{ font-size: 1.2rem; color: #f0f6fc; border-bottom: 1px solid #30363d; padding-bottom: .6rem; margin-bottom: 1rem; }}
  .pills {{ display: flex; gap: .5rem; flex-wrap: wrap; margin-bottom: 1rem; }}
  .pill {{ padding: .25rem .75rem; border-radius: 20px; font-size: .8rem; font-weight: 700; }}
  .CRITICAL {{ background:#3a0d0d; color:#f85149; border:1px solid #f85149; }}
  .HIGH     {{ background:#3a1500; color:#f0883e; border:1px solid #f0883e; }}
  .MEDIUM   {{ background:#3a2900; color:#e3b341; border:1px solid #e3b341; }}
  .LOW      {{ background:#0d2a3a; color:#58a6ff; border:1px solid #58a6ff; }}
  .INFO     {{ background:#1a1a1a; color:#8b949e; border:1px solid #8b949e; }}
  .UNKNOWN  {{ background:#1a1a1a; color:#8b949e; border:1px solid #8b949e; }}
  table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
  th {{ background:#161b22; color:#8b949e; padding:.6rem .8rem; text-align:left; font-weight:600; border-bottom:2px solid #30363d; }}
  td {{ padding:.55rem .8rem; border-bottom:1px solid #21262d; vertical-align:top; }}
  tr:hover td {{ background:#161b22; }}
  code {{ background:#161b22; padding:.1rem .35rem; border-radius:4px; font-size:.82rem; color:#79c0ff; }}
  a {{ color:#58a6ff; }}
  .fix-col {{ color:#3fb950; font-size:.8rem; }}
  .meta {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:1rem; margin-bottom:1.5rem; }}
  .meta-card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:1rem; }}
  .meta-card .label {{ color:#8b949e; font-size:.75rem; margin-bottom:.3rem; }}
  .meta-card .value {{ color:#f0f6fc; font-weight:600; }}
  .risk-card {{ background:#161b22; border:2px solid {risk_color}; border-radius:12px; padding:1.5rem 2rem; display:flex; gap:2rem; align-items:center; margin-bottom:1.5rem; flex-wrap:wrap; }}
  .risk-score-circle {{ text-align:center; min-width:100px; }}
  .risk-score-number {{ font-size:3.5rem; font-weight:900; color:{risk_color}; line-height:1; }}
  .risk-score-grade  {{ font-size:1.1rem; color:{risk_color}; font-weight:700; margin-top:.3rem; }}
  .risk-bar-wrap {{ flex:1; min-width:200px; }}
  .risk-bar-bg   {{ background:#21262d; border-radius:99px; height:14px; overflow:hidden; margin:.5rem 0; }}
  .risk-bar-fill {{ height:100%; border-radius:99px; background:{risk_color}; width:{filled}%; transition:width 1s ease; }}
  .risk-label    {{ font-size:1.3rem; font-weight:800; color:{risk_color}; }}
  .risk-desc     {{ color:#8b949e; font-size:.9rem; margin-top:.3rem; }}
  .risk-meta     {{ display:flex; gap:1.5rem; margin-top:.8rem; font-size:.85rem; color:#8b949e; }}
  .breakdown-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:.8rem; margin:.8rem 0; }}
  .breakdown-card {{ background:#0d1117; border:1px solid #30363d; border-radius:8px; padding:.8rem 1rem; }}
  .breakdown-card .blabel {{ font-size:.7rem; color:#8b949e; margin-bottom:.2rem; }}
  .breakdown-card .bvalue {{ font-size:1.2rem; font-weight:700; color:#f0f6fc; }}
</style>
</head>
<body>
<header>
  <h1>🔒 Docker Security Report</h1>
  <p>Generated on {scan_time}</p>
  <div class="verdict {verdict_class}">{verdict_text}</div>
</header>
<main>
  <section>
    <div class="meta">
      <div class="meta-card"><div class="label">IMAGE</div><div class="value">{image_name}</div></div>
      <div class="meta-card"><div class="label">DOCKERFILE</div><div class="value">{dockerfile}</div></div>
      <div class="meta-card"><div class="label">VULNERABILITIES</div><div class="value">{total_vulns}</div></div>
      <div class="meta-card"><div class="label">LINT ISSUES</div><div class="value">{total_lint}</div></div>
    </div>
  </section>

  <!-- Risk Score -->
  <section>
    <h2>🎯 Security Risk Score</h2>
    <div class="risk-card">
      <div class="risk-score-circle">
        <div class="risk-score-number">{score}</div>
        <div class="risk-score-grade">Grade {grade}</div>
      </div>
      <div class="risk-bar-wrap">
        <div class="risk-label">{label}</div>
        <div class="risk-bar-bg"><div class="risk-bar-fill"></div></div>
        <div class="risk-desc">{risk_desc}</div>
        <div class="risk-meta">
          <span>Avg CVSS: <b style="color:#f0f6fc">{avg_cvss}</b></span>
          <span>Total Vulns: <b style="color:#f0f6fc">{total_vulns}</b></span>
          <span>Dockerfile Multiplier: <b style="color:#f0f6fc">×{mult_val}</b></span>
        </div>
      </div>
    </div>

    <div class="breakdown-grid">
      <div class="breakdown-card">
        <div class="blabel">SEVERITY PENALTY</div>
        <div class="bvalue">-{sev_val} pts</div>
      </div>
      <div class="breakdown-card">
        <div class="blabel">CVSS PENALTY</div>
        <div class="bvalue">-{cvss_val} pts</div>
      </div>
      <div class="breakdown-card">
        <div class="blabel">FIXABILITY PENALTY</div>
        <div class="bvalue">-{fix_val} pts</div>
      </div>
      <div class="breakdown-card">
        <div class="blabel">TOTAL PENALTY</div>
        <div class="bvalue">{total_pen} pts</div>
      </div>
    </div>

    <h2 style="margin-top:1.2rem">💡 Recommendations</h2>
    <table>
      <thead><tr><th>#</th><th>Action</th><th>Why</th></tr></thead>
      <tbody>{rec_rows}</tbody>
    </table>
  </section>

  <!-- Image Vulnerabilities -->
  <section>
    <h2>📦 Image Vulnerabilities</h2>
    <div class="pills">{img_summary}</div>
    {"<p class='empty'>No vulnerabilities found ✅</p>" if not vuln_rows else f'''
    <table>
      <thead><tr>
        <th>Severity</th><th>CVE ID</th><th>Package</th>
        <th>Installed</th><th>Fixed In</th><th>CVSS</th><th>Description</th><th>Refs</th>
      </tr></thead>
      <tbody>{vuln_rows}</tbody>
    </table>'''}
  </section>

  <!-- Dockerfile Findings -->
  <section>
    <h2>📋 Dockerfile Best Practice Findings</h2>
    <div class="pills">{lint_summary}</div>
    {"<p class='empty'>No issues found ✅</p>" if not lint_rows else f'''
    <table>
      <thead><tr>
        <th>Severity</th><th>Rule</th><th>Issue</th><th>Location</th><th>How to Fix</th>
      </tr></thead>
      <tbody>{lint_rows}</tbody>
    </table>'''}
  </section>
</main>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def _html_badge(severity: str) -> str:
    return f'<span class="pill {severity}">{severity}</span>'


def _html_summary_pills(summary: dict) -> str:
    pills = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"):
        count = summary.get(sev, 0)
        if count:
            pills += f'<span class="pill {sev}">{sev}: {count}</span>'
    return pills or '<span style="color:#3fb950">✅ None found</span>'


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")