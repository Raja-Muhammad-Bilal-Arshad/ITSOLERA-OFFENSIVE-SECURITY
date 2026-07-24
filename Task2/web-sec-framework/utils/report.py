"""
report.py
---------
Builds the professional scan report (HTML and/or JSON) from the list of
ScanResult objects returned by each module.
"""

import json
import os
from datetime import datetime
from html import escape

from utils.findings import overall_risk_rating

SEVERITY_COLORS = {
    "Critical": "#7f1d1d",
    "High": "#dc2626",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Info": "#6b7280",
}


def _all_findings(scan_results):
    findings = []
    for sr in scan_results:
        findings.extend(sr.findings)
    return findings


def build_report_data(target, scan_results, scan_date=None):
    all_findings = _all_findings(scan_results)
    actionable = [f for f in all_findings if f.severity != "Info"]

    data = {
        "target": target,
        "scan_date": scan_date or datetime.now().isoformat(timespec="seconds"),
        "modules_executed": [sr.module_name for sr in scan_results],
        "overall_risk_rating": overall_risk_rating(actionable) if actionable else "Info",
        "summary": {
            sev: len([f for f in all_findings if f.severity == sev])
            for sev in ("Critical", "High", "Medium", "Low", "Info")
        },
        "findings": [
            {
                "module": f.module,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "location": f.location,
            }
            for f in all_findings
        ],
        "errors": [err for sr in scan_results for err in sr.errors],
    }
    return data


def write_json_report(data, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return output_path


def write_html_report(data, output_path):
    findings_rows = ""
    for f in data["findings"]:
        color = SEVERITY_COLORS.get(f["severity"], "#6b7280")
        findings_rows += f"""
        <tr>
          <td>{escape(f['module'])}</td>
          <td>{escape(f['title'])}</td>
          <td><span class="badge" style="background:{color}">{escape(f['severity'])}</span></td>
          <td>{escape(f['description'])}</td>
          <td><code>{escape(f['evidence'] or '-')}</code></td>
          <td>{escape(f['remediation'] or '-')}</td>
          <td>{escape(f['location'] or '-')}</td>
        </tr>"""

    summary_cells = "".join(
        f'<div class="summary-card" style="border-color:{SEVERITY_COLORS[sev]}">'
        f'<div class="summary-count" style="color:{SEVERITY_COLORS[sev]}">{count}</div>'
        f'<div class="summary-label">{sev}</div></div>'
        for sev, count in data["summary"].items()
    )

    overall_color = SEVERITY_COLORS.get(data["overall_risk_rating"], "#6b7280")
    errors_html = ""
    if data["errors"]:
        error_items = "".join(f"<li>{escape(e)}</li>" for e in data["errors"])
        errors_html = f"""
        <div class="section">
          <h2>Errors / Warnings</h2>
          <ul class="errors">{error_items}</ul>
        </div>"""

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Web Security Scan Report — {escape(data['target'])}</title>
<style>
  :root {{
    --bg: #0f172a;
    --panel: #ffffff;
    --text: #1e293b;
    --muted: #64748b;
    --accent: #2563eb;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', Roboto, Arial, sans-serif;
    background: #f1f5f9;
    color: var(--text);
    margin: 0;
    padding: 0;
  }}
  header {{
    background: linear-gradient(135deg, #0f172a, #1e3a8a);
    color: #fff;
    padding: 32px 40px;
  }}
  header h1 {{ margin: 0 0 8px 0; font-size: 26px; }}
  header .meta {{ color: #cbd5e1; font-size: 14px; }}
  .container {{ max-width: 1100px; margin: -20px auto 40px auto; padding: 0 20px; }}
  .section {{
    background: var(--panel);
    border-radius: 10px;
    padding: 24px 28px;
    margin-bottom: 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
  }}
  .section h2 {{ margin-top: 0; font-size: 18px; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }}
  .risk-banner {{
    display: inline-block;
    padding: 10px 20px;
    border-radius: 8px;
    color: #fff;
    font-weight: 600;
    font-size: 16px;
    background: {overall_color};
  }}
  .summary-grid {{
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin-top: 16px;
  }}
  .summary-card {{
    flex: 1;
    min-width: 100px;
    text-align: center;
    border: 2px solid;
    border-radius: 8px;
    padding: 14px 8px;
    background: #f8fafc;
  }}
  .summary-count {{ font-size: 26px; font-weight: 700; }}
  .summary-label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 10px 8px; vertical-align: top; border-bottom: 1px solid #e2e8f0; }}
  th {{ background: #f8fafc; color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.04em; }}
  .badge {{
    color: #fff;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    white-space: nowrap;
  }}
  code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 12px; word-break: break-word; }}
  .errors {{ color: #b91c1c; }}
  .modules-list {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 10px; }}
  .modules-list span {{
    background: #eef2ff;
    color: #3730a3;
    padding: 6px 12px;
    border-radius: 6px;
    font-size: 13px;
  }}
  footer {{ text-align: center; color: var(--muted); font-size: 12px; padding: 20px; }}
</style>
</head>
<body>
<header>
  <h1>Web Security Testing Framework — Scan Report</h1>
  <div class="meta">Target: {escape(data['target'])} &nbsp;|&nbsp; Scan Date: {escape(data['scan_date'])}</div>
</header>
<div class="container">

  <div class="section">
    <h2>Overview</h2>
    <p>Overall Risk Rating: <span class="risk-banner">{escape(data['overall_risk_rating'])}</span></p>
    <p><strong>Modules Executed:</strong></p>
    <div class="modules-list">
      {''.join(f'<span>{escape(m)}</span>' for m in data['modules_executed'])}
    </div>
    <div class="summary-grid">
      {summary_cells}
    </div>
  </div>

  <div class="section">
    <h2>Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Module</th><th>Title</th><th>Severity</th><th>Description</th>
          <th>Evidence</th><th>Remediation</th><th>Location</th>
        </tr>
      </thead>
      <tbody>
        {findings_rows}
      </tbody>
    </table>
  </div>
  {errors_html}
</div>
<footer>Generated by Web Security Testing Framework — for authorized security testing only.</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return output_path


def generate_report(target, scan_results, output_dir="reports", output_format="html", scan_date=None):
    os.makedirs(output_dir, exist_ok=True)
    data = build_report_data(target, scan_results, scan_date=scan_date)

    safe_host = "".join(c if c.isalnum() else "_" for c in target)[:60]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"report_{safe_host}_{timestamp}"

    paths = []
    if output_format in ("html", "both"):
        paths.append(write_html_report(data, os.path.join(output_dir, base_name + ".html")))
    if output_format in ("json", "both"):
        paths.append(write_json_report(data, os.path.join(output_dir, base_name + ".json")))
    return paths, data
