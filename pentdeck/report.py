"""Reports.

Four formats, one data structure: a terminal summary for the operator standing in
the client's server room, and JSON, Markdown and HTML for the file that gets
emailed afterwards. The HTML report is self-contained — inline CSS, inline SVG,
no fonts and no scripts from anywhere — because it has to open on a machine with
no internet and it must not phone home when it does.
"""

from __future__ import annotations

import html
import json
from typing import Dict, List, Sequence

from .findings import Finding, ScanResult, Severity

TITLE = "pentdeck — internal network assessment"


def _partial(result: ScanResult) -> str:
    """A short warning when a report describes a scan that did not finish."""
    return " — STOPPED EARLY, this report is partial" if getattr(result, "interrupted", False) else ""


def _header_lines(result: ScanResult) -> List[str]:
    return [
        f"scope       : {result.scope_name}",
        f"authorized  : {result.authorization}",
        f"window      : {result.started} → {result.finished}",
        f"licence     : {result.license_tier}",
        f"hosts       : {len(result.hosts_up)} up of {result.hosts_total} in scope",
        f"checks      : {', '.join(result.checks_run) or 'none'}",
    ]


def format_text(result: ScanResult, colour: bool = False, minimum: Severity = Severity.INFO,
                show_skipped: bool = True) -> str:
    """The terminal report: header, findings worst-first, then the notes."""
    counts = result.counts(minimum)
    lines = [f"pentdeck {result.tool_version} — internal network assessment{_partial(result)}", ""]
    lines.extend(_header_lines(result))
    tally = "  ·  ".join(f"{counts[name]} {name}" for name in
                         ("critical", "high", "medium", "low", "info") if counts[name])
    lines += ["", f"findings    : {tally or 'none'}", ""]

    findings = result.sorted_findings(minimum)
    if not findings:
        lines.append("Nothing to report at this severity level.")
    for finding in findings:
        lines.append(finding.one_line(colour))
        if finding.detail:
            lines.append(f"         {finding.detail}")
        if finding.evidence:
            lines.append(f"         evidence: {finding.evidence}")
        if finding.remediation:
            lines.append(f"         fix: {finding.remediation}")
        lines.append("")

    if show_skipped and result.checks_skipped:
        lines.append("checks not run:")
        for name, reason in result.checks_skipped:
            lines.append(f"  {name:<20} {reason}")
        lines.append("")
    if result.errors:
        lines.append("errors:")
        for error in result.errors:
            lines.append(f"  {error}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_json(result: ScanResult) -> str:
    payload = result.as_dict()
    payload["generator"] = "pentdeck"
    return json.dumps(payload, indent=2, ensure_ascii=False)


def format_markdown(result: ScanResult, minimum: Severity = Severity.INFO) -> str:
    counts = result.counts(minimum)
    lines = [
        f"# {TITLE}{_partial(result)}",
        "",
        f"- **Scope:** {result.scope_name}",
        f"- **Authorization:** {result.authorization}",
        f"- **Window:** {result.started} → {result.finished}",
        f"- **Hosts:** {len(result.hosts_up)} up of {result.hosts_total} in scope",
        f"- **Checks run:** {', '.join(f'`{name}`' for name in result.checks_run)}",
        "",
        "| severity | count |",
        "| --- | --- |",
    ]
    for name in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {name} | {counts[name]} |")
    lines += ["", "## Findings", ""]

    findings = result.sorted_findings(minimum)
    if not findings:
        lines.append("Nothing to report at this severity level.")
    for finding in findings:
        lines.append(f"### {finding.severity.label} — {finding.title} "
                     f"({finding.target})")
        lines.append("")
        if finding.detail:
            lines.append(finding.detail)
            lines.append("")
        if finding.evidence:
            lines.append(f"Evidence: `{finding.evidence}`")
            lines.append("")
        if finding.remediation:
            lines.append(f"**Remediation:** {finding.remediation}")
            lines.append("")

    if result.checks_skipped:
        lines += ["## Checks not run", "", "| check | reason |", "| --- | --- |"]
        for name, reason in result.checks_skipped:
            lines.append(f"| `{name}` | {reason} |")
        lines.append("")
    if result.errors:
        lines += ["## Errors", ""]
        lines.extend(f"- `{error}`" for error in result.errors)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


_SEVERITY_COLOUR = {
    "critical": "#d2a8ff",
    "high": "#f85149",
    "medium": "#d29922",
    "low": "#58a6ff",
    "info": "#8b949e",
}


def format_html(result: ScanResult, minimum: Severity = Severity.INFO) -> str:
    """A report you can email. Self-contained: no requests, no scripts."""
    counts = result.counts(minimum)
    findings = result.sorted_findings(minimum)

    rows: List[str] = []
    for finding in findings:
        colour = _SEVERITY_COLOUR.get(finding.severity.value, "#8b949e")
        rows.append(f"""      <tr>
        <td><span class="sev" style="background:{colour}22;color:{colour};border-color:{colour}55">{html.escape(finding.severity.label)}</span></td>
        <td class="mono">{html.escape(finding.target)}</td>
        <td>
          <strong>{html.escape(finding.title)}</strong>
          {f'<div class="detail">{html.escape(finding.detail)}</div>' if finding.detail else ''}
          {f'<div class="evidence">evidence: {html.escape(finding.evidence)}</div>' if finding.evidence else ''}
          {f'<div class="fix"><b>Fix:</b> {html.escape(finding.remediation)}</div>' if finding.remediation else ''}
          <div class="check">check: {html.escape(finding.check)}</div>
        </td>
      </tr>""")

    skipped = "".join(
        f"<tr><td class='mono'>{html.escape(name)}</td><td>{html.escape(reason)}</td></tr>"
        for name, reason in result.checks_skipped
    )
    errors = "".join(f"<li class='mono'>{html.escape(error)}</li>" for error in result.errors)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(TITLE)} — {html.escape(result.scope_name)}</title>
<style>
  :root {{ --bg:#0d1117; --panel:#161b22; --edge:#30363d; --fg:#e6edf3; --dim:#8b949e; --accent:#58a6ff; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
         font:15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "DejaVu Sans", sans-serif; }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:40px 28px 70px; }}
  h1 {{ margin:0 0 6px; font-size:28px; letter-spacing:-.4px; }}
  h1 span {{ color:var(--accent); }}
  .sub {{ color:var(--dim); margin:0 0 26px; }}
  .meta {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:10px 22px;
           background:var(--panel); border:1px solid var(--edge); border-radius:12px; padding:18px 20px; margin-bottom:26px; }}
  .meta div {{ font-size:14px; }} .meta b {{ color:var(--dim); font-weight:600; display:block; font-size:12px;
           text-transform:uppercase; letter-spacing:.5px; }}
  .tally {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:22px; }}
  .tally span {{ border:1px solid var(--edge); border-radius:999px; padding:4px 12px; font-size:13px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--edge); border-radius:12px; overflow:hidden; }}
  th, td {{ text-align:left; padding:12px 14px; border-bottom:1px solid var(--edge); vertical-align:top; font-size:14px; }}
  th {{ background:#1c2129; color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
  tr:last-child td {{ border-bottom:none; }}
  .mono {{ font-family:ui-monospace, SFMono-Regular, "DejaVu Sans Mono", monospace; font-size:13px; }}
  .sev {{ display:inline-block; border:1px solid; border-radius:999px; padding:2px 9px; font-size:11px; font-weight:700; letter-spacing:.4px; }}
  .detail {{ color:var(--dim); margin-top:6px; }}
  .evidence {{ color:#7d8590; margin-top:6px; font-size:13px; font-family:ui-monospace, monospace; word-break:break-all; }}
  .fix {{ margin-top:8px; background:#0f1a12; border-left:3px solid #3fb950; padding:8px 10px; border-radius:0 6px 6px 0; font-size:13.5px; }}
  .check {{ color:#6e7681; font-size:12px; margin-top:8px; }}
  h2 {{ font-size:19px; margin:34px 0 12px; }}
  footer {{ margin-top:44px; padding-top:18px; border-top:1px solid var(--edge); color:var(--dim); font-size:13px; }}
  a {{ color:var(--accent); }}
</style>
</head>
<body>
<div class="wrap">
  <h1>pent<span>deck</span> — internal network assessment</h1>
  <p class="sub">Generated {html.escape(result.finished)} by pentdeck {html.escape(result.tool_version)}</p>

  <div class="meta">
    <div><b>Scope</b>{html.escape(result.scope_name)}</div>
    <div><b>Authorization</b>{html.escape(result.authorization)}</div>
    <div><b>Hosts up</b>{len(result.hosts_up)} of {result.hosts_total}</div>
    <div><b>Licence</b>{html.escape(result.license_tier)}</div>
    <div><b>Checks run</b>{html.escape(', '.join(result.checks_run)) or 'none'}</div>
    <div><b>Window</b>{html.escape(result.started)} → {html.escape(result.finished)}</div>
  </div>

  <div class="tally">
    <span>{counts['critical']} critical</span>
    <span>{counts['high']} high</span>
    <span>{counts['medium']} medium</span>
    <span>{counts['low']} low</span>
    <span>{counts['info']} info</span>
  </div>

  <table>
    <thead><tr><th style="width:96px">Severity</th><th style="width:180px">Target</th><th>Finding</th></tr></thead>
    <tbody>
{chr(10).join(rows) if rows else '      <tr><td colspan="3">Nothing to report at this severity level.</td></tr>'}
    </tbody>
  </table>

  {f'<h2>Checks not run</h2><table><tbody>{skipped}</tbody></table>' if skipped else ''}
  {f'<h2>Errors</h2><ul>{errors}</ul>' if errors else ''}

  <footer>
    Only systems listed in the scope were touched, and every action is recorded in
    <span class="mono">audit.jsonl</span>. Findings were not exploited: this report describes
    exposure, not proof of compromise.
    &nbsp;·&nbsp; <a href="https://github.com/sasoun1366/pentdeck">pentdeck</a>
  </footer>
</div>
</body>
</html>
"""


FORMATS = {
    "text": format_text,
    "json": format_json,
    "markdown": format_markdown,
    "html": format_html,
}
