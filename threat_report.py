"""
threat_report.py
────────────────
Generate a self-contained interactive HTML threat report from a threat model
produced by ``threat_modelling.generate_threat_model()``.

Public API
──────────
``generate_html_report(threats, output_path)``

CLI
───
    python threat_report.py <threats.json> <output.html>
"""

from __future__ import annotations

import html
import json
import sys
from collections import Counter
from pathlib import Path


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
       font-size: 14px; line-height: 1.6; background: #f7f8fa; color: #1f2328; }
.container { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
h1 { font-size: 1.5rem; margin-bottom: 4px; }
.subtitle { color: #57606a; margin-bottom: 24px; }

/* Summary cards */
.cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }
.card  { background: #fff; border: 1px solid #e5e7eb; border-radius: 6px;
         padding: 16px 20px; min-width: 140px; flex: 1; }
.card .label { font-size: 12px; color: #57606a; text-transform: uppercase;
               letter-spacing: .05em; margin-bottom: 4px; }
.card .value { font-size: 2rem; font-weight: 700; }
.card.high   .value { color: #b91c1c; }
.card.medium .value { color: #b45309; }
.card.low    .value { color: #15803d; }

/* Filter bar */
.filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
.filters input, .filters select {
  border: 1px solid #e5e7eb; border-radius: 4px;
  padding: 6px 10px; font-size: 13px; background: #fff; }
.filters input { flex: 1; min-width: 180px; }

/* Table */
table { width: 100%; border-collapse: collapse; background: #fff;
        border: 1px solid #e5e7eb; border-radius: 6px; overflow: hidden; }
thead th { background: #f0f2f5; padding: 10px 12px; text-align: left;
           font-size: 12px; text-transform: uppercase; letter-spacing: .05em;
           border-bottom: 1px solid #e5e7eb; cursor: pointer; user-select: none; }
tbody tr { border-bottom: 1px solid #f0f2f5; cursor: pointer; }
tbody tr:hover { background: #f7f8fa; }
tbody td { padding: 10px 12px; vertical-align: top; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px;
         font-size: 11px; font-weight: 600; }
.badge-High   { background: #fee2e2; color: #991b1b; }
.badge-Medium { background: #fef3c7; color: #92400e; }
.badge-Low    { background: #d1fae5; color: #065f46; }

/* Detail panel */
.detail-panel { display: none; background: #f7f8fa; border-top: 1px solid #e5e7eb;
                padding: 16px 20px; }
.detail-panel.open { display: block; }
.detail-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
               gap: 10px; margin-bottom: 12px; }
.bar-row { margin-bottom: 6px; }
.bar-label { font-size: 12px; color: #57606a; margin-bottom: 2px; }
.bar-track { background: #e5e7eb; border-radius: 3px; height: 10px; overflow: hidden; }
.bar-fill  { height: 10px; border-radius: 3px; background: #3b82d4; }
.section-title { font-size: 12px; font-weight: 600; text-transform: uppercase;
                 letter-spacing: .05em; color: #57606a; margin: 12px 0 4px; }
.mitigation-box { background: #fffbeb; border: 1px solid #fcd34d; border-radius: 4px;
                  padding: 10px 14px; font-size: 13px; margin-top: 10px; }
.mitigation-box .mit-label { font-weight: 600; color: #92400e;
                              margin-bottom: 4px; font-size: 11px;
                              text-transform: uppercase; letter-spacing: .05em; }
.ann-dict { font-family: monospace; font-size: 12px; background: #f0f2f5;
            border-radius: 4px; padding: 8px 10px; white-space: pre-wrap; }

/* Agents summary */
.agents-list { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 24px; }
.agent-chip   { background: #fff; border: 1px solid #e5e7eb; border-radius: 4px;
                padding: 4px 10px; font-size: 12px; }
.agent-chip strong { color: #3b82d4; }

footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e5e7eb;
         text-align: center; font-size: 12px; color: #57606a; }
"""

# ---------------------------------------------------------------------------
# JS (inline, no external deps)
# ---------------------------------------------------------------------------

_JS = r"""
const rows = document.querySelectorAll('tbody tr.data-row');

function applyFilters() {
  const level  = document.getElementById('filter-level').value.toLowerCase();
  const agent  = document.getElementById('filter-agent').value.toLowerCase();
  const search = document.getElementById('filter-search').value.toLowerCase();
  rows.forEach(row => {
    const rl = row.dataset.level.toLowerCase();
    const ra = row.dataset.agent.toLowerCase();
    const rt = row.dataset.text.toLowerCase();
    const show = (!level  || rl === level)
              && (!agent  || ra.includes(agent))
              && (!search || rt.includes(search));
    row.style.display = show ? '' : 'none';
    const detail = row.nextElementSibling;
    if (detail && detail.classList.contains('detail-panel')) {
      detail.style.display = show ? detail.style.display : 'none';
    }
  });
}

document.getElementById('filter-level').addEventListener('change', applyFilters);
document.getElementById('filter-agent').addEventListener('change', applyFilters);
document.getElementById('filter-search').addEventListener('input', applyFilters);

function toggleDetail(idx) {
  const panel = document.getElementById('panel-' + idx);
  if (panel) panel.classList.toggle('open');
}
"""

# ---------------------------------------------------------------------------
# HTML builder helpers
# ---------------------------------------------------------------------------


def _esc(s: object) -> str:
    return html.escape(str(s))


def _bar(label: str, value: float, max_val: float = 9.0) -> str:
    pct = min(100, round(value / max_val * 100))
    return (
        f'<div class="bar-row">'
        f'<div class="bar-label">{_esc(label)}: {value:.2f}</div>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div>'
        f'</div>'
    )


def _badge(level: str) -> str:
    return f'<span class="badge badge-{_esc(level)}">{_esc(level)}</span>'


def _annotation_dict(annotation: str) -> str:
    if not annotation:
        return "(none)"
    return annotation


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------


def _compute_summary(threats: list[dict]) -> dict:
    levels = Counter(t["level"] for t in threats)
    agents = Counter(t["agent_name"] for t in threats)
    tasks_by_score: dict[str, float] = {}
    for t in threats:
        name = t.get("task_name", t.get("task_id", "?"))
        tasks_by_score[name] = max(tasks_by_score.get(name, 0.0), t.get("score", 0.0))

    top_tasks = sorted(tasks_by_score.items(), key=lambda x: x[1], reverse=True)[:5]
    top_agents = agents.most_common(5)

    return {
        "total":      len(threats),
        "high":       levels.get("High", 0),
        "medium":     levels.get("Medium", 0),
        "low":        levels.get("Low", 0),
        "top_agents": top_agents,
        "top_tasks":  top_tasks,
    }


# ---------------------------------------------------------------------------
# HTML section builders
# ---------------------------------------------------------------------------


def _cards_html(summary: dict) -> str:
    return f"""
<div class="cards">
  <div class="card"><div class="label">Total Threats</div>
    <div class="value">{summary['total']}</div></div>
  <div class="card high"><div class="label">High Risk</div>
    <div class="value">{summary['high']}</div></div>
  <div class="card medium"><div class="label">Medium Risk</div>
    <div class="value">{summary['medium']}</div></div>
  <div class="card low"><div class="label">Low Risk</div>
    <div class="value">{summary['low']}</div></div>
</div>
"""


def _agents_html(top_agents: list) -> str:
    chips = "".join(
        f'<div class="agent-chip">{_esc(name)}: <strong>{count}</strong></div>'
        for name, count in top_agents
    )
    return (
        '<p class="section-title">Top Threat Agents</p>'
        f'<div class="agents-list">{chips}</div>'
    )


def _top_tasks_html(top_tasks: list) -> str:
    rows = "".join(
        f"<li>{_esc(name)} — score {score:.2f}</li>"
        for name, score in top_tasks
    )
    return (
        '<p class="section-title">Highest-Risk Tasks</p>'
        f'<ol style="padding-left:20px;margin-bottom:24px">{rows}</ol>'
    )


def _filter_bar_html(threats: list[dict]) -> str:
    agents = sorted({t["agent_name"] for t in threats})
    options = "".join(f'<option value="{_esc(a)}">{_esc(a)}</option>' for a in agents)
    return f"""
<div class="filters">
  <input id="filter-search" type="text" placeholder="Search threats, tasks, agents…" />
  <select id="filter-level">
    <option value="">All Levels</option>
    <option value="High">High</option>
    <option value="Medium">Medium</option>
    <option value="Low">Low</option>
  </select>
  <select id="filter-agent">
    <option value="">All Agents</option>
    {options}
  </select>
</div>
"""


def _detail_panel_html(idx: int, t: dict) -> str:
    mit = t.get("mitigation", "")
    mit_html = (
        f'<div class="mitigation-box">'
        f'<div class="mit-label">Recommended Mitigation</div>'
        f'{_esc(mit)}'
        f'</div>'
    ) if mit else ""

    bars = (
        _bar("Likelihood",        t.get("likelihood", 0))
        + _bar("LoC",             t.get("loc", 0))
        + _bar("LoI",             t.get("loi", 0))
        + _bar("LoA",             t.get("loa", 0))
        + _bar("LoAc",            t.get("loac", 0))
        + _bar("Technical Impact",t.get("technical_impact", 0))
        + _bar("Risk Score",      t.get("score", 0))
    )

    task_ann = _esc(_annotation_dict(t.get("task_annotation", "")))

    return f"""
<tr id="panel-{idx}" class="detail-panel">
  <td colspan="6">
    <p class="section-title">Threat: {_esc(t['threat'])}</p>
    <p style="margin-bottom:10px">{_esc(t.get('behaviour',''))}</p>
    {mit_html}
    <p class="section-title" style="margin-top:12px">OWASP Risk Components</p>
    {bars}
    <p class="section-title">Task Annotations</p>
    <div class="ann-dict">{task_ann}</div>
  </td>
</tr>
"""


def _table_html(threats: list[dict]) -> str:
    header = """
<thead><tr>
  <th>#</th>
  <th>Level</th>
  <th>Score</th>
  <th>Agent</th>
  <th>Task</th>
  <th>Threat</th>
</tr></thead>
"""
    body_rows = []
    for i, t in enumerate(threats):
        task_name  = _esc(t.get("task_name") or t.get("task_id", ""))
        agent_name = _esc(t.get("agent_name", ""))
        threat     = _esc(t.get("threat", ""))
        level      = t.get("level", "Low")
        score      = t.get("score", 0.0)
        search_text = f"{task_name} {agent_name} {threat} {level}"

        row = (
            f'<tr class="data-row" data-level="{_esc(level)}" '
            f'data-agent="{agent_name}" data-text="{search_text}" '
            f'onclick="toggleDetail({i})">'
            f'<td>{i+1}</td>'
            f'<td>{_badge(level)}</td>'
            f'<td>{score:.2f}</td>'
            f'<td>{agent_name}</td>'
            f'<td>{task_name}</td>'
            f'<td>{threat}</td>'
            f'</tr>'
        )
        detail = _detail_panel_html(i, t)
        body_rows.append(row + detail)

    return f"<table>{header}<tbody>{''.join(body_rows)}</tbody></table>"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_html_report(
    threats: list[dict],
    output_path: str | Path,
) -> None:
    """Write a self-contained HTML threat report to *output_path*.

    Parameters
    ----------
    threats:
        List of threat entry dicts (output of
        ``threat_modelling.generate_threat_model()``).
    output_path:
        Destination HTML file path.
    """
    summary = _compute_summary(threats)

    body = f"""
<div class="container">
  <h1>BPMN Security Risk &amp; Privacy Analysis</h1>
  <p class="subtitle">Threat Model Report — {len(threats)} threat entries identified</p>

  {_cards_html(summary)}
  {_agents_html(summary['top_agents'])}
  {_top_tasks_html(summary['top_tasks'])}
  {_filter_bar_html(threats)}
  {_table_html(threats)}

  <footer>Made with IBM Bob</footer>
</div>
"""

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>BPMN Threat Model Report</title>
  <style>{_CSS}</style>
</head>
<body>
{body}
<script>{_JS}</script>
</body>
</html>
"""

    Path(output_path).write_text(html_doc, encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python threat_report.py <threats.json> <output.html>",
              file=sys.stderr)
        sys.exit(1)

    threats_path = Path(sys.argv[1])
    output_path  = Path(sys.argv[2])

    threats = json.loads(threats_path.read_text(encoding="utf-8"))
    generate_html_report(threats, output_path)
    print(f"Report written to {output_path} ({len(threats)} threat entries).")
