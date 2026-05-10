"""Сериализация отчёта в JSON / JSONL / SARIF / HTML."""
from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any

from glaz.core.asset_graph import AssetGraph
from glaz.core.findings import FindingCollection, Severity


class OutputFormat(str, Enum):
    JSON = "json"
    JSONL = "jsonl"
    SARIF = "sarif"
    HTML = "html"


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(findings: FindingCollection, tool_name: str = "glaz-dyavola") -> dict[str, Any]:
    """SARIF 2.1.0 — для интеграции с CI (GitHub code scanning, etc)."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {"severity": f.severity.value, "tags": ["security", f.module]},
            }

        loc_uri = f.evidence.get("source") or f.target
        line = f.evidence.get("line") or 1
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(loc_uri)},
                            "region": {"startLine": line},
                        }
                    }
                ],
                "properties": {
                    "confidence": f.confidence.value,
                    "module": f.module,
                    "fingerprint": f.fingerprint,
                    **{k: v for k, v in f.evidence.items() if k not in ("source", "line")},
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/vladimir/glaz-dyavola",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def to_html(findings: FindingCollection, graph: AssetGraph | None = None) -> str:
    """Простой HTML-отчёт без внешних зависимостей."""
    stats = findings.stats()
    rows = []
    for f in findings.sorted_by_severity():
        evidence_short = json.dumps(f.evidence, ensure_ascii=False)[:200]
        rows.append(
            f"<tr class='sev-{f.severity.value}'>"
            f"<td>{f.severity.value.upper()}</td>"
            f"<td>{f.confidence.value}</td>"
            f"<td>{f.module}</td>"
            f"<td>{f.rule_id}</td>"
            f"<td>{f.target}</td>"
            f"<td>{f.title}</td>"
            f"<td><code>{evidence_short}</code></td>"
            f"</tr>"
        )

    asset_count = len(graph) if graph else 0

    return f"""<!doctype html>
<html lang="ru">
<head><meta charset="utf-8"><title>Глаз Дьявола — отчёт</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1280px;margin:2rem auto;padding:0 1rem;background:#0f172a;color:#f1f5f9}}
h1{{color:#dc2626}}
.stats{{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}}
.stat{{padding:0.6rem 1rem;border-radius:6px;background:#1e293b;border:1px solid #334155}}
.stat strong{{color:#fbbf24;font-size:1.4rem;display:block}}
table{{width:100%;border-collapse:collapse;margin-top:1rem;background:#1e293b}}
th,td{{padding:0.4rem 0.6rem;border:1px solid #334155;text-align:left;vertical-align:top;font-size:0.9rem}}
th{{background:#0f172a;color:#fbbf24}}
.sev-critical td:first-child{{background:#7f1d1d;color:#fff;font-weight:bold}}
.sev-high td:first-child{{background:#dc2626;color:#fff;font-weight:bold}}
.sev-medium td:first-child{{background:#f59e0b;color:#000}}
.sev-low td:first-child{{background:#3b82f6;color:#fff}}
.sev-info td:first-child{{background:#64748b;color:#fff}}
code{{font-family:ui-monospace,monospace;color:#a5f3fc;word-break:break-all}}
</style></head>
<body>
<h1>🦅 Глаз Дьявола — отчёт</h1>
<div class="stats">
  <div class="stat"><strong>{stats["total"]}</strong>всего находок</div>
  <div class="stat"><strong>{stats["critical"]}</strong>critical</div>
  <div class="stat"><strong>{stats["high"]}</strong>high</div>
  <div class="stat"><strong>{stats["medium"]}</strong>medium</div>
  <div class="stat"><strong>{stats["low"]}</strong>low</div>
  <div class="stat"><strong>{stats["info"]}</strong>info</div>
  <div class="stat"><strong>{asset_count}</strong>активов в графе</div>
</div>
<table>
<thead><tr><th>Sev</th><th>Conf</th><th>Module</th><th>Rule</th><th>Target</th><th>Title</th><th>Evidence</th></tr></thead>
<tbody>
{"".join(rows)}
</tbody></table>
</body></html>
"""


def write_report(
    path: str | Path,
    findings: FindingCollection,
    graph: AssetGraph | None = None,
    fmt: OutputFormat | None = None,
) -> Path:
    """Сериализовать находки + граф. Формат определяется по расширению, либо через fmt."""
    p = Path(path)
    if fmt is None:
        ext = p.suffix.lower().lstrip(".")
        try:
            fmt = OutputFormat(ext)
        except ValueError:
            fmt = OutputFormat.JSON

    if fmt == OutputFormat.JSONL:
        with p.open("w", encoding="utf-8") as fh:
            for f in findings:
                fh.write(json.dumps(f.model_dump_serializable(), ensure_ascii=False) + "\n")
    elif fmt == OutputFormat.SARIF:
        p.write_text(json.dumps(to_sarif(findings), ensure_ascii=False, indent=2), encoding="utf-8")
    elif fmt == OutputFormat.HTML:
        p.write_text(to_html(findings, graph), encoding="utf-8")
    else:  # JSON
        report = {
            "tool": "glaz-dyavola",
            "version": "0.1.0",
            "findings": [f.model_dump_serializable() for f in findings.sorted_by_severity()],
            "stats": findings.stats(),
            "graph": graph.to_dict() if graph else None,
        }
        p.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    return p
