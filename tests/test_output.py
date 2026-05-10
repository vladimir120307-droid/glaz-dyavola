import json
from pathlib import Path

from glaz.core.findings import Confidence, Finding, FindingCollection, Severity
from glaz.core.output import OutputFormat, to_sarif, write_report


def _sample() -> FindingCollection:
    coll = FindingCollection()
    coll.add(Finding(
        rule_id="TEST_RULE_1", title="Test rule 1",
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        target="example.com", module="test",
        evidence={"key": "abc", "match": "AKIAIOSFODNN7EXAMPLE"},
    ))
    coll.add(Finding(
        rule_id="TEST_RULE_2", title="Test rule 2",
        severity=Severity.LOW, confidence=Confidence.MEDIUM,
        target="example.com", module="test",
        evidence={"key": "xyz"},
    ))
    return coll


def test_sarif_structure() -> None:
    coll = _sample()
    sarif = to_sarif(coll)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "glaz-dyavola"
    assert len(run["results"]) == 2
    assert {r["ruleId"] for r in run["results"]} == {"TEST_RULE_1", "TEST_RULE_2"}


def test_write_json(tmp_path: Path) -> None:
    coll = _sample()
    p = tmp_path / "out.json"
    write_report(p, coll, fmt=OutputFormat.JSON)
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["tool"] == "glaz-dyavola"
    assert data["stats"]["total"] == 2
    assert data["stats"]["high"] == 1


def test_write_jsonl(tmp_path: Path) -> None:
    coll = _sample()
    p = tmp_path / "out.jsonl"
    write_report(p, coll, fmt=OutputFormat.JSONL)
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    for ln in lines:
        json.loads(ln)  # должно быть валидным JSON


def test_write_sarif_via_extension(tmp_path: Path) -> None:
    coll = _sample()
    p = tmp_path / "out.sarif"
    write_report(p, coll)  # формат определяется по расширению
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"


def test_html_render(tmp_path: Path) -> None:
    coll = _sample()
    p = tmp_path / "out.html"
    write_report(p, coll, fmt=OutputFormat.HTML)
    html = p.read_text(encoding="utf-8")
    assert "Глаз Дьявола" in html
    assert "TEST_RULE_1" in html
