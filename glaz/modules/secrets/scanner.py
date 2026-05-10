"""Сканер секретов v2.

Улучшения над базовой версией:
- 65+ regex-паттернов (см. patterns.py), включая AI/LLM 2026 и RU-сегмент
- Шеннон-энтропия как фильтр ложных срабатываний
- baseline (.glaz-baseline) для подавления известных false-positive по fingerprint
- параллельный обход директорий (multiprocessing)
- дедуп через FindingCollection
- интеграция с asset_graph (находки добавляют узлы типа SECRET)
"""
from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from glaz.core.asset_graph import Asset, AssetGraph, AssetType, Edge
from glaz.core.findings import Confidence, Finding, FindingCollection, Severity
from glaz.modules.secrets.patterns import PATTERNS, SecretPattern
from glaz.utils.entropy import shannon_entropy

SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".cache", ".tox", "target", ".next", ".nuxt",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", "htmlcov", "coverage",
})

SKIP_EXTS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".webm", ".wav", ".ogg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".class", ".pyc", ".pyo", ".o", ".so", ".dll", ".exe", ".dylib",
})

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


@dataclass(frozen=True)
class SecretFinding:
    """Срез данных, удобный для возврата из подпроцессов (Pickle-friendly)."""
    rule_id: str
    severity: str
    category: str
    title: str
    match: str
    line: int
    source: str
    entropy: float


def _compile_patterns(patterns: list[SecretPattern]) -> list[tuple[SecretPattern, re.Pattern]]:
    return [(p, re.compile(p.regex)) for p in patterns]


_COMPILED = _compile_patterns(PATTERNS)


def _passes_entropy(pattern: SecretPattern, m: re.Match) -> tuple[bool, float]:
    """Проверка минимальной энтропии. Возвращает (passes, entropy_value)."""
    if pattern.min_entropy <= 0:
        return True, 0.0
    try:
        token = m.group(pattern.entropy_group) if pattern.entropy_group else m.group(0)
    except IndexError:
        token = m.group(0)
    ent = shannon_entropy(token)
    return ent >= pattern.min_entropy, ent


def scan_text(text: str, source: str = "<stdin>") -> Iterator[SecretFinding]:
    """Сканировать строку. Yield-ит SecretFinding по каждому совпадению."""
    for line_no, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4096:  # пропустим экстремально длинные строки (минифицированный JS)
            continue
        for pattern, rx in _COMPILED:
            for m in rx.finditer(line):
                ok, ent = _passes_entropy(pattern, m)
                if not ok:
                    continue
                yield SecretFinding(
                    rule_id=pattern.rule_id,
                    severity=pattern.severity.value,
                    category=pattern.category,
                    title=pattern.description or pattern.rule_id,
                    match=m.group(0)[:120],
                    line=line_no,
                    source=source,
                    entropy=round(ent, 2),
                )


def _should_skip(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXTS:
        return True
    parts = set(path.parts)
    return any(d in parts for d in SKIP_DIRS)


def _scan_file(path_str: str) -> list[SecretFinding]:
    p = Path(path_str)
    try:
        if p.stat().st_size > MAX_FILE_SIZE:
            return []
        text = p.read_text(errors="replace")
    except OSError:
        return []
    return list(scan_text(text, source=str(p)))


def _walk_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        if not _should_skip(root):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        # Inplace prune SKIP_DIRS for efficiency
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            p = Path(dirpath) / fname
            if not _should_skip(p):
                yield p


def scan_path(
    root: str | Path,
    *,
    workers: int = 1,
    baseline: set[str] | None = None,
) -> Iterator[SecretFinding]:
    """Рекурсивный обход. workers > 1 включает мультипроцессинг.

    baseline — множество fingerprint'ов (16-hex), которые надо подавить
    (используется для игнора известных false-positive, см. .glaz-baseline).
    """
    root_p = Path(root)
    files = list(_walk_files(root_p))

    if workers <= 1 or len(files) < 50:
        for f in files:
            for hit in _scan_file(str(f)):
                if baseline and _hit_fingerprint(hit) in baseline:
                    continue
                yield hit
        return

    with ProcessPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_scan_file, str(f)): f for f in files}
        for fut in as_completed(futures):
            for hit in fut.result():
                if baseline and _hit_fingerprint(hit) in baseline:
                    continue
                yield hit


def _hit_fingerprint(hit: SecretFinding) -> str:
    import hashlib
    raw = f"{hit.rule_id}|{hit.source}|{hit.match}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def to_findings(hits: list[SecretFinding], graph: AssetGraph | None = None) -> list[Finding]:
    """Конвертировать SecretFinding в общие Finding-объекты + (опц.) добавить
    узлы в граф."""
    out: list[Finding] = []
    for h in hits:
        f = Finding(
            rule_id=h.rule_id,
            title=h.title,
            severity=Severity(h.severity),
            confidence=Confidence.HIGH if h.entropy >= 4.5 or h.entropy == 0 else Confidence.MEDIUM,
            target=h.source,
            module="secrets",
            description=f"Найден секрет категории {h.category} на строке {h.line}",
            evidence={
                "match": h.match,
                "line": h.line,
                "source": h.source,
                "category": h.category,
                "entropy": h.entropy,
                "key": h.match,
            },
            tags=["secret", h.category],
        )
        out.append(f)

        if graph is not None:
            secret_id = Asset.make_id(AssetType.SECRET, f.fingerprint)
            graph.add_asset(Asset(
                id=secret_id,
                type=AssetType.SECRET,
                value=h.match,
                attributes={"category": h.category, "rule_id": h.rule_id, "entropy": h.entropy},
                discovered_by="secrets",
            ))
            file_id = Asset.make_id(AssetType.FILE, h.source)
            graph.add_asset(Asset(
                id=file_id, type=AssetType.FILE, value=h.source, discovered_by="secrets",
            ))
            graph.add_edge(Edge(
                subject=secret_id, relation="found_in", object=file_id, discovered_by="secrets",
            ))
    return out


def load_baseline(path: str | Path) -> set[str]:
    """Загрузить baseline из JSON или текстового файла (один fingerprint в строке)."""
    p = Path(path)
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return {str(x) for x in data}
        if isinstance(data, dict) and "fingerprints" in data:
            return set(data["fingerprints"])
    except json.JSONDecodeError:
        pass
    return {ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")}


def write_baseline(path: str | Path, findings: FindingCollection) -> Path:
    """Записать текущие fingerprint'ы как baseline (подавит их в следующих запусках)."""
    p = Path(path)
    data = {
        "version": 1,
        "tool": "glaz-dyavola",
        "fingerprints": sorted({f.fingerprint for f in findings}),
    }
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return p
