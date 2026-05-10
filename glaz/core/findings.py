"""Модель находок: severity + confidence + evidence."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def severity_rank(s: Severity) -> int:
    return _SEVERITY_RANK[s]


class Finding(BaseModel):
    """Одна находка. Идемпотентный хеш по (rule_id, target, evidence_key)."""

    rule_id: str = Field(..., description="Стабильный идентификатор правила, e.g. SECRET_AWS_ACCESS_KEY")
    title: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    target: str = Field(..., description="Что обследовали (домен, URL, файл)")
    module: str = Field(..., description="Модуль-источник: dns, secrets, ru.egrul, ...")
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: list[str] = Field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Стабильный хеш для дедупликации."""
        evidence_key = self.evidence.get("key") or self.evidence.get("match") or ""
        raw = f"{self.rule_id}|{self.target}|{evidence_key}".encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def model_dump_serializable(self) -> dict[str, Any]:
        d = self.model_dump(mode="json")
        d["fingerprint"] = self.fingerprint
        return d


class FindingCollection:
    """Коллекция находок с автодедупом по fingerprint."""

    def __init__(self) -> None:
        self._by_fp: dict[str, Finding] = {}

    def add(self, finding: Finding) -> bool:
        """Добавить. Возвращает True если новая (не дубль), False если уже была."""
        fp = finding.fingerprint
        if fp in self._by_fp:
            return False
        self._by_fp[fp] = finding
        return True

    def extend(self, findings: list[Finding]) -> int:
        """Добавить пачку. Возвращает количество реально добавленных."""
        return sum(1 for f in findings if self.add(f))

    def all(self) -> list[Finding]:
        return list(self._by_fp.values())

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self._by_fp.values() if f.severity == severity]

    def sorted_by_severity(self) -> list[Finding]:
        return sorted(self._by_fp.values(), key=lambda f: -severity_rank(f.severity))

    def __len__(self) -> int:
        return len(self._by_fp)

    def __iter__(self):
        return iter(self._by_fp.values())

    def stats(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self._by_fp.values():
            out[f.severity.value] += 1
        out["total"] = len(self._by_fp)
        return out
