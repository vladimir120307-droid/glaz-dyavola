"""Smoke-тесты для валидаторов: проверяем структуру результатов и
правильное формирование Finding'ов. Реальный сетевой вызов не делаем —
это смотрело бы интеграционный тест."""
from __future__ import annotations

from glaz.modules.validators.runner import (
    VALIDATORS,
    ValidationResult,
    validate_to_finding,
)


def test_validators_registry() -> None:
    """В реестре все 10 валидаторов."""
    expected = {"aws", "github", "gitlab", "slack", "anthropic", "openai",
                "postman", "atlassian", "datadog", "npm"}
    assert expected.issubset(set(VALIDATORS.keys()))


def test_unknown_provider_returns_invalid() -> None:
    import asyncio

    from glaz.modules.validators.runner import validate
    result = asyncio.run(validate("nonexistent", token="x"))
    assert not result.valid
    assert "Unknown" in result.error


def test_valid_to_finding_marks_critical() -> None:
    """Валидный токен → CRITICAL + CONFIRMED."""
    res = ValidationResult("github", True, identity="testuser",
                           scopes=["repo", "user"], raw={"login": "testuser"})
    # Эмулируем валидатор — патчим, без сети
    import asyncio

    from glaz.modules.validators import runner

    async def _fake(*_a, **_kw):
        return res

    runner.VALIDATORS["__test_provider__"] = _fake
    try:
        f = asyncio.run(validate_to_finding("__test_provider__", target="repo.git", token="x"))
        # Текущий код использует VALIDATOR_<provider.upper()>_LIVE
        assert f.severity.value == "critical"
        assert "testuser" in f.title
        assert f.confidence.value == "confirmed"
    finally:
        runner.VALIDATORS.pop("__test_provider__")


def test_invalid_to_finding_marks_info() -> None:
    res = ValidationResult("github", False, error="HTTP 401")
    import asyncio

    from glaz.modules.validators import runner

    async def _fake(*_a, **_kw):
        return res

    runner.VALIDATORS["__test_invalid__"] = _fake
    try:
        f = asyncio.run(validate_to_finding("__test_invalid__", target="x", token="x"))
        assert f.severity.value == "info"
        assert "HTTP 401" in str(f.evidence.get("error"))
    finally:
        runner.VALIDATORS.pop("__test_invalid__")
