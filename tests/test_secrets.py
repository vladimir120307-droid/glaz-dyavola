"""Тесты сканера секретов: попадания, не-попадания, энтропия, дедуп."""
from __future__ import annotations

import pytest

from glaz.core.findings import FindingCollection
from glaz.modules.secrets import scan_text
from glaz.modules.secrets.scanner import to_findings

# ============== Positive tests ==============

@pytest.mark.parametrize("text,rule_id", [
    ("AKIAIOSFODNN7EXAMPLE", "SECRET_AWS_ACCESS_KEY"),
    ("ASIAQQQQQQQQQQQQQQQQ", "SECRET_AWS_ACCESS_KEY"),
    ("ghp_aabbccddeeffgghhiijjkkllmmnnooppqqrr", "SECRET_GH_PAT_CLASSIC"),
    ("github_pat_" + "A" * 82, "SECRET_GH_PAT_FINEGRAINED"),
    ("glpat-AbCd_-1234567890XYZabcde", "SECRET_GITLAB_PAT"),  # 24 chars after glpat-
    ("xoxb-1234567890-abcdefghijkl", "SECRET_SLACK_TOKEN"),
    ("https://hooks.slack.com/services/T00000000/B00000000/abcdefghij1234567890", "SECRET_SLACK_WEBHOOK"),
    # Намеренно НЕ-валидная синтетика (24 'X' — низкая энтропия, GitHub
    # secret-scanning не блочит, наш regex `\bsk_live_[0-9A-Za-z]{24,}\b` ловит).
    ("sk_live_" + "X" * 24, "SECRET_STRIPE_LIVE"),
    ("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456", "SECRET_GOOGLE_API_KEY"),  # AIza + 35 chars
    ("hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "SECRET_HUGGINGFACE"),
    ("y0_AgAAABBpqXabAATuwQAAAADxxxxxxx_xxxxxxxxxxxxx", "SECRET_YANDEX_OAUTH"),
    ("npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "SECRET_NPM_TOKEN"),
    ("pplx-abcdefghijklmnopqrstuvwxyz0123456789ABCD", "SECRET_PERPLEXITY"),
    ("gsk_" + "a" * 50, "SECRET_GROQ"),
    ("dop_v1_" + "f" * 64, "SECRET_DIGITALOCEAN"),
    ("dckr_pat_aBcDeFgHiJkLmNoPqRsTuVwXyZ123", "SECRET_DOCKER_HUB_PAT"),  # 29 chars after dckr_pat_
])
def test_pattern_matches(text: str, rule_id: str) -> None:
    hits = [h for h in scan_text(text) if h.rule_id == rule_id]
    assert hits, f"Expected {rule_id} match in {text!r}"


def test_anthropic_match() -> None:
    fake = "sk-ant-api03-" + "a" * 95
    hits = [h for h in scan_text(fake) if h.rule_id == "SECRET_ANTHROPIC_API"]
    assert hits


def test_jwt_match() -> None:
    fake = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
    )
    hits = [h for h in scan_text(fake) if h.rule_id == "SECRET_JWT"]
    assert hits


def test_private_key_match() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
    hits = [h for h in scan_text(text) if h.rule_id == "SECRET_RSA_PRIVKEY"]
    assert hits


# ============== Negative tests (entropy / no-match) ==============

def test_low_entropy_generic_filtered() -> None:
    """Низкоэнтропийный 'apikey: aaaaaaaaaaaaaaaaaaaaaaaa' не должен срабатывать."""
    text = 'apikey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
    hits = [h for h in scan_text(text) if h.rule_id == "SECRET_GENERIC_API_KEY"]
    assert not hits, "Low-entropy generic should be filtered"


def test_high_entropy_generic_kept() -> None:
    text = 'apikey: "aB9_-cD4xYzMnOpQrStUvWxYz09876543"'
    hits = [h for h in scan_text(text) if h.rule_id == "SECRET_GENERIC_API_KEY"]
    assert hits, "High-entropy generic should be kept"


def test_random_words_no_match() -> None:
    text = "Hello world this is just regular text with no secrets at all"
    hits = list(scan_text(text))
    assert not hits


# ============== Dedup ==============

def test_finding_dedup() -> None:
    text = "AKIAIOSFODNN7EXAMPLE\nAKIAIOSFODNN7EXAMPLE\nAKIAIOSFODNN7EXAMPLE"
    hits = list(scan_text(text, source="test.txt"))
    finds = to_findings(hits)
    coll = FindingCollection()
    coll.extend(finds)
    # Те же hits в том же source должны дедупаться по fingerprint
    assert len(coll) == 1, f"Expected 1 unique, got {len(coll)}"


def test_finding_different_sources_no_dedup() -> None:
    """Одинаковый секрет, найденный в разных файлах — это разные находки."""
    text = "AKIAIOSFODNN7EXAMPLE"
    hits1 = list(scan_text(text, source="a.txt"))
    hits2 = list(scan_text(text, source="b.txt"))
    finds = to_findings(hits1) + to_findings(hits2)
    coll = FindingCollection()
    coll.extend(finds)
    assert len(coll) == 2, "Same match in different sources should produce 2 findings"


# ============== Multi-hit ==============

def test_multiple_secrets_in_one_text() -> None:
    text = "AKIAIOSFODNN7EXAMPLE and ghp_aabbccddeeffgghhiijjkkllmmnnooppqqrr"
    hits = list(scan_text(text))
    rules = {h.rule_id for h in hits}
    assert "SECRET_AWS_ACCESS_KEY" in rules
    assert "SECRET_GH_PAT_CLASSIC" in rules
