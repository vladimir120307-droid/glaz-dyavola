"""Read-only валидаторы найденных кредов.

Принцип: каждый валидатор бьёт по `whoami` / `getCallerIdentity` / `auth.test` —
эндпоинт, не модифицирующий состояние и не читающий данные шире, чем «кому
принадлежит этот токен».

Цель — отвечать на вопрос «найденный секрет живой или протух?» — это
переводит находку из MEDIUM в CONFIRMED HIGH/CRITICAL и сильно меняет
приоритет в BB-отчёте.

Покрытие (9 валидаторов):
- AWS (sts:GetCallerIdentity)
- GitHub (/user)
- GitLab (/api/v4/user)
- Slack (auth.test)
- Anthropic (/v1/messages dry с малым max_tokens — единственный auth-эндпоинт)
- OpenAI (/v1/models — самый дешёвый GET)
- Postman (/me)
- Atlassian (/rest/api/3/myself)
- Datadog (/api/v1/validate)
- npm (/-/whoami)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

import httpx

from glaz.core.findings import Confidence, Finding, Severity
from glaz.utils.http import get_async_client


@dataclass
class ValidationResult:
    provider: str
    valid: bool
    identity: str | None = None
    scopes: list[str] | None = None
    raw: dict[str, Any] | None = None
    error: str | None = None


# ============== Validators ==============


async def _validate_aws(client: httpx.AsyncClient, access_key: str, secret_key: str, session_token: str | None = None) -> ValidationResult:
    """sts:GetCallerIdentity. Возвращает ARN/account/UserId. Read-only."""
    import datetime as dt
    region = "us-east-1"
    service = "sts"
    host = "sts.amazonaws.com"
    amz_date = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    date_stamp = amz_date[:8]

    canonical_uri = "/"
    canonical_querystring = "Action=GetCallerIdentity&Version=2011-06-15"
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_headers = (
        f"host:{host}\n"
        f"x-amz-date:{amz_date}\n"
        + (f"x-amz-security-token:{session_token}\n" if session_token else "")
    )
    signed_headers = "host;x-amz-date" + (";x-amz-security-token" if session_token else "")
    canonical_request = (
        f"GET\n{canonical_uri}\n{canonical_querystring}\n"
        f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )
    k_date = hmac.new(("AWS4" + secret_key).encode(), date_stamp.encode(), hashlib.sha256).digest()
    k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode(), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth_header = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    headers = {"Authorization": auth_header, "x-amz-date": amz_date}
    if session_token:
        headers["x-amz-security-token"] = session_token

    try:
        r = await client.get(f"https://{host}/?{canonical_querystring}", headers=headers, timeout=10.0)
    except httpx.HTTPError as e:
        return ValidationResult("aws", False, error=str(e))

    if r.status_code != 200:
        return ValidationResult("aws", False, error=f"HTTP {r.status_code}", raw={"body": r.text[:300]})
    import re
    arn = re.search(r"<Arn>([^<]+)</Arn>", r.text)
    account = re.search(r"<Account>([^<]+)</Account>", r.text)
    user_id = re.search(r"<UserId>([^<]+)</UserId>", r.text)
    return ValidationResult(
        "aws", True,
        identity=arn.group(1) if arn else None,
        raw={
            "arn": arn.group(1) if arn else None,
            "account": account.group(1) if account else None,
            "user_id": user_id.group(1) if user_id else None,
        },
    )


async def _validate_github(client: httpx.AsyncClient, token: str) -> ValidationResult:
    """GitHub /user. Также вытаскиваем X-OAuth-Scopes."""
    try:
        r = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        return ValidationResult("github", False, error=str(e))
    if r.status_code != 200:
        return ValidationResult("github", False, error=f"HTTP {r.status_code}")
    data = r.json()
    scopes = r.headers.get("x-oauth-scopes", "")
    return ValidationResult(
        "github", True,
        identity=data.get("login"),
        scopes=[s.strip() for s in scopes.split(",") if s.strip()],
        raw={"login": data.get("login"), "id": data.get("id"), "type": data.get("type"),
             "rate_limit_remaining": r.headers.get("x-ratelimit-remaining")},
    )


async def _validate_gitlab(client: httpx.AsyncClient, token: str, host: str = "gitlab.com") -> ValidationResult:
    try:
        r = await client.get(
            f"https://{host}/api/v4/user",
            headers={"PRIVATE-TOKEN": token},
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        return ValidationResult("gitlab", False, error=str(e))
    if r.status_code != 200:
        return ValidationResult("gitlab", False, error=f"HTTP {r.status_code}")
    data = r.json()
    return ValidationResult("gitlab", True, identity=data.get("username"),
                            raw={"username": data.get("username"), "id": data.get("id"),
                                 "is_admin": data.get("is_admin")})


async def _validate_slack(client: httpx.AsyncClient, token: str) -> ValidationResult:
    """auth.test — единственный read-only auth-эндпоинт у Slack."""
    try:
        r = await client.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        return ValidationResult("slack", False, error=str(e))
    data = r.json() if r.status_code == 200 else {}
    if not data.get("ok"):
        return ValidationResult("slack", False, error=data.get("error", "unknown"))
    return ValidationResult("slack", True, identity=data.get("user"),
                            raw={"team": data.get("team"), "user": data.get("user"),
                                 "team_id": data.get("team_id"), "url": data.get("url")})


async def _validate_anthropic(client: httpx.AsyncClient, key: str) -> ValidationResult:
    """Anthropic не имеет /me — используем /v1/messages с минимальным запросом
    и читаем заголовки (response не сохраняем). Это всё ещё read-only с точки
    зрения идентификации, но строго говоря тратит 1 input token.
    """
    try:
        r = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={"model": "claude-haiku-4-5", "max_tokens": 1,
                  "messages": [{"role": "user", "content": "."}]},
            timeout=15.0,
        )
    except httpx.HTTPError as e:
        return ValidationResult("anthropic", False, error=str(e))
    if r.status_code in (200, 400):  # 400 если модель неверная — но ключ валиден
        org = r.headers.get("anthropic-organization-id")
        return ValidationResult("anthropic", True, identity=org,
                                raw={"organization_id": org, "status": r.status_code})
    return ValidationResult("anthropic", False, error=f"HTTP {r.status_code}: {r.text[:200]}")


async def _validate_openai(client: httpx.AsyncClient, key: str) -> ValidationResult:
    try:
        r = await client.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        return ValidationResult("openai", False, error=str(e))
    if r.status_code != 200:
        return ValidationResult("openai", False, error=f"HTTP {r.status_code}")
    data = r.json()
    org = r.headers.get("openai-organization")
    return ValidationResult("openai", True, identity=org,
                            raw={"organization": org, "models_count": len(data.get("data", []))})


async def _validate_postman(client: httpx.AsyncClient, key: str) -> ValidationResult:
    try:
        r = await client.get(
            "https://api.getpostman.com/me",
            headers={"X-Api-Key": key},
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        return ValidationResult("postman", False, error=str(e))
    if r.status_code != 200:
        return ValidationResult("postman", False, error=f"HTTP {r.status_code}")
    data = r.json().get("user", {})
    return ValidationResult("postman", True, identity=data.get("username"),
                            raw=data)


async def _validate_atlassian(client: httpx.AsyncClient, email: str, token: str, host: str) -> ValidationResult:
    """Atlassian требует email + API token + хост (subdomain.atlassian.net)."""
    import base64
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    try:
        r = await client.get(
            f"https://{host}/rest/api/3/myself",
            headers={"Authorization": f"Basic {auth}", "Accept": "application/json"},
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        return ValidationResult("atlassian", False, error=str(e))
    if r.status_code != 200:
        return ValidationResult("atlassian", False, error=f"HTTP {r.status_code}")
    data = r.json()
    return ValidationResult("atlassian", True, identity=data.get("emailAddress"),
                            raw={"accountId": data.get("accountId"), "displayName": data.get("displayName")})


async def _validate_datadog(client: httpx.AsyncClient, api_key: str, app_key: str | None = None,
                             site: str = "datadoghq.com") -> ValidationResult:
    headers = {"DD-API-KEY": api_key}
    if app_key:
        headers["DD-APPLICATION-KEY"] = app_key
    try:
        r = await client.get(f"https://api.{site}/api/v1/validate", headers=headers, timeout=10.0)
    except httpx.HTTPError as e:
        return ValidationResult("datadog", False, error=str(e))
    if r.status_code != 200:
        return ValidationResult("datadog", False, error=f"HTTP {r.status_code}")
    return ValidationResult("datadog", True, raw=r.json())


async def _validate_npm(client: httpx.AsyncClient, token: str) -> ValidationResult:
    try:
        r = await client.get(
            "https://registry.npmjs.org/-/whoami",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        return ValidationResult("npm", False, error=str(e))
    if r.status_code != 200:
        return ValidationResult("npm", False, error=f"HTTP {r.status_code}")
    return ValidationResult("npm", True, identity=r.json().get("username"),
                            raw=r.json())


# ============== Public API ==============


VALIDATORS = {
    "aws": _validate_aws,
    "github": _validate_github,
    "gitlab": _validate_gitlab,
    "slack": _validate_slack,
    "anthropic": _validate_anthropic,
    "openai": _validate_openai,
    "postman": _validate_postman,
    "atlassian": _validate_atlassian,
    "datadog": _validate_datadog,
    "npm": _validate_npm,
}


async def validate(provider: str, **creds: Any) -> ValidationResult:
    """Унифицированная точка входа: validate('github', token='ghp_...').

    Каждый провайдер требует свой набор kwargs (см. сигнатуры в _validate_*).
    """
    if provider not in VALIDATORS:
        return ValidationResult(provider, False, error=f"Unknown provider: {provider}")
    fn = VALIDATORS[provider]
    async with get_async_client() as client:
        return await fn(client, **creds)


async def validate_to_finding(provider: str, target: str = "n/a", **creds: Any) -> Finding:
    """Запуск валидатора → Finding (для интеграции с общим collection)."""
    res = await validate(provider, **creds)
    if res.valid:
        return Finding(
            rule_id=f"VALIDATOR_{provider.upper()}_LIVE",
            title=f"{provider}: токен ЖИВОЙ — {res.identity or 'unknown identity'}",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            target=target,
            module="validators",
            description=f"Валидатор подтвердил, что токен принадлежит {res.identity}.",
            evidence={"provider": provider, "identity": res.identity, "scopes": res.scopes,
                      "raw": res.raw, "key": f"{provider}:{res.identity}"},
            tags=["secret", "validated", provider],
        )
    return Finding(
        rule_id=f"VALIDATOR_{provider.upper()}_INVALID",
        title=f"{provider}: токен невалиден или протух",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        target=target,
        module="validators",
        evidence={"provider": provider, "error": res.error, "key": f"{provider}:invalid"},
        tags=["secret", "invalid", provider],
    )


async def validate_many(items: list[tuple[str, dict[str, Any]]]) -> list[ValidationResult]:
    """Параллельный запуск пачки валидаторов. items = [(provider, creds_kwargs), ...]"""
    async with get_async_client() as client:
        tasks = [VALIDATORS[p](client, **c) for p, c in items if p in VALIDATORS]
        return await asyncio.gather(*tasks, return_exceptions=False)
