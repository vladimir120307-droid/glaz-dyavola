"""AI/LLM-инфраструктура: поиск экспонированных публичных инстансов.

Разворачиваемые AI-приложения часто оставляют админ-панель открытой:
- Open-WebUI (`/api/v1/auths/signup` без отключенной регистрации)
- LangSmith / LangServe playground без аутентификации
- Dify (`/console/api/setup` сигналы первичной настройки)
- Flowise (`/api/v1/credentials`)
- LocalAI / Ollama API без auth (порт 11434)
- vLLM / Text Generation Inference (TGI) с открытым `/v1/models`

Метод проверки — пассивный GET на типичные эндпоинты, читаем заголовки и
короткий body. Никакой энумерации, никаких мутирующих запросов.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from glaz.core.findings import Confidence, Finding, Severity
from glaz.utils.http import get_async_client


@dataclass
class AiSignature:
    name: str
    path: str
    severity: Severity
    description: str
    # Если ответ содержит этот substring — match.
    body_substr: list[str]
    headers: dict[str, str] | None = None


SIGNATURES: list[AiSignature] = [
    AiSignature(
        name="OpenWebUI",
        path="/api/config",
        severity=Severity.MEDIUM,
        description="Open-WebUI публичный инстанс — проверьте отключение регистрации (ENABLE_SIGNUP=false).",
        body_substr=["openwebui", "ENABLE_SIGNUP", "default_models", "DEFAULT_MODELS"],
    ),
    AiSignature(
        name="OpenWebUI Signup Open",
        path="/api/v1/auths/signup",
        severity=Severity.HIGH,
        description="Open-WebUI с открытой регистрацией. Любой может создать аккаунт.",
        body_substr=["password", "email"],
    ),
    AiSignature(
        name="Ollama API",
        path="/api/tags",
        severity=Severity.HIGH,
        description="Ollama без аутентификации — публичный inference на чужом железе. Используется для крипто-фрода и атаки через model-injection.",
        body_substr=["models", "modelfile", "digest"],
    ),
    AiSignature(
        name="LocalAI",
        path="/v1/models",
        severity=Severity.MEDIUM,
        description="LocalAI / vLLM / TGI с открытым /v1/models — OpenAI-compat эндпоинт без auth.",
        body_substr=["object\":\"list", "model"],
    ),
    AiSignature(
        name="Dify",
        path="/console/api/setup",
        severity=Severity.HIGH,
        description="Dify в режиме первичной настройки — можно перехватить admin-аккаунт.",
        body_substr=["setup_status", "current_version"],
    ),
    AiSignature(
        name="Flowise",
        path="/api/v1/ping",
        severity=Severity.MEDIUM,
        description="Flowise без auth. Проверьте FLOWISE_USERNAME/FLOWISE_PASSWORD.",
        body_substr=["pong", "status"],
    ),
    AiSignature(
        name="Langflow",
        path="/api/v1/version",
        severity=Severity.MEDIUM,
        description="Langflow публичный — проверьте наличие настроенной auth.",
        body_substr=["version", "main_version"],
    ),
    AiSignature(
        name="LangSmith Playground",
        path="/playground/",
        severity=Severity.LOW,
        description="LangServe/LangSmith playground без auth — может палить промпты.",
        body_substr=["playground", "langserve"],
    ),
    AiSignature(
        name="Anything LLM",
        path="/api/system/check-permission",
        severity=Severity.MEDIUM,
        description="AnythingLLM без multi-user auth.",
        body_substr=["MultiUserMode", "RequiresAuth"],
    ),
    AiSignature(
        name="ComfyUI",
        path="/system_stats",
        severity=Severity.MEDIUM,
        description="ComfyUI без auth — можно использовать чужие GPU + читать сгенерированный контент.",
        body_substr=["system", "devices", "vram_total"],
    ),
    AiSignature(
        name="Stable Diffusion WebUI",
        path="/sdapi/v1/options",
        severity=Severity.MEDIUM,
        description="A1111 SD WebUI без --api-auth.",
        body_substr=["sd_model_checkpoint", "samples_save"],
    ),
]


async def _probe(client: httpx.AsyncClient, base_url: str, sig: AiSignature) -> dict[str, Any] | None:
    url = base_url.rstrip("/") + sig.path
    try:
        r = await client.get(url, timeout=10.0)
    except httpx.HTTPError:
        return None
    if r.status_code >= 400:
        return None
    body = (r.text or "")[:4096]
    if any(s.lower() in body.lower() for s in sig.body_substr):
        return {"sig": sig, "url": url, "status": r.status_code, "snippet": body[:400]}
    return None


async def scan_ai_exposure(targets: list[str]) -> list[Finding]:
    """Просканировать список base-URL'ов на признаки экспонированных AI-сервисов.

    `targets` — это `https://host:port` либо просто `host`.
    """
    norm: list[str] = []
    for t in targets:
        if "://" not in t:
            norm.append(f"http://{t}")
        else:
            norm.append(t)

    findings: list[Finding] = []
    async with get_async_client() as client:
        tasks = [_probe(client, base, sig) for base in norm for sig in SIGNATURES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if not res or isinstance(res, BaseException):
            continue
        sig: AiSignature = res["sig"]
        findings.append(Finding(
            rule_id=f"AI_EXPOSED_{sig.name.upper().replace(' ', '_')}",
            title=f"{sig.name} публично доступен",
            severity=sig.severity, confidence=Confidence.HIGH,
            target=res["url"], module="ai",
            description=sig.description,
            evidence={"url": res["url"], "status": res["status"], "snippet": res["snippet"], "key": res["url"]},
            tags=["ai", "exposure", sig.name.lower().replace(" ", "_")],
        ))
    return findings
