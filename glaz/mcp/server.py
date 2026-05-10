"""MCP-сервер для Глаз Дьявола.

Экспонирует ключевые модули как MCP-tools — Claude Code, локальная LLM с
tool-calling (через Open-WebUI / vLLM) или любой другой MCP-клиент могут
вызывать их прямо.

Tools:
- dns_lookup(domain) — DNS-records
- email_security_audit(domain) — SPF/DMARC/DKIM
- subdomain_enum(domain) — поддомены через 6 источников
- identity_fingerprint(domain) — IdP/SSO mapping
- secret_scan_text(text) — сканер секретов на строке
- egrul_lookup(inn) — ЕГРЮЛ/ЕГРИП
- parse_ru_phone(number) — RU-телефон
- vk_resolve(screen_name) — VK ID resolve
- ai_exposure_check(targets) — публичные AI-сервисы
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
except ImportError as e:
    raise ImportError(
        "MCP-зависимость не установлена. Поставьте: pip install 'glaz-dyavola[mcp]'"
    ) from e

from glaz.modules.ai import scan_ai_exposure
from glaz.modules.discovery import passive_dns_lookup, whois_summary
from glaz.modules.dns import dns_passive_scan
from glaz.modules.email_sec import audit_email_security
from glaz.modules.identity import identity_fingerprint
from glaz.modules.ru import (
    classify_gov_domain,
    fingerprint_yandex,
    lookup_bic,
    lookup_by_inn,
    parse_card_iin,
    parse_phone,
    tg_lookup_username,
    vk_resolve_screen_name,
)
from glaz.modules.secrets import scan_text
from glaz.modules.subdomains import enumerate_subdomains
from glaz.modules.validators import validate as validate_creds
from glaz.modules.web import discover_web_surface

server = Server("glaz-dyavola")


TOOLS = [
    Tool(
        name="dns_lookup",
        description="Получить DNS-записи (A/AAAA/MX/NS/TXT/SOA/CNAME/CAA) для домена через trusted-resolver'ы.",
        inputSchema={
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "FQDN, e.g. example.com"}},
            "required": ["domain"],
        },
    ),
    Tool(
        name="email_security_audit",
        description="Аудит SPF/DMARC/DKIM/MTA-STS/TLS-RPT для домена. Возвращает находки с severity.",
        inputSchema={
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    ),
    Tool(
        name="subdomain_enum",
        description="Перечислить поддомены через crt.sh + AlienVault OTX + ThreatMiner + HackerTarget + RapidDNS + Wayback.",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "sources": {"type": "array", "items": {"type": "string"}, "description": "Подмножество источников. Default: все."},
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="identity_fingerprint",
        description="Identity-fabric fingerprint: какие IdP/SSO использует домен (Entra/Okta/ADFS/Google).",
        inputSchema={
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    ),
    Tool(
        name="secret_scan_text",
        description="Просканировать строку на 65+ паттернов секретов (AWS/GCP/GitHub/AI-API/RU). Возвращает список совпадений.",
        inputSchema={
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Текст для сканирования"}},
            "required": ["text"],
        },
    ),
    Tool(
        name="egrul_lookup",
        description="ЕГРЮЛ/ЕГРИП lookup по ИНН. Возвращает структурированные данные о юрлице/ИП (название, ОГРН, директор, адрес).",
        inputSchema={
            "type": "object",
            "properties": {"inn": {"type": "string", "description": "ИНН: 10 цифр (ЮЛ) или 12 (ИП)"}},
            "required": ["inn"],
        },
    ),
    Tool(
        name="parse_ru_phone",
        description="Распарсить RU-телефон: E.164, тип (mobile/landline), оператор (МТС/МегаФон/Билайн/...) и регион.",
        inputSchema={
            "type": "object",
            "properties": {"number": {"type": "string"}},
            "required": ["number"],
        },
    ),
    Tool(
        name="vk_resolve",
        description="Резолв VK screen_name (или URL) → object_id + type (user/group/page).",
        inputSchema={
            "type": "object",
            "properties": {"screen_name": {"type": "string"}},
            "required": ["screen_name"],
        },
    ),
    Tool(
        name="ai_exposure_check",
        description="Поиск экспонированных AI-сервисов: Open-WebUI/Ollama/Dify/Flowise/Langflow/ComfyUI/SD WebUI без аутентификации.",
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "host или http://host:port"},
            },
            "required": ["targets"],
        },
    ),
    Tool(
        name="web_attack_surface",
        description="Web attack-surface: Swagger/OpenAPI (28 paths), GraphQL (13 paths) + introspection check, JS endpoint extraction, security headers audit.",
        inputSchema={
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Base URL"}},
            "required": ["url"],
        },
    ),
    Tool(
        name="whois_lookup",
        description="WHOIS/RDAP lookup. Возвращает регистратора, даты создания/истечения, NS, статусы.",
        inputSchema={
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    ),
    Tool(
        name="passive_dns",
        description="Passive DNS: историческое разрешение хостов через AlienVault OTX + HackerTarget + crt.sh.",
        inputSchema={
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    ),
    Tool(
        name="validate_credential",
        description="Read-only валидация найденного токена: aws/github/gitlab/slack/anthropic/openai/postman/atlassian/datadog/npm. Использует whoami-эндпоинты, не модифицирует ничего. Подтверждает, живой ли токен.",
        inputSchema={
            "type": "object",
            "properties": {
                "provider": {"type": "string"},
                "creds": {"type": "object", "description": "Provider-specific kwargs: {token}, {access_key, secret_key}, {email, token, host}, ..."},
            },
            "required": ["provider", "creds"],
        },
    ),
    Tool(
        name="tg_lookup",
        description="Telegram public lookup: t.me/<username> → тип (user/channel/group/bot), title, описание, число подписчиков.",
        inputSchema={
            "type": "object",
            "properties": {"username": {"type": "string"}},
            "required": ["username"],
        },
    ),
    Tool(
        name="yandex_fingerprint",
        description="Yandex footprint домена: Metrika ID на главной, Yandex Cloud/CDN, бизнес-почта на Яндексе.",
        inputSchema={
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    ),
    Tool(
        name="ru_bank_lookup",
        description="БИК → название банка (топ-50 RU). Также распознаёт BIN карты (платёжная система + эмитент).",
        inputSchema={
            "type": "object",
            "properties": {
                "bic": {"type": "string", "description": "9-значный БИК"},
                "card": {"type": "string", "description": "Номер карты (минимум 6 цифр)"},
            },
        },
    ),
    Tool(
        name="ru_gov_classify",
        description="Классификация домена как государственного (РФ): .gov.ru/.mos.ru/.mil.ru/.kremlin.ru и т.д. → метка.",
        inputSchema={
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


def _ok(data: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, ensure_ascii=False, indent=2, default=str))]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "dns_lookup":
        records, findings = dns_passive_scan(arguments["domain"])
        return _ok({"records": records, "findings": [f.model_dump_serializable() for f in findings]})

    if name == "email_security_audit":
        findings = audit_email_security(arguments["domain"])
        return _ok({"findings": [f.model_dump_serializable() for f in findings]})

    if name == "subdomain_enum":
        sources = arguments.get("sources")
        result = await enumerate_subdomains(arguments["domain"], sources=sources)
        return _ok({k: sorted(v) if isinstance(v, set) else v for k, v in result.items()})

    if name == "identity_fingerprint":
        result, findings = await identity_fingerprint(arguments["domain"])
        return _ok({"result": result, "findings": [f.model_dump_serializable() for f in findings]})

    if name == "secret_scan_text":
        hits = list(scan_text(arguments["text"]))
        return _ok([{
            "rule_id": h.rule_id, "severity": h.severity, "category": h.category,
            "match": h.match, "line": h.line, "entropy": h.entropy,
        } for h in hits])

    if name == "egrul_lookup":
        result = lookup_by_inn(arguments["inn"])
        if not result:
            return _ok({"error": "not_found", "hint": "Set DADATA_API_KEY for richer results"})
        return _ok({k: v for k, v in result.items() if k != "raw"})

    if name == "parse_ru_phone":
        info = parse_phone(arguments["number"])
        return _ok({
            "raw": info.raw, "e164": info.e164, "type": info.type,
            "country": info.country, "operator": info.operator,
            "region": info.region, "valid": info.valid,
        })

    if name == "vk_resolve":
        res = vk_resolve_screen_name(arguments["screen_name"])
        return _ok({
            "screen_name": res.screen_name, "type": res.type, "object_id": res.object_id,
        })

    if name == "ai_exposure_check":
        findings = await scan_ai_exposure(arguments["targets"])
        return _ok([f.model_dump_serializable() for f in findings])

    if name == "web_attack_surface":
        _, common = await discover_web_surface(arguments["url"])
        return _ok([f.model_dump_serializable() for f in common])

    if name == "whois_lookup":
        rec = whois_summary(arguments["domain"])
        if not rec:
            return _ok({"error": "no_data_for_tld"})
        return _ok({
            "domain": rec.domain, "registrar": rec.registrar,
            "creation_date": rec.creation_date, "expiration_date": rec.expiration_date,
            "updated_date": rec.updated_date, "name_servers": rec.name_servers,
            "status": rec.status,
        })

    if name == "passive_dns":
        res = await passive_dns_lookup(arguments["domain"])
        return _ok([{"host": r.host, "ip": r.ip, "rrtype": r.rrtype,
                     "first_seen": r.first_seen, "last_seen": r.last_seen,
                     "source": r.source} for r in res])

    if name == "validate_credential":
        provider = arguments["provider"]
        creds = arguments.get("creds") or {}
        res = await validate_creds(provider, **creds)
        return _ok({
            "provider": res.provider, "valid": res.valid, "identity": res.identity,
            "scopes": res.scopes, "raw": res.raw, "error": res.error,
        })

    if name == "tg_lookup":
        info = tg_lookup_username(arguments["username"])
        if not info:
            return _ok({"error": "not_found_or_invalid"})
        return _ok({
            "username": info.username, "type": info.type, "title": info.title,
            "description": info.description, "members": info.members,
            "image_url": info.image_url,
        })

    if name == "yandex_fingerprint":
        fp = fingerprint_yandex(arguments["domain"])
        return _ok({
            "domain": fp.domain, "metrika_ids": fp.metrika_ids,
            "has_yandex_mail": fp.has_yandex_mail, "has_yandex_cdn": fp.has_yandex_cdn,
            "notes": fp.notes,
        })

    if name == "ru_bank_lookup":
        out = {}
        if arguments.get("bic"):
            info = lookup_bic(arguments["bic"])
            out["bic"] = {"bic": info.bic, "name": info.name}
        if arguments.get("card"):
            out["card"] = parse_card_iin(arguments["card"])
        return _ok(out or {"error": "specify bic or card"})

    if name == "ru_gov_classify":
        is_gov, label = classify_gov_domain(arguments["domain"])
        return _ok({"domain": arguments["domain"], "is_gov": is_gov, "label": label})

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def run_stdio() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    asyncio.run(run_stdio())


if __name__ == "__main__":
    main()
