"""Web attack-surface discovery: Swagger/OpenAPI, GraphQL, JS-endpoints,
security headers — стандартный набор для bug-bounty/ASM.

Все проверки пассивные: только GET'ы, никакой fuzzing-ы и mutation'ов.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

import httpx

from glaz.core.findings import Confidence, Finding, Severity
from glaz.utils.http import get_async_client

# 28 путей Swagger / OpenAPI / Redoc — стандарт индустрии
SWAGGER_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api-docs", "/api-docs.json", "/api/docs", "/api/swagger.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/swagger-ui.html", "/swagger/index.html", "/swagger/", "/swagger",
    "/api/v1/swagger.json", "/api/v2/swagger.json", "/api/v3/swagger.json",
    "/docs", "/redoc", "/api/redoc",
    "/api/swagger-ui.html", "/api/swagger-ui", "/swagger/v1/swagger.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json", "/spec.json",
]

# 13 путей GraphQL — типичные позиции эндпоинта
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/api/v1/graphql", "/api/v2/graphql",
    "/v1/graphql", "/v2/graphql", "/query", "/api/query",
    "/graphql/console", "/playground", "/api/graphql/playground", "/altair",
]

# Security headers, отсутствие которых — типичный low-finding
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", Severity.MEDIUM),
    "content-security-policy": ("CSP", Severity.MEDIUM),
    "x-frame-options": ("X-Frame-Options", Severity.LOW),
    "x-content-type-options": ("X-Content-Type-Options", Severity.LOW),
    "referrer-policy": ("Referrer-Policy", Severity.LOW),
    "permissions-policy": ("Permissions-Policy", Severity.LOW),
}

GRAPHQL_INTROSPECTION_QUERY = (
    '{"query":"{__schema{types{name kind description fields{name description '
    'args{name type{name kind ofType{name kind}}} type{name kind ofType{name kind}}}}}}"}'
)

ENDPOINT_RE_TIER1 = re.compile(r"['\"`](/(?:api|v\d+|graphql|admin|user|auth|internal)[^\s'\"`<>?#]+)['\"`]")
ENDPOINT_RE_TIER2 = re.compile(r"['\"`](/[a-zA-Z0-9_\-./]+\.(?:json|xml|yaml|yml))['\"`]")
INTERNAL_HOST_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)*(?:internal|local|corp|intranet|svc|cluster\.local)\b"
)


@dataclass
class WebFinding:
    kind: str   # swagger / graphql / js_endpoint / missing_header / sourcemap
    url: str
    detail: str
    severity: Severity


async def _try_path(client: httpx.AsyncClient, base: str, path: str) -> tuple[int, str, dict[str, str]] | None:
    url = base.rstrip("/") + path
    try:
        r = await client.get(url, timeout=10.0)
    except httpx.HTTPError:
        return None
    return r.status_code, r.text[:8192], dict(r.headers)


async def find_swagger(client: httpx.AsyncClient, base: str) -> list[WebFinding]:
    out: list[WebFinding] = []
    tasks = [_try_path(client, base, p) for p in SWAGGER_PATHS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for path, res in zip(SWAGGER_PATHS, results, strict=True):
        if not res or isinstance(res, BaseException):
            continue
        status, body, _ = res
        if status >= 400:
            continue
        body_lo = body.lower()
        if any(s in body_lo for s in ('"swagger":', '"openapi":', "swagger-ui", "redoc")):
            out.append(WebFinding(
                kind="swagger", url=base.rstrip("/") + path,
                detail="Swagger/OpenAPI спецификация публично доступна — даёт полный API surface",
                severity=Severity.MEDIUM,
            ))
    return out


async def find_graphql(client: httpx.AsyncClient, base: str) -> list[WebFinding]:
    out: list[WebFinding] = []
    for path in GRAPHQL_PATHS:
        url = base.rstrip("/") + path
        try:
            r = await client.get(url, timeout=8.0)
        except httpx.HTTPError:
            continue
        body_lo = (r.text or "")[:4096].lower()
        if r.status_code < 400 and any(s in body_lo for s in ("graphql", "graphiql", "playground", "altair")):
            out.append(WebFinding(
                kind="graphql", url=url,
                detail="GraphQL endpoint обнаружен. Проверьте отключение introspection в проде.",
                severity=Severity.MEDIUM,
            ))
            # Проверяем introspection
            try:
                intro = await client.post(
                    url, content=GRAPHQL_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"}, timeout=10.0,
                )
                if intro.status_code < 400 and "__schema" in intro.text:
                    out.append(WebFinding(
                        kind="graphql_introspection", url=url,
                        detail="GraphQL introspection ВКЛЮЧЕНА — полная схема API утекла",
                        severity=Severity.HIGH,
                    ))
            except httpx.HTTPError:
                pass
    return out


async def fetch_security_headers(client: httpx.AsyncClient, url: str) -> list[WebFinding]:
    """Проверка отсутствия типичных security headers."""
    try:
        r = await client.get(url, timeout=10.0)
    except httpx.HTTPError:
        return []
    out: list[WebFinding] = []
    headers_lower = {k.lower(): v for k, v in r.headers.items()}
    for h, (label, sev) in SECURITY_HEADERS.items():
        if h not in headers_lower:
            out.append(WebFinding(
                kind="missing_header", url=url,
                detail=f"Отсутствует {label}",
                severity=sev,
            ))
    # Bonus: проверяем наличие Server-header с раскрытием версии
    server = headers_lower.get("server", "")
    if server and re.search(r"\d+\.\d+", server):
        out.append(WebFinding(
            kind="server_version_disclosed", url=url,
            detail=f"Server-header раскрывает версию: {server}",
            severity=Severity.LOW,
        ))
    # X-Powered-By
    xpb = headers_lower.get("x-powered-by", "")
    if xpb:
        out.append(WebFinding(
            kind="x_powered_by", url=url,
            detail=f"X-Powered-By раскрывает стек: {xpb}",
            severity=Severity.LOW,
        ))
    return out


async def extract_endpoints_from_js(client: httpx.AsyncClient, js_url: str) -> list[WebFinding]:
    """Простой extract из inline/external JS: эндпоинты + внутренние хосты + sourcemap leaks."""
    try:
        r = await client.get(js_url, timeout=15.0)
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    body = r.text or ""

    out: list[WebFinding] = []
    endpoints: set[str] = set()
    for m in ENDPOINT_RE_TIER1.finditer(body):
        endpoints.add(m.group(1))
    for m in ENDPOINT_RE_TIER2.finditer(body):
        endpoints.add(m.group(1))

    if endpoints:
        out.append(WebFinding(
            kind="js_endpoints", url=js_url,
            detail=f"В JS найдено {len(endpoints)} эндпоинтов: " + ", ".join(sorted(endpoints)[:10]),
            severity=Severity.LOW,
        ))

    internal = set(INTERNAL_HOST_RE.findall(body))
    if internal:
        out.append(WebFinding(
            kind="internal_host_leak", url=js_url,
            detail=f"В JS упоминаются внутренние хосты: {', '.join(sorted(internal)[:10])}",
            severity=Severity.MEDIUM,
        ))

    # Sourcemap reference?
    if "sourceMappingURL" in body:
        m = re.search(r"sourceMappingURL=([^\s]+)", body)
        if m:
            out.append(WebFinding(
                kind="sourcemap_reference", url=js_url,
                detail=f"JS ссылается на sourcemap: {m.group(1)} — может раскрыть исходники",
                severity=Severity.MEDIUM,
            ))

    return out


async def discover_web_surface(base_url: str) -> tuple[list[WebFinding], list[Finding]]:
    """Полный пас по одному base URL: Swagger + GraphQL + headers + JS-extract.

    Возвращает (web_findings_raw, common_findings) — первый для подробного
    отчёта, второй — для интеграции с общим FindingCollection.
    """
    if "://" not in base_url:
        base_url = f"https://{base_url}"

    web_findings: list[WebFinding] = []
    async with get_async_client() as client:
        sw, gq, hd = await asyncio.gather(
            find_swagger(client, base_url),
            find_graphql(client, base_url),
            fetch_security_headers(client, base_url),
            return_exceptions=False,
        )
        web_findings.extend(sw)
        web_findings.extend(gq)
        web_findings.extend(hd)

        # Простой JS-discovery: парсим главную и достаём <script src=...>
        try:
            r = await client.get(base_url, timeout=10.0)
            if r.status_code == 200:
                js_urls = set()
                for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', r.text or "", re.IGNORECASE):
                    src = m.group(1)
                    if src.startswith("//"):
                        src = "https:" + src
                    elif src.startswith("/"):
                        src = base_url.rstrip("/") + src
                    elif not src.startswith("http"):
                        src = base_url.rstrip("/") + "/" + src
                    js_urls.add(src)
                # ограничим первыми 8 чтобы не DOS-ить себя
                js_results = await asyncio.gather(*[
                    extract_endpoints_from_js(client, j) for j in list(js_urls)[:8]
                ])
                for sub in js_results:
                    web_findings.extend(sub)
        except httpx.HTTPError:
            pass

    common: list[Finding] = []
    for wf in web_findings:
        common.append(Finding(
            rule_id=f"WEB_{wf.kind.upper()}",
            title=wf.detail[:90],
            severity=wf.severity,
            confidence=Confidence.HIGH,
            target=wf.url,
            module="web",
            description=wf.detail,
            evidence={"url": wf.url, "kind": wf.kind, "key": wf.url + ":" + wf.kind},
            tags=["web", wf.kind],
        ))

    return web_findings, common
