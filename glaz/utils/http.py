"""Тонкая обёртка над httpx с дефолтным User-Agent и таймаутом.

Все исходящие запросы идут через этот клиент — единая точка для логирования
и rate-limiting в будущем."""
from __future__ import annotations

import httpx

DEFAULT_UA = "glaz-dyavola/0.1 (+https://github.com/vladimir/glaz-dyavola)"
DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


def get_client(*, follow_redirects: bool = True, ua: str = DEFAULT_UA) -> httpx.Client:
    return httpx.Client(
        headers={"User-Agent": ua, "Accept": "*/*"},
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=follow_redirects,
    )


def get_async_client(*, follow_redirects: bool = True, ua: str = DEFAULT_UA) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={"User-Agent": ua, "Accept": "*/*"},
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=follow_redirects,
    )
