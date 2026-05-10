"""VK OSINT — резолв публичных идентификаторов.

Что делает:
- `vk_resolve_screen_name(name)` — превращает короткое имя (vk.com/durov)
  в численный ID + тип (user/group/page) через метод `utils.resolveScreenName`.
  Этот метод доступен без user token, но требует service-key — поддерживается
  через `VK_SERVICE_KEY` env. Без ключа — есть fallback через парс публичной
  страницы.
- `vk_extract_from_url(url)` — извлекает screen_name из любой формы VK URL.

Без активного скрейпинга: только публичные методы и публичные страницы
(без авторизации в чужой аккаунт).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

VK_API_VERSION = "5.199"
VK_API_RESOLVE = "https://api.vk.com/method/utils.resolveScreenName"


@dataclass
class VkResolveResult:
    screen_name: str
    type: str | None  # user / group / page / application
    object_id: int | None
    raw: dict | None


def vk_extract_from_url(url: str) -> str | None:
    """Из любой формы (https://vk.com/durov, vk.com/id1, m.vk.com/club123) — screen_name."""
    try:
        p = urlparse(url if "://" in url else f"https://{url}")
    except ValueError:
        return None
    if not p.netloc.endswith("vk.com"):
        return None
    path = p.path.strip("/")
    if not path:
        return None
    # Берём первый сегмент
    return path.split("/")[0].split("?")[0]


def vk_resolve_screen_name(name: str) -> VkResolveResult:
    """Резолв screen_name → object_id + type."""
    name = name.strip().lstrip("@")
    if name.startswith("http"):
        extracted = vk_extract_from_url(name)
        if extracted:
            name = extracted

    service_key = os.getenv("VK_SERVICE_KEY")
    if service_key:
        try:
            with httpx.Client(timeout=10.0) as client:
                r = client.get(
                    VK_API_RESOLVE,
                    params={"screen_name": name, "v": VK_API_VERSION, "access_token": service_key},
                )
                if r.status_code == 200:
                    data = r.json()
                    resp = data.get("response") or {}
                    if resp:
                        return VkResolveResult(
                            screen_name=name,
                            type=resp.get("type"),
                            object_id=resp.get("object_id"),
                            raw=data,
                        )
        except (httpx.HTTPError, ValueError):
            pass

    # Fallback — парс публичной страницы. Из <meta name="al-id" content="X_Y">
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0 (compatible; glaz-dyavola)"}) as client:
            r = client.get(f"https://vk.com/{name}")
            if r.status_code != 200:
                return VkResolveResult(screen_name=name, type=None, object_id=None, raw=None)
            html = r.text
    except httpx.HTTPError:
        return VkResolveResult(screen_name=name, type=None, object_id=None, raw=None)

    m = re.search(r"\"id\":\s*(\d+)\s*,\s*\"first_name\"", html)
    if m:
        return VkResolveResult(screen_name=name, type="user", object_id=int(m.group(1)), raw=None)
    m = re.search(r"public(\d+)|club(\d+)", html)
    if m:
        gid = int(m.group(1) or m.group(2))
        return VkResolveResult(screen_name=name, type="group", object_id=gid, raw=None)

    return VkResolveResult(screen_name=name, type=None, object_id=None, raw=None)
