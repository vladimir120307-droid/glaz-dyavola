"""Telegram public-OSINT.

Берём ровно то, что отдаёт `t.me/<username>` без авторизации:
- Тип объекта (user / channel / group / bot)
- Title, описание, аватар
- Количество подписчиков (для каналов)

Никакой авторизации в чужой аккаунт, никакого активного скрейпа сообщений.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


@dataclass
class TgInfo:
    username: str
    type: str  # user / channel / group / bot / unknown
    title: str | None
    description: str | None
    members: int | None
    image_url: str | None
    raw_html_excerpt: str | None


def lookup_username(username: str) -> TgInfo | None:
    """Запросить t.me/<username> и распарсить open-graph метаданные."""
    username = username.strip().lstrip("@").lstrip("/")
    if username.startswith("https://"):
        m = re.search(r"t\.me/([A-Za-z0-9_]+)", username)
        if not m:
            return None
        username = m.group(1)

    if not re.match(r"^[A-Za-z0-9_]{4,32}$", username):
        return None

    try:
        with httpx.Client(timeout=10.0, follow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0 (compatible; glaz-dyavola)"}) as client:
            r = client.get(f"https://t.me/{username}")
            if r.status_code != 200:
                return None
            html = r.text
    except httpx.HTTPError:
        return None

    title = _extract(html, r'<meta property="og:title" content="([^"]+)"')
    description = _extract(html, r'<meta property="og:description" content="([^"]+)"')
    image = _extract(html, r'<meta property="og:image" content="([^"]+)"')

    # Тип определяется по странице. Каналы имеют counter подписчиков.
    members = None
    m = re.search(r"([\d  ]+)\s*(?:subscribers|members|подписчик)", html, re.IGNORECASE)
    if m:
        try:
            members = int(re.sub(r"\D", "", m.group(1)))
        except ValueError:
            members = None

    obj_type = "unknown"
    if "tgme_page_extra" in html:
        if "subscribers" in html.lower() or "подписчик" in html.lower():
            obj_type = "channel"
        elif "members" in html.lower() or "участник" in html.lower():
            obj_type = "group"
        elif title and title.lower().endswith("bot"):
            obj_type = "bot"
        else:
            obj_type = "user"

    return TgInfo(
        username=username,
        type=obj_type,
        title=title,
        description=description,
        members=members,
        image_url=image,
        raw_html_excerpt=html[:600] if html else None,
    )


def _extract(text: str, pattern: str) -> str | None:
    m = re.search(pattern, text)
    return m.group(1) if m else None
