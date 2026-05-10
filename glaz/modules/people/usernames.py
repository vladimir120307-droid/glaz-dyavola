"""Проверка существования username на 25+ публичных платформах.

Принцип: HEAD/GET на профильный URL. Платформа существует если:
- HTTP 200 + конкретный маркер в HTML (имя пользователя или title)
- HTTP не равно 404/410

Ничего не публикуется и не запрашивается с авторизацией. Только публичные
профильные страницы.

Покрытие:
- GitHub, GitLab, Bitbucket, Codeberg
- Twitter/X, Mastodon (instances), Bluesky
- Reddit, HackerNews, Stack Overflow, Dev.to
- LinkedIn (только публичный URL — без скрейпа)
- VK, Telegram, OK
- Instagram, TikTok, YouTube, Twitch
- Steam, Spotify, SoundCloud, Last.fm
- ProductHunt, Goodreads, Behance, Dribbble, Medium
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from glaz.utils.http import get_async_client


@dataclass
class UsernameProbe:
    platform: str
    url: str
    exists: bool
    confidence: str  # 'high' | 'medium' | 'low'
    note: str | None = None


# Платформа → (URL-template, marker-в-HTML, signal-of-not-exists)
# Если signal-of-not-exists в body → "не существует". Иначе — "вероятно существует".
PLATFORMS: dict[str, tuple[str, str | None, str | None]] = {
    "github":       ("https://github.com/{u}", None, "Not Found"),
    "gitlab":       ("https://gitlab.com/{u}", None, "404"),
    "bitbucket":    ("https://bitbucket.org/{u}/", None, "404"),
    "codeberg":     ("https://codeberg.org/{u}", None, "404"),
    "twitter":      ("https://twitter.com/{u}", None, "page doesn’t exist"),
    "x":            ("https://x.com/{u}", None, "page doesn’t exist"),
    "bluesky":      ("https://bsky.app/profile/{u}.bsky.social", None, "Profile not found"),
    "reddit":       ("https://www.reddit.com/user/{u}/about.json", "data", None),
    "hackernews":   ("https://news.ycombinator.com/user?id={u}", "user:", "No such user"),
    "stackoverflow": ("https://stackoverflow.com/users/{u}", None, "Page Not Found"),
    "devto":        ("https://dev.to/{u}", None, "Page not found"),
    "vk":           ("https://vk.com/{u}", None, "404"),
    "ok":           ("https://ok.ru/{u}", None, "не найдена"),
    "telegram":     ("https://t.me/{u}", "tgme_page", None),
    "instagram":    ("https://www.instagram.com/{u}/", None, "Page Not Found"),
    "tiktok":       ("https://www.tiktok.com/@{u}", None, "Couldn't find this account"),
    "youtube":      ("https://www.youtube.com/@{u}", None, "404"),
    "twitch":       ("https://www.twitch.tv/{u}", None, "Sorry. Unless you've got a time"),
    "steam":        ("https://steamcommunity.com/id/{u}", None, "The specified profile could not be found"),
    "spotify":      ("https://open.spotify.com/user/{u}", None, "404"),
    "soundcloud":   ("https://soundcloud.com/{u}", None, "404"),
    "lastfm":       ("https://www.last.fm/user/{u}", None, "User not found"),
    "producthunt":  ("https://www.producthunt.com/@{u}", None, "Page not found"),
    "behance":      ("https://www.behance.net/{u}", None, "404"),
    "dribbble":     ("https://dribbble.com/{u}", None, "404"),
    "medium":       ("https://medium.com/@{u}", None, "Page not found"),
    "habr":         ("https://habr.com/ru/users/{u}/", None, "Пользователь не найден"),
    "pikabu":       ("https://pikabu.ru/@{u}", None, "Пользователь не найден"),
}


async def _probe_platform(client: httpx.AsyncClient, platform: str, username: str) -> UsernameProbe:
    url_template, marker, anti = PLATFORMS[platform]
    url = url_template.format(u=username)
    try:
        r = await client.get(url, timeout=10.0)
    except httpx.HTTPError as e:
        return UsernameProbe(platform, url, False, "low", f"network error: {e}")

    if r.status_code in (404, 410):
        return UsernameProbe(platform, url, False, "high", f"HTTP {r.status_code}")

    body = (r.text or "")[:8192]
    if anti and anti in body:
        return UsernameProbe(platform, url, False, "high", "anti-marker present")

    if marker and marker in body:
        return UsernameProbe(platform, url, True, "high", "marker present")

    if r.status_code == 200:
        # Без явного маркера — confidence ниже
        return UsernameProbe(platform, url, True, "medium", "HTTP 200 (no explicit marker)")

    return UsernameProbe(platform, url, False, "low", f"HTTP {r.status_code}")


async def check_usernames(username: str, *, platforms: list[str] | None = None) -> list[UsernameProbe]:
    """Проверить username на множестве платформ. Параллельно.

    `platforms=None` — все. Можно передать подмножество имён.
    """
    chosen = platforms if platforms else list(PLATFORMS.keys())
    chosen = [p for p in chosen if p in PLATFORMS]
    if not chosen:
        return []

    async with get_async_client() as client:
        results = await asyncio.gather(
            *[_probe_platform(client, p, username) for p in chosen],
            return_exceptions=False,
        )
    return list(results)
