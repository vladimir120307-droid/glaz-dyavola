"""WHOIS / RDAP — структурированные данные о домене.

RDAP это современный JSON-преемник WHOIS, IETF-стандарт. Для большинства
TLD есть RDAP-сервер. Для остальных — fallback на WHOIS port 43 (через
`socket`, без зависимостей).
"""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any

import httpx

# IANA bootstrap для RDAP — карта TLD → RDAP base URL.
# В продакшне можно качать из https://data.iana.org/rdap/dns.json
RDAP_BASE: dict[str, str] = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "io": "https://rdap.identitydigital.services/rdap/",
    "ru": "https://rdap.tcinet.ru/",
    "su": "https://rdap.tcinet.ru/",
    "рф": "https://rdap.tcinet.ru/",
    "us": "https://rdap.identitydigital.services/rdap/",
    "uk": "https://rdap.nominet.uk/uk/",
    "de": "https://rdap.denic.de/",
    "info": "https://rdap.identitydigital.services/rdap/",
    "biz": "https://rdap.nic.biz/",
    "co": "https://rdap.nic.co/",
    "ai": "https://rdap.nic.ai/",
    "dev": "https://rdap.nic.google/",
    "app": "https://rdap.nic.google/",
}

# WHOIS-серверы, fallback
WHOIS_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.publicinterestregistry.org",
    "io": "whois.nic.io",
    "ru": "whois.tcinet.ru",
    "su": "whois.tcinet.ru",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "info": "whois.afilias.net",
}


@dataclass
class WhoisRecord:
    domain: str
    registrar: str | None
    creation_date: str | None
    expiration_date: str | None
    updated_date: str | None
    name_servers: list[str]
    status: list[str]
    raw: str


def _tld(domain: str) -> str:
    return domain.lower().rstrip(".").rsplit(".", 1)[-1]


def rdap_lookup(domain: str) -> dict[str, Any] | None:
    """Запросить RDAP. Возвращает JSON или None."""
    base = RDAP_BASE.get(_tld(domain))
    if not base:
        return None
    try:
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            r = client.get(f"{base}domain/{domain}")
            if r.status_code != 200:
                return None
            return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def whois_raw(domain: str, timeout: float = 8.0) -> str | None:
    """Сырой WHOIS через 43 порт. Stdlib-only, без зависимостей."""
    server = WHOIS_SERVERS.get(_tld(domain))
    if not server:
        return None
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall(f"{domain}\r\n".encode())
            buf = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        return buf.decode("utf-8", errors="replace")
    except (TimeoutError, OSError):
        return None


def whois_summary(domain: str) -> WhoisRecord | None:
    """Сводка по домену: пытается RDAP сначала, fallback на WHOIS."""
    raw = ""
    registrar = None
    creation = None
    expiration = None
    updated = None
    nameservers: list[str] = []
    statuses: list[str] = []

    rdap = rdap_lookup(domain)
    if rdap:
        # Парсим RDAP
        for ev in rdap.get("events", []):
            if ev.get("eventAction") == "registration":
                creation = ev.get("eventDate")
            elif ev.get("eventAction") == "expiration":
                expiration = ev.get("eventDate")
            elif ev.get("eventAction") == "last changed":
                updated = ev.get("eventDate")
        for ent in rdap.get("entities", []):
            if "registrar" in (ent.get("roles") or []):
                vcard = ent.get("vcardArray") or []
                if len(vcard) > 1:
                    for it in vcard[1]:
                        if isinstance(it, list) and len(it) >= 4 and it[0] == "fn":
                            registrar = it[3]
                            break
        for ns in rdap.get("nameservers", []) or []:
            ld = ns.get("ldhName")
            if ld:
                nameservers.append(ld.lower())
        statuses = rdap.get("status") or []
        raw = "rdap"

    if not registrar:
        whois_text = whois_raw(domain)
        if whois_text:
            raw = whois_text
            import re
            for line in whois_text.splitlines():
                low = line.lower().strip()
                if low.startswith("registrar:") and not registrar:
                    registrar = line.split(":", 1)[1].strip()
                elif "creation date:" in low or "created:" in low:
                    creation = creation or line.split(":", 1)[1].strip()
                elif "expir" in low and ":" in low:
                    expiration = expiration or line.split(":", 1)[1].strip()
                elif "updated date:" in low or "last update" in low:
                    updated = updated or line.split(":", 1)[1].strip()
                m = re.match(r"^\s*(?:nserver|name server|nameserver):\s*([^\s]+)", line, re.IGNORECASE)
                if m:
                    nameservers.append(m.group(1).lower().rstrip("."))
                m = re.match(r"^\s*(?:status|domain status):\s*(.+)$", line, re.IGNORECASE)
                if m:
                    statuses.append(m.group(1).strip())

    if not raw:
        return None

    return WhoisRecord(
        domain=domain,
        registrar=registrar,
        creation_date=creation,
        expiration_date=expiration,
        updated_date=updated,
        name_servers=sorted(set(nameservers)),
        status=sorted(set(statuses)),
        raw=(raw[:2000] if len(raw) > 2000 else raw),
    )
