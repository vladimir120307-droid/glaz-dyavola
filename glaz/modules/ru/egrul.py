"""ЕГРЮЛ / ЕГРИП — поиск юрлиц и ИП по ИНН / ОГРН / названию.

Источники (в порядке приоритета):
1. DaData (быстро, структурировано) — нужен `DADATA_API_KEY` в окружении
2. egrul.nalog.ru — публичный, без ключа, отдаёт PDF-выписку

Возвращает structured-данные: ИНН/ОГРН/КПП/название/директор/адрес/виды
деятельности (ОКВЭД).
"""
from __future__ import annotations

import os
from typing import Any

import httpx

from glaz.core.asset_graph import Asset, AssetGraph, AssetType, Edge

DADATA_FIND_URL = "https://suggestions.dadata.ru/suggestions/api/4_1/rs/findById/party"
DADATA_SUGGEST_URL = "https://suggestions.dadata.ru/suggestions/api/4_1/rs/suggest/party"


def _dadata_token() -> str | None:
    return os.getenv("DADATA_API_KEY")


def _dadata_headers() -> dict[str, str]:
    token = _dadata_token()
    if not token:
        return {}
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Token {token}",
    }


def lookup_by_inn(inn: str, *, graph: AssetGraph | None = None) -> dict[str, Any] | None:
    """Найти ЮЛ/ИП по ИНН. ИНН: 10 цифр (ЮЛ) или 12 (ИП).

    Возвращает None если не найдено или нет ключа DaData.
    """
    inn = inn.strip()
    if not inn.isdigit() or len(inn) not in (10, 12):
        return None
    if not _dadata_token():
        return _egrul_nalog_search(inn, graph=graph)

    payload = {"query": inn, "branch_type": "MAIN"}
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.post(DADATA_FIND_URL, json=payload, headers=_dadata_headers())
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError, ValueError):
        return None

    suggestions = data.get("suggestions", [])
    if not suggestions:
        return None
    raw = suggestions[0].get("data", {})
    return _normalize_egrul(raw, graph=graph)


def search_org(query: str, limit: int = 10) -> list[dict[str, Any]]:
    """Поиск организации по названию/ИНН/ОГРН. Требует DaData API key."""
    if not _dadata_token():
        return []
    payload = {"query": query, "count": limit}
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.post(DADATA_SUGGEST_URL, json=payload, headers=_dadata_headers())
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError, ValueError):
        return []
    return [_normalize_egrul(s.get("data", {})) for s in data.get("suggestions", [])]


def _normalize_egrul(raw: dict[str, Any], *, graph: AssetGraph | None = None) -> dict[str, Any]:
    """Привести разные ответы DaData к единой схеме."""
    name = raw.get("name", {})
    address = raw.get("address", {})
    management = raw.get("management") or {}
    okved = raw.get("okveds") or []

    out = {
        "inn": raw.get("inn"),
        "kpp": raw.get("kpp"),
        "ogrn": raw.get("ogrn"),
        "ogrn_date": raw.get("ogrn_date"),
        "type": raw.get("type"),  # LEGAL / INDIVIDUAL
        "name_full": name.get("full_with_opf") if isinstance(name, dict) else None,
        "name_short": name.get("short_with_opf") if isinstance(name, dict) else None,
        "address": address.get("value") if isinstance(address, dict) else address,
        "address_data": address.get("data") if isinstance(address, dict) else None,
        "director": management.get("name"),
        "director_post": management.get("post"),
        "okved_main": (okved[0].get("code") if okved and isinstance(okved[0], dict) else None),
        "okved_main_name": (okved[0].get("name") if okved and isinstance(okved[0], dict) else None),
        "status": (raw.get("state") or {}).get("status") if isinstance(raw.get("state"), dict) else None,
        "registration_date": (raw.get("state") or {}).get("registration_date") if isinstance(raw.get("state"), dict) else None,
        "liquidation_date": (raw.get("state") or {}).get("liquidation_date") if isinstance(raw.get("state"), dict) else None,
        "raw": raw,
    }

    if graph is not None and out.get("inn"):
        org_id = Asset.make_id(AssetType.ORG, out["inn"])
        graph.add_asset(Asset(
            id=org_id, type=AssetType.ORG, value=out.get("name_short") or out["inn"],
            attributes={k: v for k, v in out.items() if k != "raw"},
            tags=["ru", out.get("type", "").lower()] if out.get("type") else ["ru"],
            discovered_by="ru.egrul",
        ))
        if out.get("director"):
            person_id = Asset.make_id(AssetType.PERSON, out["director"])
            graph.add_asset(Asset(
                id=person_id, type=AssetType.PERSON, value=out["director"],
                attributes={"post": out.get("director_post")}, tags=["ru"],
                discovered_by="ru.egrul",
            ))
            graph.add_edge(Edge(
                subject=person_id, relation="manages", object=org_id,
                discovered_by="ru.egrul",
            ))

    return out


def _egrul_nalog_search(query: str, *, graph: AssetGraph | None = None) -> dict[str, Any] | None:
    """Fallback на публичный egrul.nalog.ru. Это два запроса:
    1. POST /search-result — получить ID
    2. GET /search-result/<id> — получить рез-т (HTML)

    Возвращает урезанный набор полей (без ОКВЭД и директора — они в PDF-выписке).
    """
    try:
        with httpx.Client(timeout=20.0, follow_redirects=True) as client:
            r = client.post(
                "https://egrul.nalog.ru/",
                data={"query": query, "region": "", "PreviousContextId": ""},
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
            if r.status_code != 200:
                return None
            try:
                token = r.json().get("t")
            except ValueError:
                return None
            if not token:
                return None

            # Приходится подождать пока ФНС подготовит результат
            import time
            for _ in range(5):
                time.sleep(1.0)
                rr = client.get(f"https://egrul.nalog.ru/search-result/{token}")
                if rr.status_code == 200 and "rows" in rr.text:
                    try:
                        data = rr.json()
                    except ValueError:
                        continue
                    rows = data.get("rows") or []
                    if rows:
                        first = rows[0]
                        out = {
                            "inn": first.get("i"),
                            "ogrn": first.get("o"),
                            "kpp": first.get("p"),
                            "name_short": first.get("n"),
                            "name_full": first.get("c"),
                            "address": first.get("a"),
                            "registration_date": first.get("r"),
                            "liquidation_date": first.get("e"),
                            "status": first.get("g"),
                            "source": "egrul.nalog.ru",
                            "raw": first,
                        }
                        if graph is not None and out.get("inn"):
                            org_id = Asset.make_id(AssetType.ORG, out["inn"])
                            graph.add_asset(Asset(
                                id=org_id, type=AssetType.ORG,
                                value=out.get("name_short") or out["inn"],
                                attributes={k: v for k, v in out.items() if k != "raw"},
                                tags=["ru"], discovered_by="ru.egrul",
                            ))
                        return out
    except httpx.HTTPError:
        return None
    return None
