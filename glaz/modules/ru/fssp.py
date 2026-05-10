"""ФССП — поиск исполнительных производств.

Источник: api-ip.fssp.gov.ru (открытый JSON-API ФССП). Требует регистрации
для production-токена; есть rate-limited test-эндпоинт. Для serious-use
поставьте `FSSP_TOKEN` в окружение.

В отсутствие токена возвращает None и пишет в лог. Без брутфорса.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class FsspRecord:
    name: str
    birthdate: str | None
    case_number: str
    case_date: str | None
    department: str
    sum_total: float | None
    sum_paid: float | None
    sum_left: float | None
    bailiff_name: str | None
    bailiff_phone: str | None
    raw: dict[str, Any]


def _token() -> str | None:
    return os.getenv("FSSP_TOKEN")


def search_individual(last_name: str, first_name: str, middle_name: str = "",
                      birthdate: str | None = None,
                      region: int = 0) -> list[FsspRecord] | None:
    """Поиск физлица. region=0 → все регионы (требует premium-токен).

    Возвращает None если нет токена.
    """
    token = _token()
    if not token:
        return None

    params = {
        "token": token,
        "region": region,
        "is_jur": 0,  # физлицо
        "lastname": last_name,
        "firstname": first_name,
        "secondname": middle_name,
    }
    if birthdate:
        params["birthdate"] = birthdate

    try:
        with httpx.Client(timeout=20.0) as client:
            r = client.get("https://api-ip.fssp.gov.ru/api/v1.0/search/physical", params=params)
            r.raise_for_status()
            task = r.json()
    except (httpx.HTTPError, ValueError):
        return None

    task_id = (task.get("response") or {}).get("task")
    if not task_id:
        return []

    # ФССП работает асинхронно: создаём task → опрашиваем status → получаем result
    import time
    for _ in range(15):
        time.sleep(2.0)
        try:
            with httpx.Client(timeout=15.0) as client:
                rr = client.get(
                    "https://api-ip.fssp.gov.ru/api/v1.0/status",
                    params={"token": token, "task": task_id},
                )
                if rr.status_code != 200:
                    continue
                status = rr.json()
                if (status.get("response") or {}).get("status") == 0:
                    # ready
                    res = client.get(
                        "https://api-ip.fssp.gov.ru/api/v1.0/result",
                        params={"token": token, "task": task_id},
                    )
                    if res.status_code != 200:
                        return []
                    data = res.json()
                    rows = (((data.get("response") or {}).get("result") or [{}])[0]
                            .get("result") or [])
                    return [_parse_row(row) for row in rows]
        except (httpx.HTTPError, ValueError):
            continue
    return []


def search_legal_entity(inn: str | None = None, ogrn: str | None = None,
                        name: str | None = None, region: int = 0) -> list[FsspRecord] | None:
    token = _token()
    if not token:
        return None

    params: dict[str, Any] = {"token": token, "region": region, "is_jur": 1}
    if inn:
        params["name"] = name or ""
        params["inn"] = inn
    elif ogrn:
        params["ogrn"] = ogrn
        params["name"] = name or ""
    elif name:
        params["name"] = name
    else:
        return []

    try:
        with httpx.Client(timeout=20.0) as client:
            r = client.get("https://api-ip.fssp.gov.ru/api/v1.0/search/group", params=params)
            r.raise_for_status()
            task = r.json()
    except (httpx.HTTPError, ValueError):
        return None
    task_id = (task.get("response") or {}).get("task")
    if not task_id:
        return []
    return _await_result(task_id)


def _await_result(task_id: str) -> list[FsspRecord]:
    token = _token()
    if not token:
        return []
    import time
    for _ in range(15):
        time.sleep(2.0)
        try:
            with httpx.Client(timeout=15.0) as client:
                rr = client.get(
                    "https://api-ip.fssp.gov.ru/api/v1.0/status",
                    params={"token": token, "task": task_id},
                )
                if rr.status_code != 200:
                    continue
                if (rr.json().get("response") or {}).get("status") == 0:
                    res = client.get(
                        "https://api-ip.fssp.gov.ru/api/v1.0/result",
                        params={"token": token, "task": task_id},
                    )
                    if res.status_code != 200:
                        return []
                    data = res.json()
                    rows = (((data.get("response") or {}).get("result") or [{}])[0]
                            .get("result") or [])
                    return [_parse_row(r) for r in rows]
        except (httpx.HTTPError, ValueError):
            continue
    return []


def _parse_row(row: dict[str, Any]) -> FsspRecord:
    return FsspRecord(
        name=row.get("name", ""),
        birthdate=row.get("birthdate"),
        case_number=row.get("exe_production", ""),
        case_date=row.get("details") or row.get("date"),
        department=row.get("department", ""),
        sum_total=_to_float(row.get("subject_amount")) or _to_float(row.get("subject")),
        sum_paid=None,
        sum_left=_to_float(row.get("subject_balance")),
        bailiff_name=row.get("bailiff", ""),
        bailiff_phone=row.get("bailiff_phone"),
        raw=row,
    )


def _to_float(v: Any) -> float | None:
    if v is None or v == "":
        return None
    try:
        return float(str(v).replace(",", ".").replace(" ", ""))
    except ValueError:
        return None
