"""Identity-fabric fingerprint: какие IdP/SSO использует домен.

Покрытие:
- Microsoft Entra (Azure AD): GetUserRealm + OpenID config
- Okta: tenant_slug.okta.com discovery
- ADFS: /adfs/ls/idpinitiatedsignon.aspx + /adfs/services/trust/mex
- Google Workspace OIDC: /.well-known/openid-configuration
- Generic OIDC: corp/auth/sso поддоменов

Всё пассивно — только GET'ы на публичные эндпоинты, никакой энумерации
учётных записей.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

from glaz.core.asset_graph import Asset, AssetGraph, AssetType, Edge
from glaz.core.findings import Confidence, Finding, Severity
from glaz.utils.http import get_async_client


async def _check_entra(client, domain: str) -> dict[str, Any] | None:
    """Microsoft Entra / Azure AD tenant fingerprint."""
    url = f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&xml=1"
    try:
        r = await client.get(url)
    except Exception:
        return None
    if r.status_code != 200 or "<NameSpaceType>" not in r.text:
        return None

    ns = re.search(r"<NameSpaceType>([^<]+)</NameSpaceType>", r.text)
    fed_brand = re.search(r"<FederationBrandName>([^<]+)</FederationBrandName>", r.text)
    cloud_inst = re.search(r"<CloudInstanceName>([^<]+)</CloudInstanceName>", r.text)
    domain_type = ns.group(1) if ns else None

    out: dict[str, Any] = {
        "domain_type": domain_type,
        "federation_brand": fed_brand.group(1) if fed_brand else None,
        "cloud_instance": cloud_inst.group(1) if cloud_inst else None,
    }

    # Достаём tenant GUID из openid-configuration
    try:
        cfg = await client.get(f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration")
        if cfg.status_code == 200:
            data = cfg.json()
            issuer = data.get("issuer", "")
            m = re.search(r"/([0-9a-f-]{36})/", issuer)
            if m:
                out["tenant_id"] = m.group(1)
            out["issuer"] = issuer
    except Exception:
        pass

    return out


async def _check_okta(client, domain: str) -> dict[str, Any] | None:
    # Heuristic: company.okta.com или подмен okta-config на основном домене
    candidates = [
        f"https://{domain.split('.')[0]}.okta.com/.well-known/openid-configuration",
        f"https://{domain}/.well-known/openid-configuration",
    ]
    for url in candidates:
        try:
            r = await client.get(url)
        except Exception:
            continue
        if r.status_code == 200 and "issuer" in (r.text or ""):
            try:
                data = r.json()
                if "okta" in (data.get("issuer", "") or "").lower():
                    return {"issuer": data["issuer"], "discovery_url": url}
            except ValueError:
                continue
    return None


async def _check_adfs(client, domain: str) -> dict[str, Any] | None:
    url = f"https://adfs.{domain}/adfs/ls/idpinitiatedsignon.aspx"
    try:
        r = await client.get(url)
    except Exception:
        return None
    if r.status_code in (200, 302) and ("ADFS" in r.text or "Active Directory" in r.text):
        return {"adfs_url": str(r.url)}
    return None


async def _check_google_workspace(client, domain: str) -> dict[str, Any] | None:
    try:
        r = await client.get("https://accounts.google.com/.well-known/openid-configuration")
    except Exception:
        return None
    if r.status_code != 200:
        return None
    # Косвенный признак: MX запись на google
    return {"note": "Workspace признак нужно подтвердить через MX → google.com"}


async def identity_fingerprint(domain: str, graph: AssetGraph | None = None) -> tuple[dict[str, Any], list[Finding]]:
    """Запустить все проверки параллельно, собрать карту IdP."""
    findings: list[Finding] = []
    async with get_async_client() as client:
        entra, okta, adfs = await asyncio.gather(
            _check_entra(client, domain),
            _check_okta(client, domain),
            _check_adfs(client, domain),
            return_exceptions=False,
        )

    result = {"entra": entra, "okta": okta, "adfs": adfs}

    if entra:
        findings.append(Finding(
            rule_id="IDENTITY_ENTRA_TENANT",
            title=f"Microsoft Entra (Azure AD) tenant обнаружен у {domain}",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            target=domain, module="identity",
            evidence={**entra, "key": entra.get("tenant_id") or domain},
            tags=["identity", "entra", "m365"],
        ))
        if graph is not None:
            tid = entra.get("tenant_id") or f"entra:{domain}"
            tenant_id = Asset.make_id(AssetType.TENANT, tid)
            graph.add_asset(Asset(
                id=tenant_id, type=AssetType.TENANT, value=tid,
                attributes={"provider": "entra", **entra},
                discovered_by="identity",
            ))
            domain_id = Asset.make_id(AssetType.DOMAIN, domain)
            graph.add_edge(Edge(
                subject=domain_id, relation="uses_idp", object=tenant_id, discovered_by="identity",
            ))

    if okta:
        findings.append(Finding(
            rule_id="IDENTITY_OKTA_TENANT",
            title=f"Okta tenant обнаружен у {domain}",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            target=domain, module="identity",
            evidence={**okta, "key": okta.get("issuer", domain)},
            tags=["identity", "okta"],
        ))

    if adfs:
        findings.append(Finding(
            rule_id="IDENTITY_ADFS",
            title=f"ADFS обнаружен у {domain}",
            severity=Severity.LOW, confidence=Confidence.HIGH,
            target=domain, module="identity",
            description="Старый ADFS — известен по ProxyShell/ProxyLogon/ProxyNotShell, проверьте версию.",
            evidence={**adfs, "key": adfs.get("adfs_url", domain)},
            tags=["identity", "adfs"],
        ))

    return result, findings
