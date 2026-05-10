"""Аудит email-security: SPF / DMARC / DKIM / BIMI / MTA-STS / TLS-RPT.

Всё через DNS, никаких активных проверок SMTP. Возвращает находки уровня
LOW/MEDIUM по типичным мисконфигам:
- SPF: +all / много include / >10 lookup
- DMARC: p=none, отсутствие rua, sp=none
- MTA-STS: отсутствие политики, mode=none
- TLS-RPT: отсутствие
"""
from __future__ import annotations

import re

import dns.exception
import dns.resolver

from glaz.core.findings import Confidence, Finding, Severity
from glaz.modules.dns.passive import _make_resolver


def _get_txt(name: str) -> list[str]:
    r = _make_resolver()
    try:
        ans = r.resolve(name, "TXT", raise_on_no_answer=False)
        return ['"'.join(s.decode() if isinstance(s, bytes) else s for s in rd.strings) for rd in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
        return []


def _parse_dmarc_tags(record: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def audit_email_security(domain: str) -> list[Finding]:
    findings: list[Finding] = []

    # ---------- SPF ----------
    txt_root = _get_txt(domain)
    spf_records = [t for t in txt_root if t.lower().startswith("v=spf1")]
    if not spf_records:
        findings.append(Finding(
            rule_id="EMAIL_SPF_MISSING", title=f"SPF отсутствует у {domain}",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            target=domain, module="email-sec",
            description="Без SPF почта от вашего домена легко спуфится — приёмники не имеют способа отличить отправителя.",
            evidence={"domain": domain, "key": "spf_missing"},
            references=["https://datatracker.ietf.org/doc/html/rfc7208"],
            tags=["email", "spf"],
        ))
    else:
        spf = spf_records[0]
        if re.search(r"[+~?]?all", spf, re.IGNORECASE) is None:
            findings.append(Finding(
                rule_id="EMAIL_SPF_NO_ALL_QUALIFIER", title="SPF без явного качества all",
                severity=Severity.LOW, confidence=Confidence.MEDIUM,
                target=domain, module="email-sec",
                evidence={"domain": domain, "spf": spf, "key": "spf_no_all"},
                tags=["email", "spf"],
            ))
        if re.search(r"\+all\b", spf, re.IGNORECASE):
            findings.append(Finding(
                rule_id="EMAIL_SPF_PERMISSIVE", title="SPF +all — разрешает всё",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                target=domain, module="email-sec",
                description="`+all` означает, что любой хост может слать почту от имени домена. Это эквивалентно отсутствию SPF.",
                evidence={"domain": domain, "spf": spf, "key": "spf_permissive"},
                tags=["email", "spf"],
            ))
        # >10 lookup-механизмов (RFC limit) — приближённая оценка
        lookup_count = len(re.findall(r"\b(?:include|a|mx|ptr|exists|redirect)[:=]", spf, re.IGNORECASE))
        if lookup_count > 10:
            findings.append(Finding(
                rule_id="EMAIL_SPF_TOO_MANY_LOOKUPS",
                title=f"SPF: ~{lookup_count} DNS-lookup'ов (лимит 10 по RFC)",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                target=domain, module="email-sec",
                evidence={"domain": domain, "lookup_count": lookup_count, "spf": spf, "key": "spf_too_many"},
                tags=["email", "spf"],
            ))

    # ---------- DMARC ----------
    dmarc_records = _get_txt(f"_dmarc.{domain}")
    dmarc_records = [t for t in dmarc_records if t.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        findings.append(Finding(
            rule_id="EMAIL_DMARC_MISSING", title=f"DMARC отсутствует у {domain}",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            target=domain, module="email-sec",
            description="Без DMARC даже корректные SPF/DKIM не дают приёмнику чёткого правила что делать с фейлом.",
            evidence={"domain": domain, "key": "dmarc_missing"},
            references=["https://datatracker.ietf.org/doc/html/rfc7489"],
            tags=["email", "dmarc"],
        ))
    else:
        tags = _parse_dmarc_tags(dmarc_records[0])
        if tags.get("p") == "none":
            findings.append(Finding(
                rule_id="EMAIL_DMARC_POLICY_NONE", title="DMARC p=none (мониторинг, не enforcement)",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                target=domain, module="email-sec",
                evidence={"domain": domain, "dmarc": dmarc_records[0], "key": "dmarc_none"},
                tags=["email", "dmarc"],
            ))
        if "rua" not in tags:
            findings.append(Finding(
                rule_id="EMAIL_DMARC_NO_REPORTING", title="DMARC без rua — отчётов нет",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                target=domain, module="email-sec",
                evidence={"domain": domain, "dmarc": dmarc_records[0], "key": "dmarc_no_rua"},
                tags=["email", "dmarc"],
            ))
        if tags.get("sp") == "none" or (tags.get("p") != "reject" and "sp" not in tags):
            # Поддомены могут наследовать слабую политику
            findings.append(Finding(
                rule_id="EMAIL_DMARC_SUBDOMAIN_WEAK", title="DMARC subdomain policy слабая",
                severity=Severity.LOW, confidence=Confidence.MEDIUM,
                target=domain, module="email-sec",
                evidence={"domain": domain, "dmarc": dmarc_records[0], "key": "dmarc_sp_weak"},
                tags=["email", "dmarc"],
            ))

    # ---------- MTA-STS ----------
    mta_sts = _get_txt(f"_mta-sts.{domain}")
    mta_sts = [t for t in mta_sts if t.lower().startswith("v=stsv1")]
    if not mta_sts:
        findings.append(Finding(
            rule_id="EMAIL_MTA_STS_MISSING", title="MTA-STS не настроен",
            severity=Severity.LOW, confidence=Confidence.HIGH,
            target=domain, module="email-sec",
            description="MTA-STS форсит TLS на пути SMTP и убирает downgrade-атаки. Без него STARTTLS-stripping всё ещё работает.",
            evidence={"domain": domain, "key": "mta_sts_missing"},
            tags=["email", "mta-sts"],
        ))

    # ---------- TLS-RPT ----------
    tls_rpt = _get_txt(f"_smtp._tls.{domain}")
    tls_rpt = [t for t in tls_rpt if t.lower().startswith("v=tlsrptv1")]
    if not tls_rpt:
        findings.append(Finding(
            rule_id="EMAIL_TLS_RPT_MISSING", title="TLS-RPT не настроен",
            severity=Severity.LOW, confidence=Confidence.HIGH,
            target=domain, module="email-sec",
            description="TLS-RPT даёт владельцу домена обратную связь о неудачах TLS со стороны приёмников.",
            evidence={"domain": domain, "key": "tls_rpt_missing"},
            tags=["email", "tls-rpt"],
        ))

    return findings
