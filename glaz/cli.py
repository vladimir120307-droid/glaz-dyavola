"""CLI: `glaz <subcommand>`.

Sub-commands:
  glaz dns <domain>
  glaz subdomains <domain>
  glaz email-sec <domain>
  glaz secrets <path> [--baseline ...] [--sarif ...] [--workers N]
  glaz identity <domain>
  glaz ai-exposure <host[:port]> [<host>...]
  glaz ru egrul --inn <ИНН>
  glaz ru phone <номер>
  glaz ru vk <screen_name|url>
  glaz scan <domain> [--output report.json]
  glaz mcp serve [--stdio]

Все команды поддерживают --output/-o (json/jsonl/sarif/html) и --quiet/-q.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from glaz import __version__
from glaz.core.asset_graph import AssetGraph
from glaz.core.findings import FindingCollection, Severity
from glaz.core.output import OutputFormat, write_report

app = typer.Typer(
    name="glaz",
    help="Glaz Dyavola (Devil's Eye) — OSINT tool with RU layer (DNS, subdomains, secrets, identity, EGRUL, AI-exposure).",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
ru_app = typer.Typer(name="ru", help="Russian OSINT layer (EGRUL, VK, phones).", no_args_is_help=True)
mcp_app = typer.Typer(name="mcp", help="MCP server for Claude / local LLM integration.", no_args_is_help=True)
app.add_typer(ru_app)
app.add_typer(mcp_app)

console = Console()


def _save_if_requested(
    output: Path | None, findings: FindingCollection, graph: AssetGraph | None,
    fmt_hint: str | None,
) -> None:
    if output is None:
        return
    fmt = OutputFormat(fmt_hint) if fmt_hint else None
    write_report(output, findings, graph, fmt)
    rprint(f"[green]✓[/] отчёт сохранён в [bold]{output}[/]")


def _print_findings_table(findings: FindingCollection) -> None:
    if not findings:
        rprint("[dim]Находок нет.[/]")
        return
    stats = findings.stats()
    rprint(
        f"[bold]Итого:[/] {stats['total']} находок | "
        f"[red]critical={stats['critical']}[/] | "
        f"[orange3]high={stats['high']}[/] | "
        f"[yellow]medium={stats['medium']}[/] | "
        f"[blue]low={stats['low']}[/] | "
        f"[dim]info={stats['info']}[/]"
    )
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Sev")
    table.add_column("Module")
    table.add_column("Rule")
    table.add_column("Target", overflow="fold")
    table.add_column("Title", overflow="fold")
    sev_style = {
        Severity.CRITICAL: "red bold", Severity.HIGH: "orange3 bold",
        Severity.MEDIUM: "yellow", Severity.LOW: "blue", Severity.INFO: "dim",
    }
    for f in findings.sorted_by_severity():
        table.add_row(
            f"[{sev_style[f.severity]}]{f.severity.value.upper()}[/]",
            f.module, f.rule_id, f.target[:60], f.title[:80],
        )
    console.print(table)


_LOGO = r"""
        .---.
       /     \      [red]ГЛАЗ ДЬЯВОЛА[/]  [dim]/ Devil's Eye[/]
      | () () |     [dim]OSINT · Russian intel · MCP[/]
       \  ^  /
        '|=|'
"""


@app.command(name="version")
def version_cmd() -> None:
    """Показать версию + ASCII-лого."""
    rprint(_LOGO)
    rprint(f"  [bold]glaz-dyavola[/] [green]{__version__}[/]")


@app.command(name="dns")
def dns_cmd(
    domain: str = typer.Argument(..., help="Домен"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Файл отчёта"),
    fmt: str | None = typer.Option(None, "--format", help="json|jsonl|sarif|html"),
) -> None:
    """DNS-разведка: A/AAAA/MX/NS/TXT + DNSSEC."""
    from glaz.modules.dns import dns_passive_scan
    graph = AssetGraph()
    records, findings_list = dns_passive_scan(domain, graph=graph)

    rprint(f"[bold cyan]DNS records for {domain}:[/]")
    for rt, vals in records.items():
        if vals:
            rprint(f"  [bold]{rt}[/]: " + ", ".join(vals[:5]) + (f" [dim](+{len(vals)-5})[/]" if len(vals) > 5 else ""))
    findings = FindingCollection()
    findings.extend(findings_list)
    _print_findings_table(findings)
    _save_if_requested(output, findings, graph, fmt)


@app.command(name="email-sec")
def email_sec_cmd(
    domain: str = typer.Argument(..., help="Домен"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fmt: str | None = typer.Option(None, "--format"),
) -> None:
    """Аудит SPF/DMARC/DKIM/MTA-STS/TLS-RPT."""
    from glaz.modules.email_sec import audit_email_security
    findings = FindingCollection()
    findings.extend(audit_email_security(domain))
    _print_findings_table(findings)
    _save_if_requested(output, findings, None, fmt)


@app.command(name="subdomains")
def subdomains_cmd(
    domain: str = typer.Argument(..., help="Домен"),
    sources: str | None = typer.Option(None, "--sources", help="comma-list (crt.sh,alienvault,...)"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fmt: str | None = typer.Option(None, "--format"),
) -> None:
    """Перечисление поддоменов через 6 источников (crt.sh, OTX, ThreatMiner, ...)."""
    from glaz.modules.subdomains import enumerate_subdomains
    src_list = [s.strip() for s in sources.split(",")] if sources else None
    graph = AssetGraph()
    by_source = asyncio.run(enumerate_subdomains(domain, sources=src_list, graph=graph))
    all_hosts = by_source.pop("_all", set())
    for src, hosts in by_source.items():
        rprint(f"[bold]{src}[/]: {len(hosts)}")
    rprint(f"[bold green]Уникальных поддоменов: {len(all_hosts)}[/]")
    for h in sorted(all_hosts):
        print(h)
    if output:
        _save_if_requested(output, FindingCollection(), graph, fmt)


@app.command(name="secrets")
def secrets_cmd(
    path: Path = typer.Argument(..., exists=True, help="Файл или директория"),
    workers: int = typer.Option(4, "--workers", "-w", help="Параллельных воркеров"),
    baseline: Path | None = typer.Option(None, "--baseline", help="Игнор-лист (fingerprint per line или JSON)"),
    save_baseline: Path | None = typer.Option(None, "--save-baseline", help="Записать текущие fingerprint'ы как baseline"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    sarif: Path | None = typer.Option(None, "--sarif", help="SARIF-файл для GitHub code scanning"),
    fmt: str | None = typer.Option(None, "--format"),
) -> None:
    """Сканер секретов v2: 65+ паттернов, Шеннон-энтропия, дедуп, baseline, SARIF."""
    from glaz.modules.secrets import scan_path
    from glaz.modules.secrets.scanner import load_baseline, to_findings, write_baseline

    bl: set[str] = set()
    if baseline:
        bl = load_baseline(baseline)
        if bl:
            rprint(f"[dim]Baseline: подавляется {len(bl)} известных fingerprint'ов[/]")

    rprint(f"[cyan]Сканирую {path} ({workers} воркеров)...[/]")
    hits = list(scan_path(path, workers=workers, baseline=bl))
    graph = AssetGraph()
    finds = to_findings(hits, graph=graph)
    findings = FindingCollection()
    findings.extend(finds)

    _print_findings_table(findings)

    if save_baseline:
        write_baseline(save_baseline, findings)
        rprint(f"[green]✓[/] baseline записан в {save_baseline}")
    if sarif:
        write_report(sarif, findings, graph, OutputFormat.SARIF)
        rprint(f"[green]✓[/] SARIF: {sarif}")
    _save_if_requested(output, findings, graph, fmt)

    # Exit-код для CI: 1 если есть critical/high
    if findings.by_severity(Severity.CRITICAL) or findings.by_severity(Severity.HIGH):
        raise typer.Exit(code=1)


@app.command(name="identity")
def identity_cmd(
    domain: str = typer.Argument(..., help="Домен"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fmt: str | None = typer.Option(None, "--format"),
) -> None:
    """Identity-fabric fingerprint: Entra/Okta/ADFS/Google Workspace."""
    from glaz.modules.identity import identity_fingerprint
    graph = AssetGraph()
    result, finds = asyncio.run(identity_fingerprint(domain, graph=graph))
    findings = FindingCollection()
    findings.extend(finds)
    rprint(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    _print_findings_table(findings)
    _save_if_requested(output, findings, graph, fmt)


@app.command(name="ai-exposure")
def ai_exposure_cmd(
    targets: list[str] = typer.Argument(..., help="Хосты (host или http://host:port)"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fmt: str | None = typer.Option(None, "--format"),
) -> None:
    """Поиск экспонированных AI-сервисов: Open-WebUI, Ollama, Dify, Flowise, ComfyUI."""
    from glaz.modules.ai import scan_ai_exposure
    finds = asyncio.run(scan_ai_exposure(targets))
    findings = FindingCollection()
    findings.extend(finds)
    _print_findings_table(findings)
    _save_if_requested(output, findings, None, fmt)


# -------------- ru-subapp --------------

@ru_app.command("egrul")
def egrul_cmd(
    inn: str | None = typer.Option(None, "--inn", help="ИНН (10 цифр для ЮЛ, 12 для ИП)"),
    query: str | None = typer.Option(None, "--query", "-q", help="Поиск по названию (требует DADATA_API_KEY)"),
) -> None:
    """ЕГРЮЛ/ЕГРИП поиск (через DaData или egrul.nalog.ru)."""
    from glaz.modules.ru import lookup_by_inn, search_org
    if inn:
        result = lookup_by_inn(inn)
        if not result:
            rprint("[red]Не найдено или нет доступа к источнику.[/]")
            raise typer.Exit(2)
        rprint(json.dumps({k: v for k, v in result.items() if k != "raw"}, ensure_ascii=False, indent=2, default=str))
    elif query:
        results = search_org(query)
        if not results:
            rprint("[yellow]Поиск пуст или нужен DADATA_API_KEY[/]")
            raise typer.Exit(2)
        for r in results:
            rprint(f"[bold]{r.get('name_short')}[/] — ИНН {r.get('inn')}, ОГРН {r.get('ogrn')}")
            rprint(f"  адрес: {r.get('address')}")
    else:
        rprint("[red]Укажите --inn или --query[/]")
        raise typer.Exit(2)


@ru_app.command("phone")
def phone_cmd(
    number: str = typer.Argument(..., help="Телефон в любом формате (+7..., 8..., 7...)"),
) -> None:
    """RU-телефон: формат, оператор, регион."""
    from glaz.modules.ru import parse_phone
    info = parse_phone(number)
    rprint(f"[bold]E.164:[/] {info.e164 or '[red]invalid[/]'}")
    rprint(f"[bold]Тип:[/] {info.type}")
    if info.operator:
        rprint(f"[bold]Оператор:[/] {info.operator}")
    if info.region:
        rprint(f"[bold]Регион:[/] {info.region}")
    rprint(f"[bold]Валиден:[/] {info.valid}")


@ru_app.command("vk")
def vk_cmd(
    screen_name: str = typer.Argument(..., help="screen_name или URL вида vk.com/durov"),
) -> None:
    """VK: резолв screen_name → ID + тип."""
    from glaz.modules.ru import vk_resolve_screen_name
    res = vk_resolve_screen_name(screen_name)
    rprint(f"[bold]Screen name:[/] {res.screen_name}")
    rprint(f"[bold]Тип:[/] {res.type or '[dim]не определён[/]'}")
    rprint(f"[bold]ID:[/] {res.object_id or '[dim]не получен[/]'}")


@ru_app.command("tg")
def tg_cmd(
    username: str = typer.Argument(..., help="@username или t.me/<name>"),
) -> None:
    """Telegram: публичный lookup t.me/<username>."""
    from glaz.modules.ru import tg_lookup_username
    info = tg_lookup_username(username)
    if not info:
        rprint("[red]Не найдено или невалидный username.[/]")
        raise typer.Exit(2)
    rprint(f"[bold]Тип:[/] {info.type}")
    if info.title:
        rprint(f"[bold]Заголовок:[/] {info.title}")
    if info.description:
        rprint(f"[bold]Описание:[/] {info.description[:200]}")
    if info.members is not None:
        rprint(f"[bold]Участников:[/] {info.members:,}")


@ru_app.command("yandex")
def yandex_cmd(
    domain: str = typer.Argument(..., help="Домен"),
) -> None:
    """Яндекс-фингерпринт: Metrika ID, Yandex Cloud, бизнес-почта."""
    from glaz.modules.ru import fingerprint_yandex
    fp = fingerprint_yandex(domain)
    rprint(f"[bold]Метрика-ID:[/] {fp.metrika_ids or '[dim]не найдены[/]'}")
    rprint(f"[bold]Yandex Mail:[/] {fp.has_yandex_mail}")
    rprint(f"[bold]Yandex Cloud/CDN:[/] {fp.has_yandex_cdn}")
    for n in fp.notes:
        rprint(f"  [dim]·[/] {n}")


@ru_app.command("bic")
def bic_cmd(
    bic: str = typer.Argument(..., help="БИК (9 цифр)"),
) -> None:
    """БИК → название банка."""
    from glaz.modules.ru import lookup_bic
    info = lookup_bic(bic)
    rprint(f"[bold]БИК:[/] {info.bic}")
    rprint(f"[bold]Банк:[/] {info.name or '[red]не найден в справочнике[/]'}")


@ru_app.command("card")
def card_cmd(
    number: str = typer.Argument(..., help="Номер карты (минимум первые 6 цифр)"),
) -> None:
    """BIN/IIN карты: платёжная система + банк-эмитент (по короткой таблице)."""
    from glaz.modules.ru import parse_card_iin
    info = parse_card_iin(number)
    rprint(f"[bold]BIN:[/] {info['bin'] or '[red]invalid[/]'}")
    rprint(f"[bold]Платёжная система:[/] {info['scheme'] or '[dim]не определена[/]'}")
    rprint(f"[bold]Эмитент:[/] {info['issuer'] or '[dim]нет в справочнике[/]'}")


@ru_app.command("fssp")
def fssp_cmd(
    last_name: str = typer.Option(..., "--lastname", help="Фамилия"),
    first_name: str = typer.Option(..., "--firstname", help="Имя"),
    middle_name: str = typer.Option("", "--middlename", help="Отчество"),
    birthdate: str | None = typer.Option(None, "--birthdate", help="ДД.ММ.ГГГГ"),
    region: int = typer.Option(0, "--region", help="Код региона ФССП (0 = все)"),
) -> None:
    """ФССП — поиск исполнительных производств. Требует FSSP_TOKEN в env."""
    from glaz.modules.ru import search_individual
    res = search_individual(last_name, first_name, middle_name, birthdate, region)
    if res is None:
        rprint("[red]FSSP_TOKEN не установлен или сервис недоступен.[/]")
        raise typer.Exit(2)
    if not res:
        rprint("[green]Производств не найдено.[/]")
        return
    for r in res:
        rprint(f"[bold red]{r.case_number}[/] — {r.name}")
        rprint(f"  отдел: {r.department}, остаток: {r.sum_left}, пристав: {r.bailiff_name}")


# -------------- web --------------

@app.command("web")
def web_cmd(
    url: str = typer.Argument(..., help="Базовый URL (http://host или host)"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fmt: str | None = typer.Option(None, "--format"),
) -> None:
    """Web attack-surface: Swagger/GraphQL/JS-endpoints/security-headers."""
    from glaz.modules.web import discover_web_surface
    _, common = asyncio.run(discover_web_surface(url))
    findings = FindingCollection()
    findings.extend(common)
    _print_findings_table(findings)
    _save_if_requested(output, findings, None, fmt)


# -------------- discovery --------------

discovery_app = typer.Typer(name="discovery", help="WHOIS/RDAP, passive DNS, TLD enum.", no_args_is_help=True)
app.add_typer(discovery_app)


@discovery_app.command("whois")
def whois_cmd(
    domain: str = typer.Argument(..., help="Домен"),
) -> None:
    """WHOIS/RDAP сводка."""
    from glaz.modules.discovery import whois_summary
    rec = whois_summary(domain)
    if not rec:
        rprint("[red]Нет данных WHOIS/RDAP для этого TLD.[/]")
        raise typer.Exit(2)
    rprint(f"[bold]Domain:[/] {rec.domain}")
    rprint(f"[bold]Registrar:[/] {rec.registrar}")
    rprint(f"[bold]Created:[/] {rec.creation_date}")
    rprint(f"[bold]Expires:[/] {rec.expiration_date}")
    rprint(f"[bold]Updated:[/] {rec.updated_date}")
    rprint(f"[bold]NS:[/] {', '.join(rec.name_servers)}")
    rprint(f"[bold]Status:[/] {', '.join(rec.status)}")


@discovery_app.command("pdns")
def pdns_cmd(
    domain: str = typer.Argument(..., help="Домен"),
) -> None:
    """Passive DNS — историческое разрешение хостов."""
    from glaz.modules.discovery import passive_dns_lookup
    res = asyncio.run(passive_dns_lookup(domain))
    rprint(f"[bold green]Получено {len(res)} pDNS-записей[/]")
    for r in res[:30]:
        rprint(f"  {r.host} → {r.ip or '[dim]?[/]'}  [dim]({r.source}, {r.first_seen}…{r.last_seen})[/]")


@discovery_app.command("tld")
def tld_cmd(
    brand: str = typer.Argument(..., help="Имя бренда без TLD (например `acme`)"),
) -> None:
    """TLD-энумерация: проверить acme.com, .net, .ru, .io и т.д."""
    from glaz.modules.discovery import enumerate_tlds
    res = asyncio.run(enumerate_tlds(brand))
    rprint(f"[bold green]{len(res)} существующих доменов из {len(res)} проверенных:[/]")
    for h in res:
        rprint(f"  [bold]{h.domain}[/]: {', '.join(h.sample_records[:2])}")


# -------------- validators --------------

@app.command("validate")
def validate_cmd(
    provider: str = typer.Argument(..., help="aws / github / gitlab / slack / anthropic / openai / postman / atlassian / datadog / npm"),
    token: str | None = typer.Option(None, "--token", help="Токен / API key"),
    secret: str | None = typer.Option(None, "--secret", help="AWS secret key"),
    session_token: str | None = typer.Option(None, "--session-token"),
    email: str | None = typer.Option(None, "--email", help="Atlassian email"),
    host: str | None = typer.Option(None, "--host", help="Atlassian/GitLab host"),
    app_key: str | None = typer.Option(None, "--app-key", help="Datadog app key"),
) -> None:
    """Read-only валидация креда: жив или протух."""
    from glaz.modules.validators import validate
    creds: dict = {}
    if provider == "aws":
        if not (token and secret):
            rprint("[red]Нужны --token (access key) и --secret[/]")
            raise typer.Exit(2)
        creds = {"access_key": token, "secret_key": secret, "session_token": session_token}
    elif provider == "atlassian":
        if not (email and token and host):
            rprint("[red]Нужны --email --token --host (subdomain.atlassian.net)[/]")
            raise typer.Exit(2)
        creds = {"email": email, "token": token, "host": host}
    elif provider == "datadog":
        if not token:
            rprint("[red]Нужен --token (DD-API-KEY)[/]")
            raise typer.Exit(2)
        creds = {"api_key": token, "app_key": app_key}
    elif provider == "gitlab":
        creds = {"token": token, "host": host or "gitlab.com"}
    else:
        creds = {"key" if provider in ("anthropic", "openai", "postman") else "token": token}

    res = asyncio.run(validate(provider, **creds))
    if res.valid:
        rprint(f"[bold green]✓ ЖИВОЙ[/]: {res.identity or '?'}")
        if res.scopes:
            rprint(f"  scopes: {', '.join(res.scopes)}")
        rprint(json.dumps(res.raw, ensure_ascii=False, indent=2, default=str))
    else:
        rprint(f"[bold red]✗ невалиден[/]: {res.error}")
        raise typer.Exit(1)


# -------------- people --------------

people_app = typer.Typer(name="people", help="People-OSINT: email permutations + username discovery.", no_args_is_help=True)
app.add_typer(people_app)


@people_app.command("emails")
def people_emails_cmd(
    first: str = typer.Argument(..., help="Имя"),
    last: str = typer.Argument(..., help="Фамилия"),
    domain: str = typer.Argument(..., help="Корпоративный домен"),
    middle: str = typer.Option("", "--middle", help="Отчество (для RU-схем)"),
    limit: int = typer.Option(10, "--limit", help="Сколько вариантов показать"),
) -> None:
    """Сгенерировать probable email-адреса по имени + домену."""
    from glaz.modules.people import generate_email_permutations
    guesses = generate_email_permutations(first, last, domain, middle=middle)
    for g in guesses[:limit]:
        rprint(f"  [bold]{g.address}[/]  [dim]w={g.weight:.2f}[/]")


@people_app.command("usernames")
def people_usernames_cmd(
    username: str = typer.Argument(..., help="Username для проверки"),
    platforms: str | None = typer.Option(None, "--platforms",
                                          help="Список платформ через запятую (default: все)"),
    only_found: bool = typer.Option(False, "--only-found", help="Показывать только существующие"),
) -> None:
    """Проверить существование username на 28 публичных платформах."""
    from glaz.modules.people import check_usernames
    plats = [s.strip() for s in platforms.split(",")] if platforms else None
    results = asyncio.run(check_usernames(username, platforms=plats))
    for r in results:
        if only_found and not r.exists:
            continue
        mark = "[green]✓[/]" if r.exists else "[dim]✗[/]"
        conf = f"[dim]({r.confidence})[/]"
        rprint(f"  {mark} [bold]{r.platform:14}[/] {r.url}  {conf}")


# -------------- ASN --------------

@app.command("asn")
def asn_cmd(
    target: str = typer.Argument(..., help="IP-адрес или ASN-номер"),
) -> None:
    """ASN/netblock lookup. IP → ASN/CIDR/AS-name. Число → announced prefixes."""
    from glaz.modules.asn import asn_for_ip, netblock_for_asn
    if target.isdigit():
        asn = int(target)
        prefixes = netblock_for_asn(asn)
        rprint(f"[bold]AS{asn}[/]: {len(prefixes)} announced prefixes")
        for p in prefixes[:30]:
            rprint(f"  {p}")
    else:
        rec = asn_for_ip(target)
        rprint(f"[bold]IP:[/] {rec.ip}")
        rprint(f"[bold]ASN:[/] AS{rec.asn or '?'} {rec.asn_name or ''}")
        rprint(f"[bold]Netblock:[/] {rec.netblock or '?'}")
        rprint(f"[bold]Country:[/] {rec.country or '?'}")


# -------------- subdomains sweep --------------

@app.command("sweep")
def sweep_cmd(
    domain: str = typer.Argument(..., help="Домен"),
    workers: int = typer.Option(32, "--workers", help="Параллельных DNS-запросов"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Common-prefix sweep: 120+ корпоративных префиксов (admin/dev/api/staging/...)."""
    from glaz.modules.subdomains import sweep
    graph = AssetGraph()
    found = asyncio.run(sweep(domain, workers=workers, graph=graph))
    rprint(f"[bold green]{len(found)} существующих хостов:[/]")
    for h in found:
        rprint(f"  {h}")
    if output:
        write_report(output, FindingCollection(), graph)
        rprint(f"[green]✓[/] {output}")


# -------------- visualize --------------

@app.command("visualize")
def visualize_cmd(
    report: Path = typer.Argument(..., exists=True, help="JSON-отчёт от `glaz scan`"),
    fmt: str = typer.Option("mermaid", "--format", help="mermaid | dot"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Asset graph → Mermaid (для README) / DOT (для graphviz)."""
    import json as _json

    from glaz.core import AssetGraph as _AssetGraph
    from glaz.core import to_dot, to_mermaid
    from glaz.core.asset_graph import Asset as _Asset
    from glaz.core.asset_graph import AssetType as _AssetType
    from glaz.core.asset_graph import Edge as _Edge

    data = _json.loads(report.read_text(encoding="utf-8"))
    graph = _AssetGraph()
    for a in (data.get("graph") or {}).get("assets", []):
        graph.add_asset(_Asset(
            id=a["id"], type=_AssetType(a["type"]), value=a["value"],
            attributes=a.get("attributes", {}),
            tags=a.get("tags", []),
            discovered_by=a.get("discovered_by", "manual"),
        ))
    for e in (data.get("graph") or {}).get("edges", []):
        graph.add_edge(_Edge(subject=e["subject"], relation=e["relation"], object=e["object"]))

    out = to_mermaid(graph) if fmt == "mermaid" else to_dot(graph)
    if output:
        output.write_text(out, encoding="utf-8")
        rprint(f"[green]✓[/] {output}")
    else:
        print(out)


# -------------- agg-scan --------------

@app.command("scan")
def full_scan_cmd(
    domain: str = typer.Argument(..., help="Целевой домен"),
    output: Path | None = typer.Option(Path("glaz_report.json"), "--output", "-o", help="Файл отчёта"),
    skip: str | None = typer.Option(None, "--skip", help="Пропустить модули (comma list: dns,subdomains,...)"),
) -> None:
    """Полный пас: DNS + email-sec + subdomains + identity. Один отчёт."""
    from glaz.modules.dns import dns_passive_scan
    from glaz.modules.email_sec import audit_email_security
    from glaz.modules.identity import identity_fingerprint
    from glaz.modules.subdomains import enumerate_subdomains

    skip_set = {s.strip() for s in skip.split(",")} if skip else set()
    findings = FindingCollection()
    graph = AssetGraph()

    if "dns" not in skip_set:
        rprint("[cyan]→ DNS[/]")
        _, fl = dns_passive_scan(domain, graph=graph)
        findings.extend(fl)

    if "email-sec" not in skip_set:
        rprint("[cyan]→ email-sec[/]")
        findings.extend(audit_email_security(domain))

    if "subdomains" not in skip_set:
        rprint("[cyan]→ subdomains (crt.sh + fallbacks)[/]")
        try:
            asyncio.run(enumerate_subdomains(domain, graph=graph))
        except Exception as e:  # noqa: BLE001
            rprint(f"[yellow]subdomains: {e}[/]")

    if "identity" not in skip_set:
        rprint("[cyan]→ identity-fabric[/]")
        try:
            _, fl = asyncio.run(identity_fingerprint(domain, graph=graph))
            findings.extend(fl)
        except Exception as e:  # noqa: BLE001
            rprint(f"[yellow]identity: {e}[/]")

    _print_findings_table(findings)
    write_report(output, findings, graph)
    rprint(f"[green]✓[/] отчёт: {output} (assets: {len(graph)}, findings: {len(findings)})")


# -------------- mcp -----------------

@mcp_app.command("serve")
def mcp_serve_cmd(
    stdio: bool = typer.Option(True, "--stdio/--no-stdio", help="Транспорт stdio (для Claude Code)"),
) -> None:
    """Запуск MCP-сервера. Подключение в settings.json: \"glaz\": {\"command\":\"glaz\",\"args\":[\"mcp\",\"serve\",\"--stdio\"]}"""
    try:
        from glaz.mcp.server import run_stdio
    except ImportError as e:
        rprint(f"[red]MCP-зависимость не установлена[/]: {e}")
        rprint("Поставьте через: [bold]pip install 'glaz-dyavola[mcp]'[/]")
        raise typer.Exit(2) from e
    if stdio:
        asyncio.run(run_stdio())
    else:
        rprint("[red]Только stdio пока поддерживается[/]")
        raise typer.Exit(2)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
