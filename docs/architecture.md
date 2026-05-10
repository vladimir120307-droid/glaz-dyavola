# Архитектура

## Слои

```
┌──────────────────────────────────────────────────────────────┐
│  CLI (typer)                  MCP server (stdio)             │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│  Modules                                                      │
│  ┌────────┐ ┌────────────┐ ┌────────┐ ┌──────────┐ ┌──────┐  │
│  │  dns   │ │  subdoms   │ │secrets │ │ identity │ │  ru  │  │
│  └────────┘ └────────────┘ └────────┘ └──────────┘ └──────┘  │
│  ┌──────────┐ ┌────────────┐                                  │
│  │ email-sec│ │ ai-exposure│                                  │
│  └──────────┘ └────────────┘                                  │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│  Core                                                         │
│  • asset_graph (Asset, Edge, AssetGraph)                      │
│  • findings (Severity, Confidence, Finding, FindingCollection)│
│  • output (JSON/JSONL/SARIF/HTML)                             │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│  Utils                                                        │
│  • entropy (Shannon)        • http (httpx wrapper)            │
└──────────────────────────────────────────────────────────────┘
```

## Модель данных

### Asset Graph

Ориентированный граф наблюдаемых активов: Asset (узел) + Edge (ребро,
типизированное `relation`).

**Типы Asset'ов** — DOMAIN, SUBDOMAIN, IP, ASN, NETBLOCK, URL, EMAIL, ORG,
PERSON, PHONE, REPOSITORY, CLOUD_RESOURCE, CERT, SECRET, TENANT, FILE.

**Типичные relation'ы** — `resolves_to`, `subdomain_of`, `uses_idp`, `manages`,
`found_in`, `owned_by`, `leaked_at`.

ID активов — `<type>:<value_lowercase>`. Это даёт стабильную идемпотентность:
два модуля, обнаружившие тот же актив, мерджат attribute'ы вместо дублирования.

### Findings

Модель находки: `(rule_id, severity, confidence, target, evidence)`.

**Fingerprint** для дедупа — sha256 от `(rule_id, target, evidence.key|match)[:16]`.
Два модуля, нашедшие "то же самое" — выдадут одну находку.

**Severity rubric** — CRITICAL / HIGH / MEDIUM / LOW / INFO. Соответствует
SARIF-маппингу (`error` / `error` / `warning` / `note` / `note`).

**Confidence** — CONFIRMED / HIGH / MEDIUM / LOW. Передаёт неопределённость
эвристик: regex попался → MEDIUM, валидатор подтвердил → CONFIRMED.

## Output

| Формат | Use case |
|---|---|
| JSON | Архив отчёта (полный граф + находки) |
| JSONL | Стриминг, line-by-line обработка |
| SARIF | GitHub code scanning, Azure DevOps, Sonatype |
| HTML | Презентация, e-mail клиенту |

## MCP server

Каждый модуль экспонируется как отдельный MCP-tool. Это позволяет:

- Claude Code дёргать модули из чата как первоклассные инструменты
- Локальной LLM (Qwen/Llama/Mistral через Open-WebUI или vLLM с tool-calling)
  использовать ровно тот же набор инструментов
- Объединять с другими MCP-серверами (filesystem, fetch, github) в одной сессии

## Производительность

- **Subdomains**: 6 источников параллельно через `asyncio.gather` →
  worst-case latency = max(slowest source), а не sum.
- **Secrets**: `ProcessPoolExecutor` для директорий >50 файлов. Регексы
  компилируются один раз и переиспользуются всеми воркерами.
- **DNS**: `dnspython` с явными trusted resolver'ами (1.1.1.1/9.9.9.9/8.8.8.8),
  таймаут 4с/запрос.

## Расширение

Чтобы добавить новый модуль:

1. Создайте `glaz/modules/<name>/__init__.py` + `<name>/<entrypoint>.py`
2. Возвращайте `list[Finding]` (или `tuple[dict, list[Finding]]`)
3. Опционально интегрируйтесь с `AssetGraph` (добавляйте узлы и рёбра)
4. Добавьте subcommand в `glaz/cli.py`
5. (Опционально) экспонируйте как MCP-tool в `glaz/mcp/server.py`
6. Тесты в `tests/test_<name>.py`
