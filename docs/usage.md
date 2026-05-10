# Использование

## Установка

```bash
git clone https://github.com/vladimir/glaz-dyavola.git
cd glaz-dyavola
pip install -e .

# С MCP-сервером для интеграции с Claude / локальной LLM
pip install -e ".[mcp]"
```

## CLI

### DNS-разведка

```bash
glaz dns example.com
glaz dns example.com --output dns.json
```

Возвращает A/AAAA/MX/NS/TXT/SOA/CNAME/CAA + проверку DNSSEC.

### Email-security аудит

```bash
glaz email-sec example.com
glaz email-sec example.com --format sarif --output email.sarif
```

Аудит SPF/DMARC/DKIM/MTA-STS/TLS-RPT с разбором политик. Типичные находки:
- SPF отсутствует или `+all`
- DMARC `p=none` (мониторинг, не enforcement)
- DMARC без `rua` (отчёты не приходят)
- MTA-STS / TLS-RPT не настроены

### Поддомены

```bash
glaz subdomains example.com

# Конкретные источники
glaz subdomains example.com --sources crt.sh,wayback,alienvault
```

Источники (все без API-ключей):
- `crt.sh` (CT logs)
- `alienvault` (OTX passive DNS)
- `threatminer`
- `hackertarget` (rate-limited)
- `rapiddns`
- `wayback` (history)

### Сканер секретов v2

```bash
# Просто сканирование
glaz secrets ./repo

# С baseline (игнор известных false-positive)
glaz secrets ./repo --baseline .glaz-baseline.json

# Записать текущие fingerprints как baseline
glaz secrets ./repo --save-baseline .glaz-baseline.json

# SARIF для GitHub code scanning
glaz secrets ./repo --sarif glaz.sarif --workers 8
```

65+ паттернов: AWS / GCP / Azure / GitHub / GitLab / Stripe / Slack / Discord /
Telegram / SendGrid / Twilio / Cloudflare / DigitalOcean / Heroku / Anthropic /
OpenAI / HuggingFace / Mistral / Cohere / Together / Replicate / Fireworks /
RunPod / DeepSeek / Groq / Perplexity / LangSmith / npm / PyPI / Docker Hub /
Atlassian / Linear / Notion / Asana / Figma / Airtable / Supabase / New Relic /
Datadog / Honeycomb / JWT / private keys / Yandex / VK + generic API key.

Шеннон-энтропия фильтрует ложные срабатывания на типичных переменных вроде
`apikey="xxxxxxxxxxxxxxxxxxxxxxxxx"` (низкая энтропия → отбрасывается).

Exit code: 1 если найдены критические/high находки → удобно для CI.

### Identity-fabric fingerprint

```bash
glaz identity example.com
```

Определяет, какие IdP / SSO-провайдеры использует домен:
- Microsoft Entra (Azure AD) tenant + GUID
- Okta tenant slug
- ADFS endpoint
- Google Workspace OIDC

### AI-инфраструктура

```bash
glaz ai-exposure 192.168.1.50:11434 example.com:7860 my-server.com
```

Ищет публично доступные AI-сервисы без аутентификации:
Open-WebUI / Ollama / LocalAI / Dify / Flowise / Langflow / LangSmith
Playground / AnythingLLM / ComfyUI / Stable Diffusion WebUI.

### RU-слой

```bash
# ЕГРЮЛ/ЕГРИП по ИНН
glaz ru egrul --inn 7707083893

# По названию (нужен DADATA_API_KEY)
glaz ru egrul --query "Сбербанк"

# Парсинг RU-телефона
glaz ru phone "+7 (916) 123-45-67"
glaz ru phone 89261234567

# VK screen_name → object_id
glaz ru vk durov
glaz ru vk https://vk.com/durov
```

### Полный пас

```bash
glaz scan example.com --output report.json

# Пропустить медленные модули
glaz scan example.com --skip subdomains,identity
```

Запускает DNS + email-sec + subdomains + identity и собирает единый отчёт.

## MCP-сервер

```bash
glaz mcp serve --stdio
```

В `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "glaz": {
      "command": "glaz",
      "args": ["mcp", "serve", "--stdio"]
    }
  }
}
```

После рестарта Claude Code увидит 9 новых tools:
`dns_lookup`, `email_security_audit`, `subdomain_enum`, `identity_fingerprint`,
`secret_scan_text`, `egrul_lookup`, `parse_ru_phone`, `vk_resolve`,
`ai_exposure_check`.

Локальная LLM с tool-calling (vLLM с function-calling, Open-WebUI с tool plugin)
тоже подключается через стандартный MCP.

## Переменные окружения

| Переменная | Что делает |
|---|---|
| `DADATA_API_KEY` | Подробный поиск ЕГРЮЛ через DaData (без него — fallback на `egrul.nalog.ru`) |
| `VK_SERVICE_KEY` | VK API service key для `utils.resolveScreenName` (без него — парсинг публичной страницы) |
| `PYTHONIOENCODING=utf-8` | Рекомендуется на Windows для корректного вывода кириллицы |

## Форматы отчёта

| Расширение | Формат |
|---|---|
| `.json` | Полный отчёт: findings + asset graph + stats |
| `.jsonl` | Один JSON на строку — для стриминга |
| `.sarif` | SARIF 2.1.0 — для GitHub code scanning |
| `.html` | HTML-отчёт без зависимостей (для отправки клиенту) |
