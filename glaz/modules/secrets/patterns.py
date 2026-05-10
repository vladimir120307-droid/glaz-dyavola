"""Каталог regex-паттернов секретов.

Расширенный относительно базовых утилит: 65+ паттернов, включая современные
AI/LLM-провайдеры (Mistral, Cohere, Together, Replicate, Fireworks, RunPod,
DeepSeek), package-registry токены, observability, RU-сегмент.

Порядок важен: специфичные паттерны идут перед общими, чтобы не переловить.
"""
from __future__ import annotations

from dataclasses import dataclass

from glaz.core.findings import Severity


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    severity: Severity
    category: str
    regex: str
    description: str = ""
    # Минимальная энтропия для capture-группы (если 0 — не проверяем).
    # Применяется к group(1) если есть, иначе к group(0).
    min_entropy: float = 0.0
    # Если capture group задан — его смотрим, иначе group(0).
    entropy_group: int = 0


PATTERNS: list[SecretPattern] = [
    # ========================= AWS =========================
    SecretPattern("SECRET_AWS_ACCESS_KEY", Severity.CRITICAL, "aws",
                  r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "AWS Access Key ID"),
    SecretPattern("SECRET_AWS_SECRET_TYPED", Severity.CRITICAL, "aws",
                  r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})",
                  "AWS Secret Access Key (typed)", min_entropy=4.0, entropy_group=1),
    SecretPattern("SECRET_AWS_SESSION_TOKEN", Severity.HIGH, "aws",
                  r"(?i)aws[_\-]?session[_\-]?token['\"\s:=]+([A-Za-z0-9/+=]{100,})",
                  "AWS Session Token", entropy_group=1, min_entropy=4.5),

    # ========================= GCP =========================
    SecretPattern("SECRET_GCP_SERVICE_ACCOUNT", Severity.CRITICAL, "gcp",
                  r'"type"\s*:\s*"service_account"', "GCP service account JSON"),
    SecretPattern("SECRET_GOOGLE_API_KEY", Severity.HIGH, "gcp",
                  r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google API Key"),
    SecretPattern("SECRET_GOOGLE_OAUTH_REFRESH", Severity.HIGH, "gcp",
                  r"\b1//0[A-Za-z0-9_\-]{30,}\b", "Google OAuth refresh token"),

    # ========================= Azure =========================
    SecretPattern("SECRET_AZURE_STORAGE_KEY", Severity.HIGH, "azure",
                  r"(?i)(?:account[_\-]?key|sharedaccesskey)['\"\s:=]+([A-Za-z0-9+/=]{86,88})",
                  "Azure storage account key", entropy_group=1, min_entropy=4.5),
    SecretPattern("SECRET_AZURE_AD_CLIENT_SECRET", Severity.HIGH, "azure",
                  r"\b[A-Za-z0-9_~\-.]{34,40}\.[A-Za-z0-9_~\-.]{3}-[A-Za-z0-9_~\-.]{34,40}\b",
                  "Azure AD client secret (v2 format heuristic)"),

    # ========================= GitHub =========================
    SecretPattern("SECRET_GH_PAT_CLASSIC", Severity.CRITICAL, "github",
                  r"\bghp_[A-Za-z0-9]{36}\b", "GitHub Personal Access Token (classic)"),
    SecretPattern("SECRET_GH_PAT_FINEGRAINED", Severity.CRITICAL, "github",
                  r"\bgithub_pat_[A-Za-z0-9_]{82}\b", "GitHub PAT (fine-grained)"),
    SecretPattern("SECRET_GH_OAUTH", Severity.HIGH, "github",
                  r"\bgho_[A-Za-z0-9]{36}\b", "GitHub OAuth"),
    SecretPattern("SECRET_GH_S2S", Severity.HIGH, "github",
                  r"\bgh[usr]_[A-Za-z0-9]{36,}\b", "GitHub server-to-server"),
    SecretPattern("SECRET_GH_APP_INSTALL", Severity.HIGH, "github",
                  r"\bv1\.[a-f0-9]{40}\b", "GitHub App installation token"),

    # ========================= GitLab / Bitbucket =========================
    SecretPattern("SECRET_GITLAB_PAT", Severity.HIGH, "gitlab",
                  r"\bglpat-[A-Za-z0-9_\-]{20,}\b", "GitLab PAT"),
    SecretPattern("SECRET_GITLAB_PIPELINE", Severity.MEDIUM, "gitlab",
                  r"\bglptt-[A-Za-z0-9_\-]{20,}\b", "GitLab pipeline trigger token"),
    SecretPattern("SECRET_BITBUCKET_APP", Severity.HIGH, "bitbucket",
                  r"\bATBB[A-Za-z0-9]{32,}\b", "Bitbucket app password"),

    # ========================= Stripe / Payments =========================
    SecretPattern("SECRET_STRIPE_LIVE", Severity.CRITICAL, "stripe",
                  r"\bsk_live_[0-9A-Za-z]{24,}\b", "Stripe live secret key"),
    SecretPattern("SECRET_STRIPE_TEST", Severity.LOW, "stripe",
                  r"\bsk_test_[0-9A-Za-z]{24,}\b", "Stripe test key"),
    SecretPattern("SECRET_STRIPE_RESTRICTED", Severity.HIGH, "stripe",
                  r"\brk_live_[0-9A-Za-z]{24,}\b", "Stripe restricted key"),
    SecretPattern("SECRET_PAYPAL_BRAINTREE", Severity.HIGH, "stripe",
                  r"\baccess_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}\b",
                  "PayPal Braintree production token"),

    # ========================= Slack / Discord / Telegram =========================
    SecretPattern("SECRET_SLACK_TOKEN", Severity.HIGH, "slack",
                  r"\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b", "Slack token"),
    SecretPattern("SECRET_SLACK_WEBHOOK", Severity.MEDIUM, "slack",
                  r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
                  "Slack incoming webhook"),
    SecretPattern("SECRET_DISCORD_BOT", Severity.HIGH, "discord",
                  r"\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b", "Discord bot token"),
    SecretPattern("SECRET_DISCORD_WEBHOOK", Severity.MEDIUM, "discord",
                  r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
                  "Discord webhook"),
    SecretPattern("SECRET_TELEGRAM_BOT", Severity.HIGH, "telegram",
                  r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b", "Telegram bot token"),

    # ========================= Email-сервисы =========================
    SecretPattern("SECRET_SENDGRID", Severity.HIGH, "email_svc",
                  r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "SendGrid API key"),
    SecretPattern("SECRET_MAILGUN_HEX", Severity.HIGH, "email_svc",
                  r"\bkey-[0-9a-f]{32}\b", "Mailgun key"),
    SecretPattern("SECRET_POSTMARK", Severity.HIGH, "email_svc",
                  r"(?i)postmark[\"'\s:=_-]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
                  "Postmark server token", entropy_group=1),
    SecretPattern("SECRET_MAILCHIMP", Severity.HIGH, "email_svc",
                  r"\b[a-f0-9]{32}-us\d{1,2}\b", "Mailchimp API key"),

    # ========================= Twilio =========================
    SecretPattern("SECRET_TWILIO_API", Severity.HIGH, "twilio",
                  r"\bSK[0-9a-fA-F]{32}\b", "Twilio API key SID"),
    SecretPattern("SECRET_TWILIO_SID", Severity.MEDIUM, "twilio",
                  r"\bAC[a-f0-9]{32}\b", "Twilio Account SID"),

    # ========================= Cloudflare / Infra =========================
    SecretPattern("SECRET_CLOUDFLARE_API", Severity.CRITICAL, "infra_api",
                  r"(?i)cf[_\-]?api[_\-]?(?:key|token)['\"\s:=]+([A-Za-z0-9_\-]{37,})",
                  "Cloudflare API key/token", entropy_group=1, min_entropy=4.5),
    SecretPattern("SECRET_DIGITALOCEAN", Severity.HIGH, "infra_api",
                  r"\bdop_v1_[a-f0-9]{64}\b", "DigitalOcean PAT"),
    SecretPattern("SECRET_HEROKU_API", Severity.MEDIUM, "infra_api",
                  r"(?i)heroku(.{0,20})?api[\"'=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
                  "Heroku API key", entropy_group=2),
    SecretPattern("SECRET_HETZNER_API", Severity.HIGH, "infra_api",
                  r"\bhcloud_[A-Za-z0-9]{32,}\b", "Hetzner Cloud API token"),
    SecretPattern("SECRET_LINODE_API", Severity.HIGH, "infra_api",
                  r"\b[0-9a-f]{64}\b(?=.*linode)", "Linode API key (heuristic)"),

    # ========================= AI / LLM (модерн 2026) =========================
    SecretPattern("SECRET_ANTHROPIC_API", Severity.CRITICAL, "ai_api",
                  r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}\b", "Anthropic API key"),
    SecretPattern("SECRET_OPENAI_LEGACY", Severity.CRITICAL, "ai_api",
                  r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b", "OpenAI API key (legacy)"),
    SecretPattern("SECRET_OPENAI_PROJECT", Severity.CRITICAL, "ai_api",
                  r"\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b",
                  "OpenAI project key"),
    SecretPattern("SECRET_OPENAI_SESSION", Severity.HIGH, "ai_api",
                  r"\bsess-[A-Za-z0-9]{40}\b", "OpenAI session"),
    SecretPattern("SECRET_HUGGINGFACE", Severity.HIGH, "ai_api",
                  r"\bhf_[A-Za-z0-9]{30,}\b", "HuggingFace API token"),
    SecretPattern("SECRET_MISTRAL", Severity.HIGH, "ai_api",
                  r"(?i)mistral[_\-]?api[_\-]?key['\"\s:=]+([A-Za-z0-9]{32,})",
                  "Mistral API key", entropy_group=1, min_entropy=4.0),
    SecretPattern("SECRET_COHERE", Severity.HIGH, "ai_api",
                  r"(?i)cohere[_\-]?(?:api[_\-]?)?key['\"\s:=]+([A-Za-z0-9]{40,})",
                  "Cohere API key", entropy_group=1, min_entropy=4.0),
    SecretPattern("SECRET_TOGETHER_AI", Severity.HIGH, "ai_api",
                  r"(?i)together[_\-]?api[_\-]?key['\"\s:=]+([a-f0-9]{64})",
                  "Together.ai API key", entropy_group=1),
    SecretPattern("SECRET_REPLICATE", Severity.HIGH, "ai_api",
                  r"\br8_[A-Za-z0-9]{32,}\b", "Replicate token"),
    SecretPattern("SECRET_FIREWORKS_AI", Severity.HIGH, "ai_api",
                  r"\bfw_[A-Za-z0-9]{30,}\b", "Fireworks.ai API key"),
    SecretPattern("SECRET_RUNPOD_API", Severity.HIGH, "ai_api",
                  r"(?i)runpod[_\-]?api[_\-]?key['\"\s:=]+([A-Z0-9]{40,})",
                  "RunPod API key", entropy_group=1),
    SecretPattern("SECRET_DEEPSEEK", Severity.HIGH, "ai_api",
                  r"(?i)deepseek[_\-]?api[_\-]?key['\"\s:=]+(sk-[A-Za-z0-9]{32,})",
                  "DeepSeek API key", entropy_group=1),
    SecretPattern("SECRET_GROQ", Severity.HIGH, "ai_api",
                  r"\bgsk_[A-Za-z0-9]{50,}\b", "Groq API key"),
    SecretPattern("SECRET_PERPLEXITY", Severity.HIGH, "ai_api",
                  r"\bpplx-[A-Za-z0-9]{40,}\b", "Perplexity API key"),
    SecretPattern("SECRET_LANGSMITH", Severity.HIGH, "ai_api",
                  r"\blsv2_(?:pt|sk)_[A-Za-z0-9_]{36,}_[A-Za-z0-9]{6,}\b",
                  "LangSmith API key"),

    # ========================= Package registries =========================
    SecretPattern("SECRET_NPM_TOKEN", Severity.HIGH, "package_registry",
                  r"\bnpm_[A-Za-z0-9]{36}\b", "npm token"),
    SecretPattern("SECRET_PYPI_TOKEN", Severity.HIGH, "package_registry",
                  r"\bpypi-AgENdGV[A-Za-z0-9_\-]+\b", "PyPI token"),
    SecretPattern("SECRET_DOCKER_HUB_PAT", Severity.HIGH, "package_registry",
                  r"\bdckr_pat_[A-Za-z0-9_\-]{27,}\b", "Docker Hub PAT"),
    SecretPattern("SECRET_RUBYGEMS", Severity.MEDIUM, "package_registry",
                  r"\brubygems_[a-f0-9]{48}\b", "RubyGems API key"),
    SecretPattern("SECRET_CRATES_IO", Severity.MEDIUM, "package_registry",
                  r"\bcio[A-Za-z0-9]{32,}\b", "crates.io token (heuristic)"),

    # ========================= SaaS =========================
    SecretPattern("SECRET_ATLASSIAN_TOKEN", Severity.HIGH, "saas_api",
                  r"\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b", "Atlassian token"),
    SecretPattern("SECRET_LINEAR_API", Severity.MEDIUM, "saas_api",
                  r"\blin_api_[A-Za-z0-9]{40}\b", "Linear API"),
    SecretPattern("SECRET_NOTION_TOKEN", Severity.HIGH, "saas_api",
                  r"\b(?:secret_|ntn_)[A-Za-z0-9]{40,}\b", "Notion integration token"),
    SecretPattern("SECRET_ASANA_PAT", Severity.MEDIUM, "saas_api",
                  r"\b\d/\d{16,}:[a-f0-9]{32}\b", "Asana PAT"),
    SecretPattern("SECRET_FIGMA_PAT", Severity.MEDIUM, "saas_api",
                  r"\bfigd_[A-Za-z0-9_\-]{40,}\b", "Figma PAT"),
    SecretPattern("SECRET_AIRTABLE", Severity.MEDIUM, "saas_api",
                  r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b", "Airtable PAT"),
    SecretPattern("SECRET_SUPABASE_SERVICE", Severity.CRITICAL, "saas_api",
                  r"\beyJhbGciOi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b(?=.*service_role)",
                  "Supabase service-role JWT (heuristic)"),

    # ========================= Observability =========================
    SecretPattern("SECRET_NEWRELIC_LICENSE", Severity.MEDIUM, "observability",
                  r"\b(?:NRAA|NRAK|NRBR|NRJS)-[A-F0-9]{27}\b", "New Relic license"),
    SecretPattern("SECRET_DATADOG_API", Severity.HIGH, "observability",
                  r"(?i)dd[_\-]?api[_\-]?key['\"\s:=]+([a-f0-9]{32})",
                  "Datadog API key", entropy_group=1),
    SecretPattern("SECRET_DATADOG_APP", Severity.HIGH, "observability",
                  r"(?i)dd[_\-]?app[_\-]?key['\"\s:=]+([a-f0-9]{40})",
                  "Datadog Application key", entropy_group=1),
    SecretPattern("SECRET_SENTRY_DSN", Severity.LOW, "observability",
                  r"https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+", "Sentry DSN"),
    SecretPattern("SECRET_HONEYCOMB", Severity.MEDIUM, "observability",
                  r"(?i)honeycomb[_\-]?(?:api[_\-]?)?key['\"\s:=]+([A-Za-z0-9]{32,})",
                  "Honeycomb API key", entropy_group=1),

    # ========================= Tokens / auth =========================
    SecretPattern("SECRET_JWT", Severity.MEDIUM, "jwt",
                  r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
                  "JWT token"),
    SecretPattern("SECRET_BEARER_AUTH", Severity.MEDIUM, "bearer",
                  r"(?i)authorization[\"'=: ]+bearer\s+([A-Za-z0-9._\-]{20,})",
                  "Bearer auth header", entropy_group=1, min_entropy=4.0),
    SecretPattern("SECRET_BASIC_AUTH_URL", Severity.MEDIUM, "basic_auth",
                  r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+", "URL with embedded basic auth"),

    # ========================= Private keys =========================
    SecretPattern("SECRET_RSA_PRIVKEY", Severity.CRITICAL, "private_key",
                  r"-----BEGIN RSA PRIVATE KEY-----", "RSA private key"),
    SecretPattern("SECRET_EC_PRIVKEY", Severity.CRITICAL, "private_key",
                  r"-----BEGIN EC PRIVATE KEY-----", "EC private key"),
    SecretPattern("SECRET_OPENSSH_PRIVKEY", Severity.CRITICAL, "private_key",
                  r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH private key"),
    SecretPattern("SECRET_PGP_PRIVKEY", Severity.CRITICAL, "private_key",
                  r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP private key"),
    SecretPattern("SECRET_GENERIC_PRIVKEY", Severity.CRITICAL, "private_key",
                  r"-----BEGIN (DSA |)PRIVATE KEY-----", "Generic private key"),

    # ========================= Tunneling / Bot =========================
    SecretPattern("SECRET_NGROK_AUTH", Severity.MEDIUM, "tunneling",
                  r"\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b", "ngrok auth token"),

    # ========================= Firebase =========================
    SecretPattern("SECRET_FIREBASE_URL", Severity.LOW, "firebase",
                  r"\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b", "Firebase realtime DB URL"),

    # ========================= RU-сегмент =========================
    SecretPattern("SECRET_YANDEX_API", Severity.HIGH, "ru_api",
                  r"(?i)yandex[_\-]?api[_\-]?key['\"\s:=]+([A-Za-z0-9_\-]{30,})",
                  "Yandex Cloud API key", entropy_group=1, min_entropy=4.0),
    SecretPattern("SECRET_YANDEX_OAUTH", Severity.HIGH, "ru_api",
                  r"\by0_[A-Za-z0-9_\-]{30,}\b", "Yandex OAuth token"),
    SecretPattern("SECRET_VK_TOKEN", Severity.HIGH, "ru_api",
                  r"(?i)vk[_\-]?(?:api[_\-]?)?(?:access[_\-]?)?token['\"\s:=]+([a-f0-9]{60,})",
                  "VK API access token", entropy_group=1),

    # ========================= Generic (low precision, last resort) =========================
    SecretPattern("SECRET_GENERIC_API_KEY", Severity.MEDIUM, "generic",
                  r"(?i)(?:api[_\-]?key|apikey|api_secret|access_token|secret[_\-]?token)['\"\s:=]+[\"']([A-Za-z0-9+/=_\-]{24,})[\"']",
                  "Generic API key", entropy_group=1, min_entropy=4.0),
    SecretPattern("SECRET_GENERIC_PASSWORD", Severity.LOW, "generic",
                  r"(?i)(?:password|passwd|pwd)['\"\s:=]+[\"']([^\"'\s]{8,})[\"']",
                  "Generic password", entropy_group=1, min_entropy=3.0),
]
