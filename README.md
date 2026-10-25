# 🛡️ AI-Powered SOC Analyst Tool

A Streamlit application that uses a large language model to analyze security logs, built for the
*AI in Cybersecurity* course. Analysts paste or upload logs, the AI classifies each one (severity,
attack type, recommended action), and the app enriches, stores and alerts on the results, **without
ever sending real usernames or IP addresses to the AI provider**.

## Features

| # | Feature | What it does |
|---|---|---|
| 1 | **Data masking & privacy** *(mandatory)* | Replaces usernames with `USER_01…` and IPv4 addresses with `IP_01…` before the log leaves the machine, then restores the real values in the AI's answer. |
| 2 | **Real-time alerts** | Sends a Discord/Slack webhook (or SMTP email) whenever the AI rates a log **High** or **Critical**. Toggle in the sidebar. |
| 3 | **Threat intelligence** | For logs the AI flags as attacks, looks up the attacker IP on **AbuseIPDB** and shows the Abuse Confidence Score, report count, country and ISP. |
| 4 | **SQLite storage** | Every analysis is saved in `soc_history.db`; the **History** tab shows past investigations and survives restarts. |
| 5 | **False-positive feedback** | A *Mark as False Positive* button on each result saves a correction; the dashboard shows **Total Analyst Corrections**. |
| 6 | **Token & cost tracker** | Counts tokens from each API response and estimates cost in USD using a per-model price table (per log, per batch, all-time). |
| ⭐ | **Role-based access control** | Login with two roles: **Admin** (PDF reports, delete history) and **Junior Analyst** (view only). |

## How it works

```
 log line ──► [1] mask ──► AI provider ──► JSON analysis ──► [1] restore real values
 (paste/CSV)   USER_01        (sees only      severity,             │
               IP_01           placeholders)  attack type, …        ▼
                                                        ┌───────────────────────────┐
                                                        │ [3] AbuseIPDB lookup      │
                                                        │ [4] save to SQLite        │
                                                        │ [2] alert if High/Critical│
                                                        │ [6] add tokens & cost     │
                                                        └─────────────┬─────────────┘
                                                                      ▼
                                              Dashboard result card  +  [5] "Mark as False Positive"
```

1. **Input** – logs are pasted (one per line) or uploaded as `.log`, `.txt` or `.csv`. For CSV only the
   `log` column is read, so ground-truth columns such as `true_label` are never sent to the AI.
2. **Masking** – `DataMasker` first scans *all* lines to learn usernames (patterns such as `User: sara`,
   `user=root`, `Invalid user bob`, `sudo: john`, `for admin from …`), then replaces every occurrence and
   every IPv4 address. One mapping is shared across the batch, so the same value always gets the same
   token and the AI can still correlate events (`IP_01` attacked `USER_01` five times).
   The UI shows exactly what the AI received under *"What the AI actually received (masked)"*.
3. **Analysis** – each masked log is sent to the AI, which answers in JSON
   (`severity`, `attack_type`, `is_attack`, `summary`, `recommendation`). Free-tier rate limits are handled
   with automatic retries and an optional delay.
4. **Restore** – placeholders in the AI's answer are replaced by the real usernames/IPs for display.
5. **Enrichment** – if `is_attack` is true, the attacker IP (first public IP in the log) is checked on
   AbuseIPDB (cached per batch; private/reserved IPs are skipped with an explanation).
6. **Persistence & alerting** – the result is saved to SQLite; High/Critical results trigger an alert
   if the sidebar toggle is on.
7. **Feedback loop** – analysts can flag wrong detections; corrections are stored in a separate table
   and counted on the dashboard.

## Supported AI providers

The app uses the official `openai` Python library. Because the providers below expose an
OpenAI-compatible endpoint, switching provider only needs `.env` changes.

| `AI_PROVIDER` | Key variable | Default model | Cost shown |
|---|---|---|---|
| `openai` | `OPENAI_API_KEY` | `gpt-4o-mini` | Estimated from the price table in `SOC_app.py` (`MODEL_PRICING`) |
| `groq` | `GROQ_API_KEY` | `openai/gpt-oss-20b` | $0.00 (free tier) |
| `gemini` | `GEMINI_API_KEY` | `gemini-2.5-flash` | $0.00 (free tier) |
| `openrouter` | `OPENROUTER_API_KEY` | `openrouter/free` | $0.00 (free models) |

Model names and prices change over time. Verify them in the provider's dashboard and edit
`PROVIDERS` / `MODEL_PRICING` in `SOC_app.py` if needed, or set `AI_MODEL` in `.env`.

## Setup

**Requirements:** Python 3.9+

```bash
# 1. create and activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS / Linux

# 2. install dependencies
pip install -r requirements.txt

# 3. create your config file
copy .env.example .env         # Windows  (cp .env.example .env on macOS/Linux)
#    ...then open .env and fill in your keys

# 4. run
streamlit run SOC_app.py
```

### Configuration (`.env`)

All settings live in `.env`; the only control in the sidebar is the alerts toggle.

| Variable | Required | Description |
|---|---|---|
| `AI_PROVIDER` | recommended | `openai`, `groq`, `gemini` or `openrouter` (if unset, the first provider with a key is used) |
| `<PROVIDER>_API_KEY` | yes* | Key for the chosen provider (see table above) |
| `AI_MODEL` | no | Override the default model |
| `AI_DELAY_SECONDS` | no | Pause between AI calls to respect free-tier rate limits (Groq ≈ 2, Gemini ≈ 7) |
| `ABUSEIPDB_API_KEY` | no | Enables threat-intelligence lookups (free key from abuseipdb.com) |
| `ALERT_WEBHOOK_URL` | no | Discord or Slack webhook URL (type detected automatically) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `ALERT_EMAIL_TO` | no | Email alerts via `smtplib` (used when no webhook URL is set) |
| `EXTRA_MASK_USERS` | no | Comma-separated extra usernames to always mask |
| `DEMO_MODE` | no | `true` = built-in keyword analyzer, **no API call** (for free testing) |

\* not needed in demo mode. Settings can also come from real environment variables or
`.streamlit/secrets.toml` (used on Streamlit Community Cloud).

## Usage

1. Log in. Demo accounts:

   | Username | Password | Role |
   |---|---|---|
   | `admin` | `admin123` | Admin |
   | `junior` | `junior123` | Junior Analyst |

2. **Analyze logs** tab → *Load sample logs* (or paste / upload a file) → **Analyze**.
3. Review each result card: severity, AI summary, recommended action, AbuseIPDB data, tokens and cost.
   Use **Mark as False Positive** if the AI got it wrong.
4. The **dashboard** at the top shows total analyses, **Total Analyst Corrections**, tokens and estimated
   cost for the current batch and for all time.
5. **History** tab → all saved investigations. Admins can download a PDF report or delete history;
   Junior Analysts see a notice instead of those buttons.

Role checks are enforced inside the restricted functions (`build_pdf_report`, `delete_history`), not only
by hiding buttons.

## Project structure

```
SOC_app.py          # the whole application (UI + logic)
requirements.txt    # Python dependencies
.env.example        # template for your private .env (never commit .env)
.gitignore          # keeps .env, venv and the local database out of git
soc_history.db      # created automatically on first run
```

## Security notes & limitations

- **Never commit `.env`** or API keys. If a key leaks, revoke it and create a new one.
- Masking is rule-based (regex), designed for common log formats. Unusual formats may need
  `EXTRA_MASK_USERS`. Names like `admin`/`root` are masked too, which can slightly reduce context for
  the AI (privacy vs. accuracy trade-off). Only usernames and IPv4 addresses are masked, not hostnames,
  emails or IPv6.
- The history database stores the **real** (restored) log text locally; masking protects what is sent
  to the AI provider, not what is stored on your machine.
- Demo passwords are hard-coded for coursework. A real deployment needs a proper user store.
- On Streamlit Community Cloud the SQLite file is **not guaranteed to persist** across restarts or
  redeploys. Run locally to demonstrate persistence.
- Do not leave a public deployment connected to a paid key; anyone who can log in can spend your credits.
- Free-tier limits and model names change; check the provider's current documentation.

## Testing

Run with `DEMO_MODE=true` to exercise the full workflow (masking, history, corrections, RBAC, PDF)
without any API key or cost, then repeat with a real provider on the sample logs before analyzing a
large CSV.

## Libraries & services

`streamlit` · `openai` · `requests` · `fpdf2` · `python-dotenv` · `sqlite3`, `smtplib`, `re`,
`ipaddress`, `hashlib`, `hmac` (standard library) · AI provider API · AbuseIPDB · Discord/Slack webhooks