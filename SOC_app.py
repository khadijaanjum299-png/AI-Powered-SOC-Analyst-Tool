"""
SOC_app.py - Advanced AI-Powered SOC Analyst Tool
=================================================
Run with:   streamlit run SOC_app.py

Features implemented
--------------------
Feature 1 (MANDATORY)  Data masking / privacy  -> DataMasker (usernames + IPs)
Feature 2              Real-time alerts        -> Discord / Slack webhook or SMTP email
Feature 3              Threat intelligence     -> AbuseIPDB (Abuse Confidence Score)
Feature 4              SQLite storage          -> soc_history.db + History tab
Feature 5              False-positive feedback -> button per log + "Total Analyst Corrections"
Feature 6              Token & cost tracker    -> per-model price table
Bonus                  RBAC                    -> Admin / Junior Analyst login

Demo logins (change them before any real use!):
    admin  / admin123   -> Admin
    junior / junior123  -> Junior Analyst
"""

import csv
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import smtplib
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from email.message import EmailMessage

import requests
import streamlit as st

# Load API keys from a .env file placed next to this script (optional but recommended).
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass  # python-dotenv not installed -> fall back to sidebar / environment variables

# ----------------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------------
# The database file sits next to this script, so history survives restarts
# no matter which folder the app is launched from.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc_history.db")

# Price in USD per 1,000,000 tokens: (input, output).
# Prices change - verify at https://openai.com/api/pricing and edit if needed.
MODEL_PRICING = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.00, 8.00),
}

# AI providers. Every one of them speaks the OpenAI API format, so the same `openai`
# library is used for all - only base_url, key and model name change.
# Model names change over time: check each provider's dashboard if one is rejected.
PROVIDERS = {
    "openai": {"label": "OpenAI (paid)", "base_url": None, "key_env": "OPENAI_API_KEY",
               "models": list(MODEL_PRICING)},
    "groq": {"label": "Groq (free tier)", "base_url": "https://api.groq.com/openai/v1",
             "key_env": "GROQ_API_KEY",
             "models": ["openai/gpt-oss-20b", "openai/gpt-oss-120b", "llama-3.3-70b-versatile"]},
    "gemini": {"label": "Google Gemini (free tier)",
               "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
               "key_env": "GEMINI_API_KEY", "models": ["gemini-2.5-flash", "gemini-2.5-flash-lite"]},
    "openrouter": {"label": "OpenRouter (free models)", "base_url": "https://openrouter.ai/api/v1",
                   "key_env": "OPENROUTER_API_KEY", "models": ["openrouter/free"]},
}

SEVERITIES = ["Informational", "Low", "Medium", "High", "Critical"]
SEVERITY_ICON = {"Informational": "⚪", "Low": "🔵", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}
ALERT_SEVERITIES = {"High", "Critical"}

SAMPLE_LOGS = """Oct 23 10:15:32 server sshd[1234]: Failed password for admin from 185.220.101.45 port 51514 ssh2
Oct 23 10:16:01 server sshd[1236]: Failed password for invalid user root from 185.220.101.45 port 51520 ssh2
Oct 23 10:20:11 web01 nginx: 91.240.118.172 - - "GET /product?id=1' UNION SELECT username,password FROM users-- HTTP/1.1" 200 512
Oct 23 10:25:44 server sshd[1301]: Accepted password for alice from 192.168.1.25 port 40222 ssh2
Oct 23 10:30:09 server sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/cat /etc/shadow
Oct 23 10:31:00 fw01 kernel: DROPPED IN=eth0 SRC=10.0.0.5 DST=192.168.1.25 PROTO=TCP DPT=3389"""

# ----------------------------------------------------------------------------
# BONUS: ROLE-BASED ACCESS CONTROL
# ----------------------------------------------------------------------------
def _hash_pw(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()


# Demo user store (salted SHA-256). A real system would use a proper user DB.
USERS = {
    "admin": {"salt": "s0c-a", "hash": _hash_pw("admin123", "s0c-a"), "role": "Admin"},
    "junior": {"salt": "s0c-j", "hash": _hash_pw("junior123", "s0c-j"), "role": "Junior Analyst"},
}

PERMISSIONS = {
    "Admin": {"view", "download_pdf", "delete_history"},
    "Junior Analyst": {"view"},
}


def authenticate(username: str, password: str):
    """Return the user's role if credentials are valid, else None."""
    user = USERS.get(username.strip().lower())
    if not user:
        return None
    if hmac.compare_digest(_hash_pw(password, user["salt"]), user["hash"]):
        return user["role"]
    return None


def has_permission(role, action: str) -> bool:
    return action in PERMISSIONS.get(role, set())


def require_permission(role, action: str):
    """Server-side check: restricted functions call this before doing anything."""
    if not has_permission(role, action):
        raise PermissionError(f"Role '{role}' is not allowed to perform '{action}'.")


# ----------------------------------------------------------------------------
# FEATURE 1: DATA MASKING AND PRIVACY (MANDATORY)
# ----------------------------------------------------------------------------
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# Patterns that reveal a username inside typical log lines.
USER_PATTERNS = [
    # Labelled fields:  "User: Sara", "user=root", "USER=root", "username: bob", "account=alice"
    re.compile(r"(?i)\b(?:username|user|account)\s*[=:]\s*([A-Za-z0-9_.\-]+)"),
    # sshd style:  "Invalid user bob from ..."
    re.compile(r"(?i)\binvalid user\s+([A-Za-z0-9_.\-]+)"),
    # sudo style:  "sudo: john : TTY=..."
    re.compile(r"(?i)\bsudo:\s*([A-Za-z0-9_.\-]+)"),
    # "Failed password for admin from ...", "Accepted password for alice from ..."
    re.compile(r"(?i)\bfor (?:invalid user )?([A-Za-z0-9_.\-]+) from\b"),
]
# Words that follow "user"/"for" in normal English log text but are not usernames.
NOT_USERNAMES = {
    "logged", "login", "session", "from", "for", "and", "not", "the", "is", "was", "unknown",
    "invalid", "authentication", "name", "account", "connection", "user", "failed", "accepted",
    "opened", "closed", "id", "root_login", "password", "attempt", "attempts",
}
TOKEN_RE = re.compile(r"\b(?:USER|IP)_\d{2,}\b")


class DataMasker:
    """
    Replaces usernames -> USER_01, USER_02 ... and IPv4 addresses -> IP_01, IP_02 ...
    The same real value always receives the same token, so the AI can still
    correlate events (e.g. "IP_01 attacked USER_01 five times") without ever
    seeing the real values. restore() reverses the substitution.
    """

    def __init__(self):
        self.user_map = {}  # real value -> token
        self.ip_map = {}

    @staticmethod
    def _token(prefix: str, mapping: dict, real: str) -> str:
        if real not in mapping:
            mapping[real] = f"{prefix}_{len(mapping) + 1:02d}"
        return mapping[real]

    def learn(self, text: str, extra_users=()):
        """Discover usernames in a log line (call on ALL lines before masking any)."""
        for name in extra_users:
            if name:
                self._token("USER", self.user_map, name)
        for pattern in USER_PATTERNS:
            for match in pattern.finditer(text):
                name = match.group(1).strip(".-")
                if len(name) >= 2 and name.lower() not in NOT_USERNAMES and not TOKEN_RE.fullmatch(name):
                    self._token("USER", self.user_map, name)

    def mask(self, text: str, extra_users=()) -> str:
        # 1) discover usernames
        self.learn(text, extra_users)
        # 2) replace every known username as a whole word (longest first)
        for real, token in sorted(self.user_map.items(), key=lambda kv: -len(kv[0])):
            text = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(real)}(?![A-Za-z0-9_])", token, text)
        # 3) replace IPv4 addresses
        return IPV4_RE.sub(lambda m: self._token("IP", self.ip_map, m.group()), text)

    def restore(self, value):
        """Put the real usernames/IPs back (works on str, list and dict)."""
        reverse = {**{t: r for r, t in self.user_map.items()}, **{t: r for r, t in self.ip_map.items()}}

        def _restore(obj):
            if isinstance(obj, str):
                return TOKEN_RE.sub(lambda m: reverse.get(m.group(), m.group()), obj)
            if isinstance(obj, list):
                return [_restore(o) for o in obj]
            if isinstance(obj, dict):
                return {k: _restore(v) for k, v in obj.items()}
            return obj

        return _restore(value)


# ----------------------------------------------------------------------------
# FEATURE 6: TOKEN AND COST TRACKER
# ----------------------------------------------------------------------------
def calculate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    in_price, out_price = MODEL_PRICING.get(model, (0.0, 0.0))
    return (prompt_tokens * in_price + completion_tokens * out_price) / 1_000_000


# ----------------------------------------------------------------------------
# AI ANALYSIS (OpenAI)
# ----------------------------------------------------------------------------
SYSTEM_PROMPT = f"""You are a senior SOC analyst. Analyze ONE security log line.
Sensitive values were replaced by placeholders such as USER_01 and IP_01. Treat them as
real identities and keep the placeholders exactly as written in your answer.
Respond with ONLY a JSON object with these keys:
  "severity": one of {SEVERITIES},
  "attack_type": short name (e.g. "Brute Force", "SQL Injection", "Privilege Escalation", "None"),
  "is_attack": true if the log indicates a potential attack or malicious activity, else false,
  "summary": 1-2 sentence explanation,
  "recommendation": 1-2 sentence recommended action."""


def analyze_with_openai(client, model: str, masked_log: str):
    """Send ONE masked log to the AI. Returns (analysis_dict, prompt_tokens, completion_tokens)."""
    kwargs = dict(model=model, messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": masked_log},
    ])
    try:
        response = client.chat.completions.create(**kwargs, response_format={"type": "json_object"})
    except Exception as exc:
        # Some free models do not support JSON mode -> retry without it.
        if exc.__class__.__name__ in ("BadRequestError", "UnprocessableEntityError"):
            response = client.chat.completions.create(**kwargs)
        else:
            raise
    content = response.choices[0].message.content or ""
    found = re.search(r"\{.*\}", content, re.S)  # tolerate extra text around the JSON
    data = json.loads(found.group(0) if found else content)
    usage = response.usage  # Feature 6: token counts reported by the API
    if usage is not None:
        pt, ct = usage.prompt_tokens, usage.completion_tokens
    else:  # a few providers omit usage -> rough estimate (~4 characters per token)
        pt, ct = (len(SYSTEM_PROMPT) + len(masked_log)) // 4, len(content) // 4
    return normalize_analysis(data), pt, ct


def analyze_with_retry(client, model: str, masked_log: str, attempts: int = 4):
    """Free tiers have low rate limits: on a 429 wait and try again (but not when quota is exhausted)."""
    for i in range(attempts):
        try:
            return analyze_with_openai(client, model, masked_log)
        except Exception as exc:
            rate_limited = exc.__class__.__name__ == "RateLimitError"
            if rate_limited and "insufficient_quota" not in str(exc) and i < attempts - 1:
                time.sleep(15 * (i + 1))
                continue
            raise


def normalize_analysis(data: dict) -> dict:
    severity = str(data.get("severity", "Medium")).strip().capitalize()
    if severity not in SEVERITIES:
        severity = "Medium"
    return {
        "severity": severity,
        "attack_type": str(data.get("attack_type", "Unknown")),
        "is_attack": bool(data.get("is_attack", severity in ALERT_SEVERITIES)),
        "summary": str(data.get("summary", "")),
        "recommendation": str(data.get("recommendation", "")),
    }


def demo_analyze(masked_log: str):
    """Offline keyword-based stand-in so the app can be tested WITHOUT an API key/cost."""
    low = masked_log.lower()
    if "union select" in low or "' or 1=1" in low or "<script" in low:
        a = ("Critical", "SQL Injection / Web Attack", True, "Malicious payload in a web request.")
    elif "failed password" in low or "invalid user" in low:
        a = ("High", "Brute Force", True, "Repeated failed authentication attempt.")
    elif "/etc/shadow" in low or "sudo" in low:
        a = ("High", "Privilege Escalation", True, "Sensitive file accessed via sudo.")
    elif "dropped" in low:
        a = ("Low", "Blocked Traffic", False, "Firewall dropped a connection attempt.")
    else:
        a = ("Informational", "None", False, "Looks like routine activity.")
    sev, attack, is_attack, text = a
    analysis = normalize_analysis({
        "severity": sev, "attack_type": attack, "is_attack": is_attack,
        "summary": f"[DEMO MODE] {text} Log seen by the 'AI': {masked_log[:120]}",
        "recommendation": "Investigate the source and review related events.",
    })
    return analysis, len(masked_log) // 4 + 120, 60  # estimated token counts


# ----------------------------------------------------------------------------
# FEATURE 3: THREAT INTELLIGENCE (AbuseIPDB)
# ----------------------------------------------------------------------------
def extract_attacker_ip(original_log: str):
    """Pick the most likely attacker IP: first public IP, else the first IP found."""
    ips = IPV4_RE.findall(original_log)
    for ip in ips:
        if ipaddress.ip_address(ip).is_global:
            return ip
    return ips[0] if ips else None


def check_abuseipdb(ip: str, api_key: str) -> dict:
    """Query AbuseIPDB. Returns a dict of results or {'error': '...'}."""
    if not ipaddress.ip_address(ip).is_global:
        return {"error": f"{ip} is a private/reserved address - not checked against AbuseIPDB."}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        if r.status_code != 200:
            return {"error": f"AbuseIPDB returned HTTP {r.status_code}: {r.text[:150]}"}
        d = r.json()["data"]
        return {
            "ip": ip,
            "score": d.get("abuseConfidenceScore"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "reports": d.get("totalReports"),
            "usage": d.get("usageType"),
        }
    except Exception as exc:  # network errors, bad JSON ...
        return {"error": f"AbuseIPDB lookup failed: {exc}"}


# ----------------------------------------------------------------------------
# FEATURE 2: REAL-TIME ALERTS
# ----------------------------------------------------------------------------
def send_alert(cfg: dict, record: dict):
    """Send an alert via Discord/Slack webhook or SMTP email. Returns (ok, message)."""
    text = (
        f"🚨 {record['severity']} severity detected\n"
        f"Type: {record['attack_type']}\nSource IP: {record.get('attacker_ip') or 'n/a'}\n"
        f"Summary: {record['summary']}\nLog: {record['log'][:300]}"
    )
    try:
        channel = cfg["alert_channel"]
        if not channel:
            return False, "No alert channel configured in .env"
        if channel in ("Discord webhook", "Slack webhook"):
            if not cfg["webhook_url"]:
                return False, "No webhook URL configured"
            payload = {"content": text[:1900]} if channel.startswith("Discord") else {"text": text}
            r = requests.post(cfg["webhook_url"], json=payload, timeout=10)
            return (r.status_code < 300), f"{channel} HTTP {r.status_code}"
        # Email via smtplib
        if not (cfg["smtp_host"] and cfg["smtp_user"] and cfg["smtp_pass"] and cfg["email_to"]):
            return False, "SMTP settings incomplete"
        msg = EmailMessage()
        msg["Subject"] = f"[SOC ALERT] {record['severity']} - {record['attack_type']}"
        msg["From"], msg["To"] = cfg["smtp_user"], cfg["email_to"]
        msg.set_content(text)
        with smtplib.SMTP(cfg["smtp_host"], int(cfg["smtp_port"]), timeout=15) as smtp:
            smtp.starttls()
            smtp.login(cfg["smtp_user"], cfg["smtp_pass"])
            smtp.send_message(msg)
        return True, "Email sent"
    except Exception as exc:
        return False, f"Alert failed: {exc}"


# ----------------------------------------------------------------------------
# FEATURE 4 & 5: SQLITE STORAGE + FALSE POSITIVE CORRECTIONS
# ----------------------------------------------------------------------------
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, log TEXT, severity TEXT, attack_type TEXT, is_attack INTEGER,
            summary TEXT, recommendation TEXT, attacker_ip TEXT, abuse_score INTEGER,
            model TEXT, prompt_tokens INTEGER, completion_tokens INTEGER, cost_usd REAL,
            false_positive INTEGER DEFAULT 0)""")
        c.execute("""CREATE TABLE IF NOT EXISTS corrections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER, timestamp TEXT, analyst TEXT,
            original_severity TEXT, original_attack_type TEXT)""")


def save_analysis(r: dict) -> int:
    with db() as c:
        cur = c.execute(
            """INSERT INTO analyses (timestamp, log, severity, attack_type, is_attack, summary,
               recommendation, attacker_ip, abuse_score, model, prompt_tokens, completion_tokens, cost_usd)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), r["log"], r["severity"], r["attack_type"],
             int(r["is_attack"]), r["summary"], r["recommendation"], r.get("attacker_ip"),
             r.get("abuse_score"), r["model"], r["prompt_tokens"], r["completion_tokens"], r["cost"]),
        )
        return cur.lastrowid


def mark_false_positive(analysis_id: int, analyst: str) -> bool:
    """Flag an analysis as a false positive and record the correction. False if already flagged."""
    with db() as c:
        row = c.execute("SELECT severity, attack_type, false_positive FROM analyses WHERE id=?",
                        (analysis_id,)).fetchone()
        if row is None or row["false_positive"]:
            return False
        c.execute("UPDATE analyses SET false_positive=1 WHERE id=?", (analysis_id,))
        c.execute("INSERT INTO corrections (analysis_id, timestamp, analyst, original_severity, "
                  "original_attack_type) VALUES (?,?,?,?,?)",
                  (analysis_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), analyst,
                   row["severity"], row["attack_type"]))
        return True


def count_corrections() -> int:
    with db() as c:
        return c.execute("SELECT COUNT(*) FROM corrections").fetchone()[0]


def get_history():
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM analyses ORDER BY id DESC").fetchall()]


def lifetime_totals() -> dict:
    with db() as c:
        row = c.execute("""SELECT COUNT(*) n, COALESCE(SUM(prompt_tokens),0) pt,
                           COALESCE(SUM(completion_tokens),0) ct, COALESCE(SUM(cost_usd),0) cost
                           FROM analyses""").fetchone()
        return dict(row)


def delete_history(role: str):
    """Admin-only. Removes all saved investigations and corrections."""
    require_permission(role, "delete_history")
    with db() as c:
        c.execute("DELETE FROM analyses")
        c.execute("DELETE FROM corrections")


# ----------------------------------------------------------------------------
# PDF REPORT (Admin only)
# ----------------------------------------------------------------------------
def _latin1(text) -> str:
    return str(text).encode("latin-1", "replace").decode("latin-1")


def build_pdf_report(role: str, rows: list) -> bytes:
    require_permission(role, "download_pdf")
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "SOC Investigation Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=10)
    totals = lifetime_totals()
    pdf.multi_cell(0, 6, _latin1(
        f"Generated: {datetime.now():%Y-%m-%d %H:%M}  |  Investigations: {totals['n']}  |  "
        f"Corrections: {count_corrections()}  |  Tokens: {totals['pt'] + totals['ct']:,}  |  "
        f"Est. cost: ${totals['cost']:.4f}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    for r in rows[:200]:
        pdf.set_font("Helvetica", "B", 10)
        flag = "  [FALSE POSITIVE]" if r["false_positive"] else ""
        pdf.multi_cell(0, 6, _latin1(f"#{r['id']}  {r['timestamp']}  {r['severity']} - {r['attack_type']}{flag}"),
                       new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=9)
        body = f"Log: {r['log']}\nSummary: {r['summary']}\nAction: {r['recommendation']}"
        if r["attacker_ip"]:
            score = r["abuse_score"] if r["abuse_score"] is not None else "n/a"
            body += f"\nAttacker IP: {r['attacker_ip']} (AbuseIPDB score: {score})"
        pdf.multi_cell(0, 5, _latin1(body), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
    return bytes(pdf.output())


# ----------------------------------------------------------------------------
# SECRETS HELPER (sidebar box -> environment variable -> .streamlit/secrets.toml)
# ----------------------------------------------------------------------------
def get_secret(typed_value: str, name: str) -> str:
    if typed_value:
        return typed_value.strip()
    if os.getenv(name):
        return os.getenv(name).strip()
    try:
        return str(st.secrets[name]).strip()
    except Exception:
        return ""


# ----------------------------------------------------------------------------
# STREAMLIT UI
# ----------------------------------------------------------------------------
def login_screen():
    st.title("🛡️ AI-Powered SOC Analyst Tool")
    st.subheader("Sign in")
    with st.form("login_form"):
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        submitted = st.form_submit_button("Log in")
    if submitted:
        role = authenticate(username, password)
        if role:
            st.session_state.user = {"name": username.strip().lower(), "role": role}
            st.rerun()
        else:
            st.error("Invalid username or password.")
    st.caption("Demo accounts: admin / admin123 (Admin) and junior / junior123 (Junior Analyst).")


def load_config() -> dict:
    """All settings come from .env / environment variables / Streamlit secrets - no keys in the UI."""
    env = lambda name: get_secret("", name)
    chosen = env("AI_PROVIDER").lower()
    if chosen not in PROVIDERS:  # not set -> use the first provider that has a key
        chosen = next((n for n in PROVIDERS if env(PROVIDERS[n]["key_env"])), "openai")
    prov = PROVIDERS[chosen]
    cfg = {"provider": chosen, "base_url": prov["base_url"], "key_env": prov["key_env"],
           "openai_key": env(prov["key_env"]), "model": env("AI_MODEL") or prov["models"][0]}
    cfg["demo"] = env("DEMO_MODE").lower() in ("1", "true", "yes", "on")
    try:
        cfg["delay"] = float(env("AI_DELAY_SECONDS") or 0)  # pause between calls (free-tier rate limits)
    except ValueError:
        cfg["delay"] = 0.0
    cfg["extra_users"] = [u.strip() for u in env("EXTRA_MASK_USERS").split(",") if u.strip()]
    cfg["abuse_key"] = env("ABUSEIPDB_API_KEY")
    cfg["ti_enabled"] = bool(cfg["abuse_key"])  # threat intel is on whenever a key exists
    # Alert channel: webhook URL (Discord or Slack, detected from the URL) or SMTP email
    cfg.update(webhook_url=env("ALERT_WEBHOOK_URL"), smtp_host=env("SMTP_HOST"),
               smtp_port=env("SMTP_PORT") or 587, smtp_user=env("SMTP_USER"),
               smtp_pass=env("SMTP_PASS"), email_to=env("ALERT_EMAIL_TO"))
    if cfg["webhook_url"]:
        cfg["alert_channel"] = "Discord webhook" if "discord" in cfg["webhook_url"] else "Slack webhook"
    elif cfg["smtp_host"]:
        cfg["alert_channel"] = "Email (SMTP)"
    else:
        cfg["alert_channel"] = ""
    return cfg


def render_sidebar(cfg: dict) -> dict:
    """Sidebar: who is logged in, the alerts toggle and a read-only status line."""
    user = st.session_state.user
    with st.sidebar:
        st.markdown(f"**👤 {user['name']}**  \nRole: `{user['role']}`")
        if st.button("Log out"):
            st.session_state.user = None
            st.session_state.results = []
            st.rerun()
        st.divider()
        st.header("🚨 Alerts")
        cfg["alerts_enabled"] = st.toggle("Enable High/Critical alerts", value=False)
        if cfg["alerts_enabled"] and not cfg["alert_channel"]:
            st.warning("No alert channel found. Add ALERT_WEBHOOK_URL to your .env file.")
        st.divider()
        if cfg["demo"]:
            st.caption("🧪 Demo mode (no AI call)")
        else:
            st.caption(f"🤖 {PROVIDERS[cfg['provider']]['label']} · `{cfg['model']}`  \n"
                       f"AI key: {'✅' if cfg['openai_key'] else '❌ missing ' + cfg['key_env']}")
        st.caption(f"🌐 AbuseIPDB: {'✅' if cfg['ti_enabled'] else '❌ no key'} · "
                   f"🚨 Alert channel: {cfg['alert_channel'] or '❌ none'}")
    return cfg


def read_uploaded_logs(upload) -> str:
    """Return the log lines from an uploaded .log/.txt/.csv file as plain text.
    For CSV files only the 'log' column is used, so ground-truth columns such as
    'true_label' are NEVER sent to the AI."""
    raw = upload.getvalue().decode("utf-8-sig", errors="replace")
    if not upload.name.lower().endswith(".csv"):
        return raw
    rows = list(csv.reader(io.StringIO(raw)))
    if not rows:
        return ""
    header = [h.strip().lower() for h in rows[0]]
    if "log" in header:
        col, body = header.index("log"), rows[1:]
    else:
        col, body = 0, rows  # no header row -> first column holds the logs
    return "\n".join(r[col].strip() for r in body if len(r) > col and r[col].strip())


def load_samples():
    st.session_state.log_input = SAMPLE_LOGS


def handle_false_positive(analysis_id: int):
    """Button callback: save the correction, then update the on-screen result."""
    if mark_false_positive(analysis_id, st.session_state.user["name"]):
        for r in st.session_state.results:
            if r["id"] == analysis_id:
                r["false_positive"] = True


def handle_delete_history():
    try:
        delete_history(st.session_state.user["role"])  # role re-checked server-side
        st.session_state.results = []
        st.toast("Investigation history deleted.")
    except PermissionError as exc:
        st.toast(str(exc))


def run_batch(cfg: dict, lines: list):
    if not cfg["demo"] and not cfg["openai_key"]:
        st.error(f"Enter your API key in the sidebar or set {cfg['key_env']} in .env (or tick Demo mode to test without one).")
        return
    client = None
    if not cfg["demo"]:
        from openai import OpenAI
        client = OpenAI(api_key=cfg["openai_key"], base_url=cfg["base_url"])

    masker = DataMasker()  # shared across the batch -> consistent tokens
    for line in lines:     # pre-scan: learn every username first so none slips through
        masker.learn(line, cfg["extra_users"])
    batch = {"n": 0, "pt": 0, "ct": 0, "cost": 0.0}
    threat_cache = {}  # same attacker IP is only looked up once per batch
    st.session_state.results = []
    progress = st.progress(0.0, text="Analyzing logs...")

    for i, log in enumerate(lines, start=1):
        try:
            masked = masker.mask(log, cfg["extra_users"])               # Feature 1: mask
            if cfg["demo"]:
                analysis, pt, ct = demo_analyze(masked)
            else:
                analysis, pt, ct = analyze_with_retry(client, cfg["model"], masked)
                if cfg["delay"]:
                    time.sleep(cfg["delay"])
            analysis = masker.restore(analysis)                         # Feature 1: restore
        except Exception as exc:
            st.warning(f"Log {i} failed: {exc}")
            if exc.__class__.__name__ in ("AuthenticationError", "PermissionDeniedError"):
                break  # no point retrying with a bad key
            continue

        record = {**analysis, "log": log, "masked": masked, "model": cfg["model"],
                  "prompt_tokens": pt, "completion_tokens": ct,
                  "cost": calculate_cost(cfg["model"], pt, ct),         # Feature 6
                  "attacker_ip": None, "abuse_score": None, "threat": None,
                  "alert_status": None, "false_positive": False}

        if analysis["is_attack"]:                                       # Feature 3
            record["attacker_ip"] = extract_attacker_ip(log)
            if cfg["ti_enabled"] and record["attacker_ip"]:
                if cfg["abuse_key"]:
                    ip = record["attacker_ip"]
                    if ip not in threat_cache:
                        threat_cache[ip] = check_abuseipdb(ip, cfg["abuse_key"])
                    record["threat"] = threat_cache[ip]
                    record["abuse_score"] = record["threat"].get("score")
                else:
                    record["threat"] = {"error": "No AbuseIPDB API key set in the sidebar."}

        record["id"] = save_analysis(record)                            # Feature 4

        if cfg["alerts_enabled"] and record["severity"] in ALERT_SEVERITIES:   # Feature 2
            ok, info = send_alert(cfg, record)
            record["alert_status"] = ("✅ " if ok else "⚠️ ") + info
            time.sleep(0.6)  # stay under Discord's webhook rate limit on big batches

        batch["n"] += 1
        batch["pt"] += pt
        batch["ct"] += ct
        batch["cost"] += record["cost"]
        st.session_state.results.append(record)
        progress.progress(i / len(lines), text=f"Analyzed {i}/{len(lines)}")

    progress.empty()
    st.session_state.batch = batch


def render_result(r: dict):
    with st.container(border=True):
        head, btn = st.columns([4, 1])
        head.markdown(f"### {SEVERITY_ICON[r['severity']]} {r['severity']} — {r['attack_type']}")
        if r["false_positive"]:
            btn.success("Marked false positive")
        else:
            btn.button("Mark as False Positive", key=f"fp_{r['id']}",
                       on_click=handle_false_positive, args=(r["id"],))
        st.code(r["log"], language=None)
        with st.expander("🔒 What OpenAI actually received (masked)"):
            st.code(r["masked"], language=None)
        st.write(f"**Analysis:** {r['summary']}")
        st.write(f"**Recommended action:** {r['recommendation']}")
        t = r["threat"]
        if t:
            if "error" in t:
                st.info(f"Threat intel: {t['error']}")
            else:
                st.markdown(f"**🌐 AbuseIPDB — {t['ip']}**")
                a, b, c, d = st.columns(4)
                a.metric("Abuse Confidence Score", f"{t['score']}%")
                b.metric("Reports (90d)", t["reports"])
                c.metric("Country", t["country"] or "—")
                d.metric("ISP", (t["isp"] or "—")[:22])
        st.caption(f"Tokens: {r['prompt_tokens']} in / {r['completion_tokens']} out · "
                   f"Cost: ${r['cost']:.6f}" + (f" · Alert: {r['alert_status']}" if r["alert_status"] else ""))


def render_metrics(container):
    totals = lifetime_totals()
    batch = st.session_state.get("batch", {"n": 0, "pt": 0, "ct": 0, "cost": 0.0})
    with container:
        st.subheader("📊 Dashboard")
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Analyses (all time)", totals["n"])
        c2.metric("Total Analyst Corrections", count_corrections())
        c3.metric("Tokens (this batch)", f"{batch['pt'] + batch['ct']:,}",
                  help=f"{batch['pt']:,} input + {batch['ct']:,} output")
        c4.metric("Est. cost (this batch)", f"${batch['cost']:.5f}")
        c5.metric("Est. cost (all time)", f"${totals['cost']:.5f}",
                  help=f"{totals['pt'] + totals['ct']:,} tokens in total")


def render_history(role: str):
    rows = get_history()
    st.caption(f"{len(rows)} saved investigation(s) in {os.path.basename(DB_PATH)}")
    if rows:
        view = [{"ID": r["id"], "Time": r["timestamp"], "Severity": r["severity"],
                 "Type": r["attack_type"], "Attacker IP": r["attacker_ip"],
                 "Abuse score": r["abuse_score"], "False positive": bool(r["false_positive"]),
                 "Model": r["model"], "Cost ($)": round(r["cost_usd"], 6), "Log": r["log"],
                 "Summary": r["summary"]} for r in rows]
        st.dataframe(view, hide_index=True)
    else:
        st.info("No investigations saved yet.")

    st.divider()
    col1, col2 = st.columns(2)
    with col1:                                              # RBAC: PDF download
        if has_permission(role, "download_pdf"):
            if rows:
                st.download_button("⬇️ Download PDF report", data=build_pdf_report(role, rows),
                                   file_name="soc_report.pdf", mime="application/pdf")
        else:
            st.info("🔒 PDF reports are available to Admins only.")
    with col2:                                              # RBAC: delete history
        if has_permission(role, "delete_history"):
            sure = st.checkbox("I understand this permanently deletes all history")
            st.button("🗑️ Delete history", disabled=not sure, on_click=handle_delete_history)
        else:
            st.info("🔒 Deleting history is available to Admins only.")


def main():
    st.set_page_config(page_title="AI SOC Analyst", page_icon="🛡️", layout="wide")
    init_db()
    ss = st.session_state
    ss.setdefault("user", None)
    ss.setdefault("results", [])
    ss.setdefault("log_input", "")

    if ss.user is None:
        login_screen()
        return

    cfg = render_sidebar(load_config())
    st.title("🛡️ AI-Powered SOC Analyst Tool")
    metrics_box = st.container()  # filled at the end so numbers reflect this run

    tab_analyze, tab_history = st.tabs(["🔍 Analyze logs", "🗂️ History"])
    with tab_analyze:
        st.text_area("Paste security logs (one per line)", key="log_input", height=180)
        upload = st.file_uploader("...or upload a .log / .txt / .csv file (CSV: uses the 'log' column)",
                                  type=["log", "txt", "csv"])
        left, right = st.columns([1, 5])
        left.button("Load sample logs", on_click=load_samples)
        if right.button("Analyze", type="primary"):
            text = ss.log_input
            if upload is not None:
                text += "\n" + read_uploaded_logs(upload)
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            if lines:
                run_batch(cfg, lines)
            else:
                st.warning("Please paste or upload at least one log line.")
        for result in ss.results:
            render_result(result)

    with tab_history:
        render_history(ss.user["role"])

    render_metrics(metrics_box)


if __name__ == "__main__":
    main()