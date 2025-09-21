"""
Reusable Email Breach backend for GUI & CLI.
"""

import os
import json
import time
import hashlib
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None

# ----------------------------
# Paths
# ----------------------------
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

LOCAL_DB_PATH = os.path.join(DATA_DIR, "breaches_local.json")
CACHE_PATH = os.path.join(DATA_DIR, "email_breach_cache.json")
SETTINGS_PATH = os.path.join(DATA_DIR, "email_breach_settings.json")

CACHE_TTL = 60 * 60 * 24  # 24h

# ----------------------------
# Settings (API keys)
# ----------------------------
def load_settings() -> Dict[str, Any]:
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_settings(s: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
    except Exception:
        pass

def get_api_key(provider: str) -> Optional[str]:
    return load_settings().get(f"{provider}_api_key")

def set_api_key(provider: str, key: Optional[str]) -> None:
    s = load_settings()
    if key:
        s[f"{provider}_api_key"] = key.strip()
    else:
        s.pop(f"{provider}_api_key", None)
    save_settings(s)

# ----------------------------
# Cache
# ----------------------------
def _read_cache() -> Dict[str, Any]:
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _write_cache(obj: Dict[str, Any]) -> None:
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
    except Exception:
        pass

# ----------------------------
# Local demo breaches
# ----------------------------
EXAMPLE_DB = [
    {
        "Name": "LinkedIn",
        "Domain": "linkedin.com",
        "BreachDate": "2012-05-01",
        "DataClasses": ["Emails", "Passwords"],
        "Description": "LinkedIn password leak...",
        "AffectedEmails": ["alice@example.com"]
    }
]

def get_breaches_local(email: str) -> List[Dict[str, Any]]:
    email_l = email.lower().strip()
    try:
        with open(LOCAL_DB_PATH, "r", encoding="utf-8") as f:
            db = json.load(f)
    except Exception:
        db = EXAMPLE_DB
    return [b for b in db if email_l in [a.lower() for a in b.get("AffectedEmails", [])]]

# ----------------------------
# LeakCheck API
# ----------------------------
def get_breaches_leakcheck(email: str, timeout: int = 10):
    if requests is None:
        return None, {"status": 0, "text": "requests not installed"}
    api_key = get_api_key("leakcheck")
    if not api_key:
        return None, {"status": 0, "text": "missing LeakCheck API key"}

    url = f"https://leakcheck.io/api/v2/search?query={email}"
    headers = {"User-Agent": "ThreatToolkit/1.0", "X-API-Key": api_key}
    r = requests.get(url, headers=headers, timeout=timeout)

    if r.status_code != 200:
        return None, {"status": r.status_code, "text": r.text}

    data = r.json()
    items = (
        data.get("result")
        or data.get("results")
        or data.get("data")
        or data.get("hits")
        or [data]
    )

    breaches = []
    for it in items:
        if not isinstance(it, dict):
            continue
        breaches.append({
            "Name": it.get("title") or it.get("source") or "Unknown",
            "Domain": it.get("domain"),
            "BreachDate": it.get("date") or it.get("added"),
            "DataClasses": it.get("fields") or [],
            "Description": it.get("excerpt") or ""
        })
    return breaches, None

# ----------------------------
# Pwned Passwords
# ----------------------------
def check_pwned_password(password: str, timeout: int = 10):
    if requests is None:
        return False, 0, {"status": 0, "text": "requests not installed"}
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    r = requests.get(url, timeout=timeout)
    if r.status_code != 200:
        return False, 0, {"status": r.status_code, "text": r.text}
    for line in r.text.splitlines():
        sfx, count = line.split(":")
        if sfx.upper() == suffix:
            return True, int(count), None
    return False, 0, None

# ----------------------------
# Unified runner
# ----------------------------
def run_email_breach(email: str, provider="local", force_refresh=False):
    key = f"{provider}:{email.lower()}"
    cache = _read_cache()
    now = int(time.time())
    if not force_refresh and key in cache and now - cache[key]["ts"] < CACHE_TTL:
        return cache[key]["report"], cache[key]["breaches"], None

    if provider == "local":
        breaches = get_breaches_local(email)
    elif provider == "leakcheck":
        breaches, err = get_breaches_leakcheck(email)
        if err:
            return f"[LeakCheck error] {err}", [], err
    else:
        return f"Unknown provider {provider}", [], {"status": 0, "text": "unknown provider"}

    report = format_report(email, breaches, provider)
    cache[key] = {"ts": now, "report": report, "breaches": breaches}
    _write_cache(cache)
    return report, breaches, None

# ----------------------------
# Formatter
# ----------------------------
def format_report(email: str, breaches: List[Dict[str, Any]], provider: str):
    lines = [f"Email: {email}", f"Provider: {provider}"]
    if not breaches:
        lines.append("No breaches found.")
        return "\n".join(lines)
    lines.append(f"Total breaches: {len(breaches)}")
    for b in breaches:
        lines.append(f"- {b.get('Name')} ({b.get('BreachDate')})")
        if b.get("DataClasses"):
            lines.append(f"   • Data: {', '.join(b['DataClasses'])}")
        if b.get("Description"):
            lines.append(f"   • {b['Description']}")
    return "\n".join(lines)

# ----------------------------
# Export
# ----------------------------
def export_report(text: str, path: str):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return True
    except Exception:
        return False
