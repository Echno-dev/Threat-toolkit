# modules/email_breach.py
"""
Email-breach helpers — local DB + XposedOrNot (XON) + pwned-passwords helper.

Drop this file at: modules/email_breach.py
Requires `requests` for live API usage (pip install requests).
"""

from __future__ import annotations
import requests
import os
import json
import time
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from email_breach_tool import get_api_key, set_api_key


try:
    import requests
except Exception:
    requests = None

# ----------------------------
# Paths & config
# ----------------------------
BASE_DIR = os.path.dirname(os.path.dirname(__file__)) or os.getcwd()
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

LOCAL_DB_PATH = os.path.join(DATA_DIR, "breaches_local.json")
CACHE_PATH = os.path.join(DATA_DIR, "email_breach_cache.json")
SETTINGS_PATH = os.path.join(DATA_DIR, "email_breach_settings.json")

CACHE_TTL = 60 * 60 * 24  # 24h

# ----------------------------
# Local demo data (fallback)
# ----------------------------
EXAMPLE_DB = [
    {
        "Name": "LinkedIn",
        "Domain": "linkedin.com",
        "BreachDate": "2012-05-01",
        "DataClasses": ["Emails", "Passwords"],
        "Description": "LinkedIn password leak...",
        "AffectedEmails": ["alice@example.com"]
    },
    {
        "Name": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-01",
        "DataClasses": ["Emails", "PasswordHints", "Passwords"],
        "Description": "Adobe database leak...",
        "AffectedEmails": ["alice@example.com"]
    }
]

# ensure local DB exists (sample)
try:
    if not os.path.exists(LOCAL_DB_PATH):
        with open(LOCAL_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(EXAMPLE_DB, f, indent=2)
except Exception:
    pass

# ----------------------------
# Settings helpers (API keys if needed later)
# ----------------------------
def load_settings() -> Dict[str, Any]:
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

#def get_api_key(provider: str) -> Optional[str]:
#    s = load_settings()
#    return s.get("api_keys", {}).get(provider)
#
#def set_api_key(provider: str, key: Optional[str]) -> None:
 #   s = load_settings()
 #       s["api_keys"] = {}
 #   if key:
 #       s["api_keys"][provider] = key.strip()
 #   else:
 #       s["api_keys"].pop(provider, None)
 #   save_settings(s)



# ----------------------------
# Cache helpers
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
# Local lookup
# ----------------------------
def get_breaches_local(email: str) -> List[Dict[str, Any]]:
    email_l = email.strip().lower()
    try:
        with open(LOCAL_DB_PATH, "r", encoding="utf-8") as f:
            db = json.load(f)
    except Exception:
        db = EXAMPLE_DB
    res = []
    for e in db:
        affected = e.get("AffectedEmails", []) or []
        for a in affected:
            if isinstance(a, str) and a.lower() == email_l:
                res.append(e)
                break
    return res

# ----------------------------
# XposedOrNot (XON) provider
# ----------------------------
def get_breaches_xon(email: str, timeout: int = 10) -> Tuple[Optional[List[Dict[str, Any]]], Optional[Dict[str, Any]]]:
    """
    Query XposedOrNot public check-email API.
    Returns (breach_list or None, error_dict or None)
    Normalized breach entries: {Name, Domain, BreachDate, DataClasses, Description}
    """
    if requests is None:
        return None, {"status": 0, "text": "requests library not available"}
    # API doc: https://api.xposedornot.com/v1/check-email/<email>
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    headers = {"User-Agent": "Multinador-EmailBreach/1.0"}

    try:
        r = requests.get(url, headers=headers, timeout=timeout)
    except Exception as e:
        return None, {"status": 0, "text": str(e)}

    if r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            return None, {"status": r.status_code, "text": "invalid json from XON"}
        # XON docs show either {"Error":"Not found"} or {"breaches": [[...]]} or analytics
        if isinstance(data, dict) and data.get("Error"):
            # Not found
            return [], None
        # Simple "breaches" can be list-of-lists or list-of-strings
        breaches_out: List[Dict[str, Any]] = []
        # Case 1: data contains "breaches" key (list)
        if isinstance(data, dict) and "breaches" in data:
            raw = data.get("breaches") or []
            # raw may be nested list: [[ "SiteA", "SiteB" ]] or flat list
            items = []
            if len(raw) == 0:
                items = []
            elif isinstance(raw[0], list):
                # flatten first array
                items = raw[0]
            elif isinstance(raw, list):
                # list of strings
                items = raw
            else:
                items = []
            for name in items:
                if not isinstance(name, str):
                    continue
                breaches_out.append({
                    "Name": name,
                    "Domain": None,
                    "BreachDate": None,
                    "DataClasses": [],
                    "Description": ""
                })
            return breaches_out, None
        # Case 2: more detailed 'breach-analytics' style response
        if isinstance(data, dict) and data.get("breach_metrics") or data.get("ExposedBreaches") or data.get("breaches_details"):
            # try several possible keys
            items = data.get("ExposedBreaches") or data.get("breaches_details") or []
            for it in items:
                if not isinstance(it, dict):
                    continue
                name = it.get("breach") or it.get("name") or it.get("site") or it.get("title")
                domain = it.get("domain") or it.get("site") or None
                breach_date = it.get("xposed_date") or it.get("breach_date") or it.get("date")
                data_classes = []
                xpd = it.get("xposed_data") or it.get("exposed_data") or it.get("DataClasses") or ""
                if isinstance(xpd, str) and xpd:
                    data_classes = [x.strip() for x in xpd.split(";") if x.strip()]
                breaches_out.append({
                    "Name": name or "Unknown",
                    "Domain": domain,
                    "BreachDate": breach_date,
                    "DataClasses": data_classes,
                    "Description": it.get("description", "") or ""
                })
            return breaches_out, None

        # fallback: unknown shape, try to extract lists of strings
        try:
            flat = []
            if isinstance(data, list):
                for el in data:
                    if isinstance(el, str):
                        flat.append(el)
            if flat:
                for name in flat:
                    breaches_out.append({
                        "Name": name,
                        "Domain": None,
                        "BreachDate": None,
                        "DataClasses": [],
                        "Description": ""
                    })
                return breaches_out, None
        except Exception:
            pass

        # unknown structure but not error
        return None, {"status": r.status_code, "text": "unexpected xon response shape"}
    elif r.status_code == 404:
        # treat as not found
        return [], None
    else:
        # forward status + limited text
        txt = (r.text or "")[:800]
        return None, {"status": r.status_code, "text": txt}

# ----------------------------
# Pwned Passwords (HIBP k-anonymity)
# ----------------------------
def check_pwned_password(password: str, timeout: int = 10) -> Tuple[bool, int, Optional[Dict[str, Any]]]:
    if not isinstance(password, str) or password == "":
        raise ValueError("password must be a non-empty string")
    if requests is None:
        return False, 0, {"status": 0, "text": "requests library not available"}

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "Multinador-PwnedPasswords/1.0"}
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
    except Exception as e:
        return False, 0, {"status": 0, "text": str(e)}
    if r.status_code != 200:
        return False, 0, {"status": r.status_code, "text": (r.text or "")[:800]}
    for line in r.text.splitlines():
        parts = line.split(":")
        if len(parts) != 2:
            continue
        suf, cnt = parts
        if suf.upper() == suffix.upper():
            try:
                return True, int(cnt.strip()), None
            except Exception:
                return True, 0, None
    return False, 0, None

# ----------------------------
# Simple analyzer & formatter
# ----------------------------
def analyze_breaches_simple(breaches: List[Dict[str, Any]]) -> Tuple[str, Optional[int], Optional[int]]:
    if not breaches:
        return "NONE", None, None
    years: List[int] = []
    score = 0
    for b in breaches:
        bd = b.get("BreachDate") or ""
        if bd:
            try:
                years.append(int(str(bd).split("-")[0]))
            except Exception:
                pass
        data_classes = [str(x).lower() for x in (b.get("DataClasses") or [])]
        if "passwords" in data_classes:
            score += 3
        if "password hints" in data_classes or "passwordhints" in data_classes:
            score += 2
        if any(x in data_classes for x in ("credit card", "financial", "ssn", "national id", "personal")):
            score += 4
        if any(x in data_classes for x in ("emails", "email")):
            score += 1
    first = min(years) if years else None
    last = max(years) if years else None
    if score >= 6:
        sev = "CRITICAL"
    elif score >= 4:
        sev = "HIGH"
    elif score >= 2:
        sev = "MEDIUM"
    else:
        sev = "LOW"
    return sev, first, last

def _breach_short_line(b: Dict[str, Any]) -> str:
    name = b.get("Name") or b.get("Title") or "Unknown"
    bd = b.get("BreachDate") or ""
    year = "?"
    if bd:
        try:
            year = str(int(str(bd).split("-")[0]))
        except Exception:
            year = str(bd)
    return f" - {name} ({year})"

def format_report(email: str, breaches: Optional[List[Dict[str, Any]]], source: str = "local", error: Optional[Dict[str, Any]] = None) -> str:
    breached = bool(breaches)
    total = len(breaches) if breaches else 0
    severity, first_year, last_year = analyze_breaches_simple(breaches or [])
    lines: List[str] = []
    lines.append(f"Email: {email}")
    lines.append(f"Breached: {'YES' if breached else 'NO'}")
    lines.append(f"Total breaches found: {total}")
    lines.append(f"First seen (year): {first_year if first_year is not None else 'N/A'}")
    lines.append(f"Most recent (year): {last_year if last_year is not None else 'N/A'}")
    lines.append(f"Severity: {severity}")
    lines.append("")
    if error:
        lines.append(f"[{source}] error: status {error.get('status')} text: {error.get('text')}")
        return "\n".join(lines)
    if breaches:
        lines.append(f"[{source}] breaches: {total}")
        for b in breaches:
            lines.append(_breach_short_line(b))
            data_classes = b.get("DataClasses") or []
            if data_classes:
                try:
                    lines.append(f"    • Data exposed: {', '.join(data_classes)}")
                except Exception:
                    lines.append(f"    • Data exposed: {data_classes}")
            desc = b.get("Description") or ""
            if desc:
                short = str(desc).strip()
                if len(short) > 200:
                    short = short[:197] + "..."
                lines.append(f"    • Description: {short}")
        lines.append("")
    lines.append("Recommendations:")
    if severity in ("CRITICAL", "HIGH"):
        lines.append(" - Change passwords for breached services immediately.")
        lines.append(" - If you reused passwords, change them across other services.")
        lines.append(" - Enable two-factor authentication (2FA) for important accounts.")
        lines.append(" - Use a password manager to generate and store unique passwords.")
        lines.append(" - Consider a credit freeze / monitoring if financial data was exposed.")
    elif severity == "MEDIUM":
        lines.append(" - Change passwords for affected accounts.")
        lines.append(" - Enable 2FA and review account activity.")
        lines.append(" - Use a password manager to avoid reuse.")
    elif severity == "LOW":
        lines.append(" - Monitor accounts and consider changing passwords.")
        lines.append(" - Use unique passwords and enable 2FA where possible.")
    else:
        lines.append(" - No known breaches for this email. Continue monitoring and use strong, unique passwords.")
    return "\n".join(lines)

# ----------------------------
# Unified runner
# ----------------------------
def run_email_breach(email: str, provider: str = "local", force_refresh: bool = False):
    """
    provider: 'local' | 'xon' | 'leakcheck' | 'breachdirectory'
    Returns (report_text, breaches_list_or_empty, error_or_None)
    """
    if not email or not isinstance(email, str):
        raise ValueError("email must be a non-empty string")
    key = f"{provider}:{email.strip().lower()}"
    cache = _read_cache()
    now = int(time.time())
    if not force_refresh and key in cache and now - cache[key].get("ts", 0) < CACHE_TTL:
        cached = cache[key]["breaches"]
        return cache[key]["report"], cached, None

    # --- Local DB ---
    if provider == "local":
        breaches = get_breaches_local(email)
        report = format_report(email, breaches, source="local")
        cache[key] = {"ts": now, "report": report, "breaches": breaches}
        _write_cache(cache)
        return report, breaches, None

    # --- XposedOrNot ---
    if provider == "xon":
        breaches, err = get_breaches_xon(email)
        if err:
            # fallback to local
            fallback = get_breaches_local(email)
            report = format_report(email, fallback, source="local", error=err)
            cache[key] = {"ts": now, "report": report, "breaches": fallback}
            _write_cache(cache)
            return report, fallback, err
        report = format_report(email, breaches, source="xon")
        cache[key] = {"ts": now, "report": report, "breaches": breaches}
        _write_cache(cache)
        return report, breaches, None

    # --- BreachDirectory ---
    if provider == "breachdirectory":
        breaches, err = get_breaches_breachdirectory(email)
        if err:
            # fallback to local
            fallback = get_breaches_local(email)
            report = format_report(email, fallback, source="local", error=err)
            cache[key] = {"ts": now, "report": report, "breaches": fallback}
            _write_cache(cache)
            return report, fallback, err
        report = format_report(email, breaches, source="breachdirectory")
        cache[key] = {"ts": now, "report": report, "breaches": breaches}
        _write_cache(cache)
        return report, breaches, None

    # --- LeakCheck ---
    if provider == "leakcheck":
        breaches, err = get_breaches_leakcheck(email)
        if err:
            fallback = get_breaches_local(email)
            report = format_report(email, fallback, source="local", error=err)
            cache[key] = {"ts": now, "report": report, "breaches": fallback}
            _write_cache(cache)
            return report, fallback, err
        report = format_report(email, breaches, source="leakcheck")
        cache[key] = {"ts": now, "report": report, "breaches": breaches}
        _write_cache(cache)
        return report, breaches, None

    # --- Unknown provider ---
    err = {"status": 0, "text": f"unknown provider {provider}"}
    return format_report(email, [], source=provider, error=err), [], err


# ----------------------------
# LeakCheck API
# ----------------------------
def get_breaches_leakcheck(email: str, timeout: int = 10):
    """
    Query LeakCheck API for breaches.
    Always returns (breaches_list, error_dict_or_None).
    """
    if requests is None:
        return [], {"status": 0, "text": "requests not installed"}

    api_key = get_api_key("leakcheck")
    if not api_key:
        return [], {"status": 0, "text": "missing LeakCheck API key"}

    url = f"https://leakcheck.io/api/v2/search?query={email}"
    headers = {"User-Agent": "ThreatToolkit/1.0", "X-API-Key": api_key}

    try:
        r = requests.get(url, headers=headers, timeout=timeout)
    except Exception as e:
        return [], {"status": 0, "text": f"request failed: {e}"}

    if r.status_code != 200:
        return [], {"status": r.status_code, "text": r.text}

    try:
        data = r.json()
    except Exception:
        return [], {"status": r.status_code, "text": "invalid JSON response"}

    items = data.get("result") or data.get("results") or data.get("data") or []
    breaches = []
    for it in items:
        if isinstance(it, dict):
            breaches.append({
                "Name": it.get("title") or it.get("source") or "Unknown",
                "Domain": it.get("domain") or "",
                "BreachDate": it.get("date") or it.get("added") or "",
                "DataClasses": it.get("fields") or [],
                "Description": it.get("excerpt") or ""
            })

    return breaches, None



# ----------------------------
# BreachDirectory API
# ----------------------------
def get_breaches_breachdirectory(email: str, timeout: int = 10):
    """
    Query BreachDirectory API for breaches.
    Returns (breaches, error)
    """
    if requests is None:
        return [], {"status": 0, "text": "requests not installed"}

    api_key = get_api_key("breachdirectory")
    if not api_key:
        return [], {"status": 0, "text": "missing BreachDirectory API key"}

    url = f"https://breachdirectory.p.rapidapi.com/?func=auto&term={email}"
    headers = {
        "User-Agent": "ThreatToolkit/1.0",
        "X-RapidAPI-Key": api_key,
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
    }

    try:
        r = requests.get(url, headers=headers, timeout=timeout)
    except Exception as e:
        return [], {"status": 0, "text": str(e)}

    if r.status_code != 200:
        return [], {"status": r.status_code, "text": r.text}

    try:
        data = r.json()
    except Exception:
        return [], {"status": r.status_code, "text": "invalid JSON from BreachDirectory"}

    items = data.get("result") or []
    breaches = []
    for it in items:
        if not isinstance(it, dict):
            continue
        breaches.append({
            "Name": it.get("source") or "Unknown",
            "Domain": it.get("domain"),
            "BreachDate": it.get("date"),
            "DataClasses": it.get("fields") or [],
            "Description": it.get("description") or ""
        })
    return breaches, None


    # --- Unknown provider ---
    err = {"status": 0, "text": f"unknown provider {provider}"}
    return format_report(email, [], source=provider, error=err), [], err


# ----------------------------
# Export helper
# ----------------------------
def export_report(text: str, path: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return True
    except Exception:
        return False
