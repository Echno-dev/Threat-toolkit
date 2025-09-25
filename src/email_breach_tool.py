"""
Wrapper between GUI and modules/email_breach.py
Ensures the GUI can call consistent functions.
"""

import os
import json
from modules import email_breach

BASE_DIR = os.path.dirname(os.path.dirname(__file__)) or os.getcwd()
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

SETTINGS_PATH = os.path.join(DATA_DIR, "email_breach_settings.json")




# ----------------------------
# API Key Management
# ----------------------------
def _load_settings():
    print(f"[DEBUG] Loading settings from: {SETTINGS_PATH}")
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                print(f"[DEBUG] Settings content: {data}")
                return data
        except Exception as e:
            print(f"[DEBUG] Failed to load settings: {e}")
            return {}
    return {}


def _save_settings(data):
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[DEBUG] Saved settings to {SETTINGS_PATH}: {data}")
    except Exception as e:
        print(f"[email_breach_tool] Failed to save settings: {e}")


def get_api_key(provider: str):
    data = _load_settings()
    return data.get("api_keys", {}).get(provider)


def set_api_key(provider: str, key: str):
    data = _load_settings()
    if "api_keys" not in data:
        data["api_keys"] = {}
    if key:
        data["api_keys"][provider] = key.strip()
    else:
        data["api_keys"].pop(provider, None)
    _save_settings(data)
    print(f"[DEBUG] set_api_key called with provider='{provider}', key='{key}'")



# ----------------------------
# Core Functions
# ----------------------------
def run_email_breach(email: str, provider="local", force_refresh=False):
    """
    Wrapper around modules.email_breach.run_email_breach
    Returns (report_text, breaches, error)
    """
    try:
        report, breaches, error = email_breach.run_email_breach(
            email=email,
            provider=provider,
            force_refresh=force_refresh
        )
        return report, breaches, error
    except Exception as e:
        return f"[email_breach_tool] Error: {e}", [], str(e)


def check_pwned_password(password: str):
    """
    Wrapper around modules.email_breach.check_pwned_password
    Returns (found, count, error)
    """
    try:
        return email_breach.check_pwned_password(password)
    except Exception as e:
        return False, 0, str(e)
