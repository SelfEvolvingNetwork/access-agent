"""Tokens, audit and config paths — access_agent.security.

All secrets live under ACCESS_AGENT_HOME (default /etc/access-agent, root-only).
Tokens are stored as SHA-256 hashes only; presented tokens are compared
constant-time. Nothing here ever logs a token value.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path


def home() -> Path:
    return Path(os.environ.get("ACCESS_AGENT_HOME", "/etc/access-agent"))


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------- tokens ----------

def load_tokens() -> dict:
    """tokens.json: {"admin_sha": "...", "agent_sha": "...|empty", "updated_at": iso}"""
    p = home() / "tokens.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("tokens.json must be an object")
        return data
    except Exception:
        return {"admin_sha": "", "agent_sha": "", "updated_at": ""}


def save_tokens(data: dict) -> None:
    p = home() / "tokens.json"
    data["updated_at"] = now_iso()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass


def check_token(presented: str, role: str) -> bool:
    """role: "admin" | "agent". Empty stored hash = realm disabled."""
    if not presented:
        return False
    stored = load_tokens().get(f"{role}_sha", "")
    if not stored:
        return False
    return hmac.compare_digest(sha256_hex(presented), stored)


# ---------- audit (append-only JSONL; contractual red line: agent must not edit it) ----------

def audit(actor: str, action: str, detail: dict | None = None, ip: str = "") -> None:
    d = home() / "audit"
    d.mkdir(parents=True, exist_ok=True)
    rec = {"ts": now_iso(), "ip": ip, "actor": actor, "action": action}
    if detail:
        rec.update(detail)
    with (d / "audit.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def audit_tail(n: int) -> list[str]:
    p = home() / "audit" / "audit.jsonl"
    if not p.exists():
        return []
    try:
        with p.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        return [l.rstrip("\n") for l in lines[-max(0, min(n, 2000)):]]
    except Exception:
        return []


# ---------- agent-realm pause state (v0.3 — mobile kill switch) ----------
# state.json (chmod 600): {"agent_paused": bool, "reason": str, "ts": iso}
# Paused realm only blocks the agent role; admin stays a full superset and
# public endpoints (/healthz) are untouched. Survives service restarts.

def load_state() -> dict:
    p = home() / "state.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"agent_paused": False, "reason": "", "ts": ""}


def save_state(data: dict) -> None:
    p = home() / "state.json"
    data["ts"] = now_iso()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass


def agent_paused() -> tuple[bool, str]:
    s = load_state()
    return bool(s.get("agent_paused")), str(s.get("reason", ""))


def set_agent_paused(paused: bool, reason: str = "") -> dict:
    s = load_state()
    s["agent_paused"] = bool(paused)
    s["reason"] = str(reason)[:300]
    save_state(s)
    return s


# ---------- admin sessions (v0.4 — ورود با رمز سرور؛ parastoo-mobile) ----------
# توکن ادمین اصلی فقط به‌صورت هش نگه‌داری می‌شود، پس با رمز «نشست» صادر
# می‌کنیم نه آن توکن. sessions.json (chmod 600):
#   {"sessions": [{"sha": "...", "created": iso, "expires": iso,
#                  "label": str, "ip": str}]}
# TTL ۳۰ روز، سقف ۱۰ نشست فعال (کهنه‌ترین حذف می‌شود)؛ هر بررسی، منقضی‌ها
# را پر می‌کند. هیچ رویدادی خودِ رمز یا توکن را لاگ نمی‌کند.

SESSION_TTL_S = 30 * 24 * 3600
SESSIONS_MAX = 10


def load_sessions() -> dict:
    p = home() / "sessions.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("sessions"), list):
            return data
    except Exception:
        pass
    return {"sessions": []}


def save_sessions(data: dict) -> None:
    p = home() / "sessions.json"
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass


def _prune_sessions(sessions: list[dict], now: float | None = None) -> list[dict]:
    now = time.time() if now is None else now
    live = [s for s in sessions if _parse_iso(s.get("expires", "")) > now]
    return live[-SESSIONS_MAX:]


def _parse_iso(value: str) -> float:
    try:
        import datetime
        return datetime.datetime.fromisoformat(value).timestamp()
    except Exception:
        return 0.0


def mint_session(label: str = "", ip: str = "") -> tuple[str, dict]:
    """New admin session — returns (raw_token, record). Raw is shown once."""
    import secrets as pysecrets
    raw = "aasess_" + pysecrets.token_hex(24)
    now = time.time()
    rec = {
        "sha": sha256_hex(raw),
        "created": now_iso(),
        "expires": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now + SESSION_TTL_S)),
        "label": str(label)[:80],
        "ip": ip,
    }
    data = load_sessions()
    data["sessions"] = _prune_sessions(data.get("sessions", []), now) + [rec]
    save_sessions(data)
    return raw, rec


def check_session(presented: str) -> bool:
    """Constant-time compare against live sessions; prunes expired on read."""
    if not presented:
        return False
    data = load_sessions()
    live = _prune_sessions(data.get("sessions", []))
    if len(live) != len(data.get("sessions", [])):
        data["sessions"] = live
        save_sessions(data)
    h = sha256_hex(presented)
    return any(hmac.compare_digest(h, s.get("sha", "")) for s in live)


def revoke_sessions() -> int:
    """Owner-side logout everywhere (v0.4). Returns removed count."""
    data = load_sessions()
    n = len(data.get("sessions", []))
    save_sessions({"sessions": []})
    return n
