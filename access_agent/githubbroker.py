"""GitHub PAT custody + session-scoped disclosure — access_agent.githubbroker.

The owner's GitHub PAT is stored only in ACCESS_AGENT_HOME/github.env (chmod
600, outside any git tree). The AI agent can never push to GitHub directly
with the owner's own knowledge — it asks this broker, which records a grant
(purpose + TTL bookkeeping) and returns the token over the authenticated TLS
channel. v0.1 model (owner decision): session-scoped disclosure; real
1-hour GitHub App installation tokens are the documented v2 upgrade.
"""
from __future__ import annotations

import json
import time
import uuid

from .security import audit, home, now_iso

DEFAULT_TTL_MIN = 60


def _env_path():
    return home() / "github.env"


def stored_token() -> str:
    try:
        for line in _env_path().read_text(encoding="utf-8").splitlines():
            if line.startswith("GITHUB_TOKEN="):
                return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return ""


def save_token(token: str) -> bool:
    if not isinstance(token, str) or len(token) < 20 or "\n" in token or "\r" in token:
        return False
    p = _env_path()
    p.write_text(
        "# managed by access-agent — root-only, never commit\n"
        f"GITHUB_TOKEN={token}\n",
        encoding="utf-8",
    )
    p.chmod(0o600)
    return True


def disclose(purpose: str, ttl_min: int = DEFAULT_TTL_MIN, ip: str = "") -> dict:
    """Return the stored PAT under a recorded, session-scoped grant."""
    if not isinstance(purpose, str) or len(purpose.strip()) < 8:
        return {"ok": False, "status": 400,
                "error": "purpose_required",
                "detail": "purpose must be >= 8 chars describing why the token is needed"}
    try:
        ttl_min = max(1, min(int(ttl_min), 24 * 60))
    except (TypeError, ValueError):
        ttl_min = DEFAULT_TTL_MIN
    token = stored_token()
    if not token:
        return {"ok": False, "status": 409, "error": "no_stored_token",
                "detail": "owner sets it once: sudo access-agent set-github-token <token>"}

    grant = {
        "grant_id": uuid.uuid4().hex[:12],
        "purpose": purpose.strip()[:200],
        "ttl_min": ttl_min,
        "issued_at": now_iso(),
        "expires_at_bookkeeping": time.strftime(
            "%Y-%m-%dT%H:%M:%S%z", time.localtime(time.time() + ttl_min * 60)),
        "ip": ip,
    }
    try:
        with (home() / "sessions.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(grant, ensure_ascii=False) + "\n")
    except Exception:
        pass
    audit("agent", "github_token_disclosed",
          {"grant_id": grant["grant_id"], "purpose": grant["purpose"], "ttl_min": ttl_min}, ip)
    return {
        "ok": True,
        "token": token,
        "grant": grant,
        "note": ("session-scoped disclosure (v0.1): the PAT itself does not expire — "
                 "the real revocation is token rotation by the owner"),
    }


def grants_tail(n: int = 50) -> list[dict]:
    p = home() / "sessions.jsonl"
    if not p.exists():
        return []
    try:
        with p.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        out = []
        for l in lines[-max(0, min(n, 500)):]:
            try:
                out.append(json.loads(l))
            except Exception:
                continue
        return out
    except Exception:
        return []
