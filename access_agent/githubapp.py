"""GitHub App installation tokens — access_agent.githubapp (v0.2).

The real fix for "temporary token": GitHub never lets anyone mint a new PAT
over the API, but a GitHub App CAN mint installation tokens that expire on
their own (GitHub-enforced, <= 1 hour) and are scoped to the repos where the
app is installed. This module mints them:

  1. JWT (RS256, <= 10 min) signed with the app private key via the openssl
     CLI — no third-party dependencies (same discipline as the whole agent).
  2. GET /app/installations -> installation id (auto-discovered once, stored).
  3. POST /app/installations/{id}/access_tokens -> installation token
     (requested narrowly: contents=write + metadata=read).

Owner configures it ONCE (PEM must arrive by SSH/scp — never through the AI
channel):
    sudo access-agent set-github-app <app_id> /path/to/app.pem
    sudo access-agent test-github-app

Broker contract (server.py /api/github/token):
  - app configured  -> REAL installation tokens; the master PAT is never served.
  - app not set     -> v0.1 behaviour (session-scoped PAT disclosure).
In both modes the request needs a recorded purpose and every grant is
appended to sessions.jsonl + audit. Token values are never logged.

Testability: the GitHub HTTP call lives in _api() — tests monkeypatch it;
no network is ever needed for the smoke suite.
"""
from __future__ import annotations

import calendar
import datetime
import json
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .security import audit, home, now_iso

APP_API = "https://api.github.com"
JWT_TTL_S = 540            # 9 minutes (GitHub allows <= 10)
REUSE_MARGIN_S = 300       # reuse cached token until 5 min before expiry
DEFAULT_PERMISSIONS = {"contents": "write", "metadata": "read"}


class GitHubAppError(Exception):
    """Raised for any config/mint failure; message is safe to show (no token values)."""


# ---------- config ----------

def app_config_path() -> Path:
    return home() / "github-app.json"


def pem_path() -> Path:
    return home() / "github-app.pem"


def load_config() -> dict:
    try:
        data = json.loads(app_config_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def configured() -> bool:
    cfg = load_config()
    return bool(str(cfg.get("app_id") or "").strip()) and pem_path().exists()


def save_config(app_id: str, pem_src: str, installation_id: str = "") -> dict:
    """Store app id + private key (chmod 600). Validates before saving."""
    app_id = str(app_id).strip()
    if not app_id.isdigit():
        raise GitHubAppError("app_id must be the numeric GitHub App ID")
    try:
        pem = Path(pem_src).read_text(encoding="utf-8")
    except Exception as e:
        raise GitHubAppError(f"cannot read pem file: {e}") from None
    if "PRIVATE KEY" not in pem or len(pem) < 100:
        raise GitHubAppError("file does not look like a GitHub App private key (.pem)")
    installation_id = str(installation_id).strip()
    if installation_id and not installation_id.isdigit():
        raise GitHubAppError("installation_id must be numeric (or empty for auto-discovery)")
    home().mkdir(parents=True, exist_ok=True)
    pem_path().write_text(pem, encoding="utf-8")
    try:
        pem_path().chmod(0o600)
    except Exception:
        pass
    cfg = {"app_id": app_id, "installation_id": installation_id,
           "configured_at": now_iso(), "mode": "github-app"}
    tmp = app_config_path().with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    tmp.replace(app_config_path())
    try:
        app_config_path().chmod(0o600)
    except Exception:
        pass
    audit("owner", "github_app_configured", {"app_id": app_id,
          "installation_id": installation_id or "auto"}, "")
    return cfg


def clear_config() -> bool:
    """Remove app config + key; broker falls back to PAT mode."""
    existed = app_config_path().exists() or pem_path().exists()
    for p in (app_config_path(), pem_path()):
        try:
            p.unlink()
        except Exception:
            pass
    _CACHE.clear()
    if existed:
        audit("owner", "github_app_cleared", {}, "")
    return existed


# ---------- JWT (RS256 via openssl CLI — stdlib has no RSA) ----------

def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint_jwt(app_id: str, pem_text: str, ttl_s: int = JWT_TTL_S,
             now: float | None = None) -> str:
    """RS256 JWT for the GitHub App auth flow, signed through openssl."""
    import base64
    now = int(now if now is not None else time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"},
                                separators=(",", ":")).encode())
    payload = _b64url(json.dumps(
        {"iss": int(app_id), "iat": now - 60, "exp": now + int(ttl_s)},
        separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    with tempfile.TemporaryDirectory(prefix="aa-jwt.") as td:
        key = Path(td) / "key.pem"
        key.write_text(pem_text, encoding="utf-8")
        try:
            key.chmod(0o600)
        except Exception:
            pass
        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key)],
            input=signing_input, capture_output=True, timeout=20)
    if r.returncode != 0 or not r.stdout:
        raise GitHubAppError(
            "openssl signing failed: " + r.stderr.decode(errors="replace")[:200])
    sig = base64.urlsafe_b64encode(r.stdout).rstrip(b"=").decode("ascii")
    return f"{header}.{payload}.{sig}"


# ---------- GitHub API (thin wrapper — tests monkeypatch this) ----------

def _api(method: str, path: str, bearer: str,
         body: dict | None = None, timeout: int = 20) -> tuple[int, object]:
    url = APP_API + path
    req = urllib.request.Request(
        url, method=method,
        data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "access-agent")
    req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read()).get("message", "")
        except Exception:
            detail = ""
        raise GitHubAppError(
            f"github api {method} {path} -> HTTP {e.code}: {str(detail)[:200]}") from None
    except GitHubAppError:
        raise
    except Exception as e:
        raise GitHubAppError(f"github api unreachable: {type(e).__name__}") from None


# ---------- mint ----------

_CACHE: dict = {}


def _expires_epoch(iso: str) -> float:
    try:
        dt = datetime.datetime.strptime(iso.replace("+00:00", "Z"),
                                        "%Y-%m-%dT%H:%M:%SZ")
        return calendar.timegm(dt.timetuple())
    except Exception:
        return time.time() + 3600  # pessimistic fallback: GitHub grants 1h


def mint_token(force: bool = False) -> dict:
    """Return a live installation token (cached until REUSE_MARGIN_S remains)."""
    cfg = load_config()
    if not (str(cfg.get("app_id") or "").strip() and pem_path().exists()):
        raise GitHubAppError("github app not configured "
                             "(owner: sudo access-agent set-github-app <app_id> <pem>)")
    now = time.time()
    c = _CACHE.get("tok")
    if not force and c and float(c.get("expires_epoch", 0)) - now > REUSE_MARGIN_S:
        return {**c, "cached": True}
    pem = pem_path().read_text(encoding="utf-8")
    jwt = mint_jwt(cfg["app_id"], pem)
    inst_id = str(cfg.get("installation_id") or "").strip()
    if not inst_id:
        st, data = _api("GET", "/app/installations", bearer=jwt)
        insts = data if isinstance(data, list) else (data or {}).get("installations", [])
        if not insts:
            raise GitHubAppError(
                "app has no installations — install it on the parastoo repo first "
                "(GitHub UI -> your app -> Install App)")
        inst_id = str(insts[0].get("id") or "")
        if not inst_id:
            raise GitHubAppError("installations response had no id")
        cfg["installation_id"] = inst_id
        tmp = app_config_path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        tmp.replace(app_config_path())
        try:
            app_config_path().chmod(0o600)
        except Exception:
            pass
    st, data = _api("POST", f"/app/installations/{inst_id}/access_tokens",
                    bearer=jwt, body={"permissions": DEFAULT_PERMISSIONS})
    token = str((data or {}).get("token") or "")
    if not token.startswith("ghs_"):
        raise GitHubAppError("unexpected access_tokens response (no ghs_ token)")
    expires_at = str((data or {}).get("expires_at") or "")
    out = {"token": token, "expires_at": expires_at,
           "expires_epoch": _expires_epoch(expires_at),
           "permissions": (data or {}).get("permissions") or DEFAULT_PERMISSIONS,
           "installation_id": inst_id,
           "repository_selection": (data or {}).get("repository_selection", ""),
           "cached": False}
    _CACHE["tok"] = out
    return dict(out)


# ---------- broker entry point (same contract as githubbroker.disclose) ----------

def disclose(purpose: str, ip: str = "") -> dict:
    """Serve a real installation token under a recorded grant.

    The master PAT is never touched; the returned token dies on its own.
    """
    if not isinstance(purpose, str) or len(purpose.strip()) < 8:
        return {"ok": False, "status": 400, "error": "purpose_required",
                "detail": "purpose must be >= 8 chars describing why the token is needed"}
    try:
        minted = mint_token()
    except GitHubAppError as e:
        audit("agent", "github_app_mint_failed", {"detail": str(e)[:200]}, ip)
        return {"ok": False, "status": 502, "error": "github_app_error",
                "detail": str(e)[:300]}
    grant = {
        "grant_id": uuid.uuid4().hex[:12],
        "purpose": purpose.strip()[:200],
        "mode": "github-app",
        "issued_at": now_iso(),
        "expires_at": minted["expires_at"],
        "cached": bool(minted.get("cached")),
        "ip": ip,
    }
    try:
        with (home() / "sessions.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(grant, ensure_ascii=False) + "\n")
    except Exception:
        pass
    audit("agent", "github_app_token_disclosed",
          {"grant_id": grant["grant_id"], "purpose": grant["purpose"],
           "expires_at": grant["expires_at"], "cached": grant["cached"]}, ip)
    return {
        "ok": True,
        "token": minted["token"],
        "mode": "github-app",
        "grant": grant,
        "expires_at": minted["expires_at"],
        "permissions": minted.get("permissions"),
        "note": ("real GitHub-enforced expiry: this installation token dies on its own "
                 "(<= 1h) and only reaches repos where the app is installed; "
                 "the owner's master PAT never left the server"),
    }


def test_github_app() -> dict:
    """Owner CLI: mint fresh and return ONLY metadata — never the token value."""
    m = mint_token(force=True)
    return {"ok": True, "app_id": load_config().get("app_id"),
            "installation_id": m.get("installation_id"),
            "expires_at": m.get("expires_at"),
            "permissions": m.get("permissions"),
            "repository_selection": m.get("repository_selection"),
            "token_prefix": m["token"][:4]}


def status() -> dict:
    """Safe summary for CLI/status output — no token or key values."""
    cfg = load_config()
    return {
        "configured": configured(),
        "app_id": str(cfg.get("app_id") or ""),
        "installation_id": str(cfg.get("installation_id") or ""),
        "pem_present": pem_path().exists(),
        "configured_at": str(cfg.get("configured_at") or ""),
        "cached_token_live": bool(
            _CACHE.get("tok")
            and float(_CACHE["tok"].get("expires_epoch", 0)) - time.time() > 0),
    }
