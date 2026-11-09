"""Parastoo lifecycle control from the owner's phone — access_agent.parastoolifecycle.

Owner directive (2026-11-08): the admin must get everything through Parastoo
Mobile, never logging into the server — install, full uninstall with all
belongings, reinstall, and forced update.

Rules (non-negotiable):
- Admin realm only (guard lives in server.py); every transition audited;
  no secret ever reaches the log or audit (installer prints none by contract).
- Max ONE lifecycle operation at a time; a second call gets 409 busy.
- Mutual exclusivity with /api/exec (v0.5.1, owner decree 2026-11-09 «one
  transparent pipeline»): while an operation runs, exec requests matching
  install/update/uninstall patterns get 409 lifecycle_busy (read-only
  supervision still passes); while a conflicting exec runs, start()
  refuses with 409 exec_busy. The mid-install deploy race (parastoo
  docs/LESSONS.md, field 2026-11-08) is structurally closed.
- Operations run in a background thread; output appends to a log file under
  ACCESS_AGENT_HOME/parastoo-lifecycle/ (root-only directory, chmod 600).
- "Full uninstall" = POINT ZERO (owner decree 2026-11-09 «هیچ آثاری و گردی
  باقی نماند»): uninstall.sh answered y/y (drop projects/volumes) PLUS removal
  of every last trace — install folder, /var/lib/parastoo incl. the TLS store
  (the stock installer would keep it; the owner's explicit full-cleanup order
  overrides the certificate-store rule on this path), /etc/parastoo-domain,
  /etc/parastoo-install-path, systemd units, /tmp leftovers, every parastoo
  docker artifact (user-project + stack containers, networks, volumes,
  images, build cache) and the installer-injected registry-mirrors in
  /etc/docker/daemon.json (+ docker restart only when that changed).
  The bridge itself and all of its assets (/etc/access-agent/**, audit,
  tokens, github vault) are NEVER touched — the phone keeps its channel.
  The final log line is "== point zero reached ==" and lifecycle-status
  reports installed:false — that polling channel IS the notification to
  Parastoo Mobile; the app renders the zero-point state and offers a fresh
  install that behaves exactly like a first install on a clean OS.
- Default install domain is ALWAYS zeolitecenter.ir (owner decree
  2026-11-09): before every fresh install the bridge writes
  /etc/parastoo-domain from DEFAULT_BASE_DOMAIN; install.sh picks it up
  when no live .env exists (a live .env still wins per install.sh contract).
- Destructive endpoints require {"confirm": "<action>"} exactly matching the
  action (defense in depth; the primary gate is the admin token itself).
- Install goes through the official one-liner path only: download bootstrap.sh
  (raw.githubusercontent → gh-proxy.com fallback for Iran) to /tmp, then run
  it. No other install method is offered (parastoo README §contract).

Test hooks (offline smoke suite): ACCESS_AGENT_PARASTOO_DIR_FILE,
ACCESS_AGENT_PARASTOO_BOOTSTRAP_CMD, ACCESS_AGENT_PARASTOO_SUDO.
"""
from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from pathlib import Path

from . import execbridge
from .security import audit, home, now_iso

ACTIONS = ("install", "uninstall", "reinstall", "update")
CONFIRM_REQUIRED = ("uninstall", "reinstall")   # destructive pair
MAX_RUNTIME_S = 3600                            # hard cap: 1 hour per operation
LOG_TAIL_DEFAULT = 40
LOG_TAIL_MAX = 200

BOOTSTRAP_URL = (
    "https://raw.githubusercontent.com/SelfEvolvingNetwork/parastoo/main/bootstrap.sh"
)
BOOTSTRAP_PROXY = f"https://gh-proxy.com/{BOOTSTRAP_URL}"

# Owner decree 2026-11-09: the default install domain is always this one.
# Written to /etc/parastoo-domain before every fresh install; parastoo's
# install.sh restores it when no live .env exists (a live .env still wins).
DEFAULT_BASE_DOMAIN = "zeolitecenter.ir"

_state = {
    "busy": False, "action": "", "started_at": "", "finished_at": "",
    "exit_code": None, "ok": None, "duration_s": None, "log_file": "",
}
_lock = threading.Lock()


# ---------- environment / paths ----------

def _dir_file() -> Path:
    return Path(os.environ.get(
        "ACCESS_AGENT_PARASTOO_DIR_FILE", "/etc/parastoo-install-path"))


def is_busy() -> bool:
    with _lock:
        return bool(_state.get("busy"))


def exec_block_reason(cmd: str) -> str:
    """Non-empty refusal reason for an exec request while a lifecycle operation
    is running (mutating commands only — read-only supervision still passes)."""
    with _lock:
        busy = bool(_state.get("busy"))
        action = _state.get("action", "")
    if not busy:
        return ""
    tok = execbridge.lifecycle_conflict(cmd)
    if not tok:
        return ""
    return (f'lifecycle operation "{action}" is running; exec matching '
            f'"{tok}" is refused — poll /api/admin/parastoo/lifecycle-status')


def install_path() -> str:
    try:
        p = _dir_file().read_text(encoding="utf-8").strip().splitlines()
        if p and p[0]:
            return p[0]
    except Exception:
        pass
    fallback = Path("/opt/parastoo")
    return str(fallback) if (fallback / "install.sh").exists() else ""


def installed() -> bool:
    p = install_path()
    return bool(p) and (Path(p) / "install.sh").exists()


def version() -> str:
    """VERSION from core/app/config.py of the installed tree (best-effort)."""
    p = install_path()
    if not p:
        return ""
    try:
        src = (Path(p) / "core" / "app" / "config.py").read_text(encoding="utf-8")
        m = re.search(r'VERSION:\s*str\s*=\s*"([^"]+)"', src)
        return m.group(1) if m else ""
    except Exception:
        return ""


# ---------- setup-wizard token (v0.5.3, parastoo-mobile) ----------

_ENV_KEYS = ("PARASTOO_SETUP_TOKEN", "BASE_DOMAIN", "TLS_ENABLED", "ACME_EMAIL",
             "TRAEFIK_TLS")


def _read_env(path: Path) -> dict:
    """Flat KEY=value reader for the installed .env — comments/quotes tolerated."""
    out: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            if key in _ENV_KEYS and key not in out:
                out[key] = val.strip().strip('"').strip("'")
    except Exception:
        pass
    return out


def _acme_from_traefik(install: str) -> str:
    """ایمیل زندهٔ ACME از config/traefik.yml — render_static با هر apply
    دامنه آن را می‌نویسد؛ منبع زندهٔ درست (میدان 2026-11-09: ACME_EMAIL در
    .env می‌توانست از زمان نصب کهنه بماند)."""
    try:
        txt = (Path(install) / "config" / "traefik.yml").read_text(
            encoding="utf-8", errors="replace")
        m = re.search(r'\bemail:\s*["\']?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+)', txt)
        return m.group(1) if m else ""
    except Exception:
        return ""


def setup_token_info() -> dict:
    """Facts the owner's phone needs to finish the panel setup wizard WITHOUT
    ssh (owner directive 2026-11-09: «توکن نصب باید در پرستو موبایل نمایش
    داده شود»): the PARASTOO_SETUP_TOKEN plus domain/TLS context so the app
    can offer a one-tap link to the wizard. admin realm only (guard in
    server.py); the token value NEVER reaches log or audit — the audit event
    carries the has_token boolean only, same contract as github.env.

    v0.5.4 (field 2026-11-09): TLS/ACME prefer the LIVE writer fields —
    TRAEFIK_TLS (sync_host_env refreshes it on every apply) and the acme
    email rendered inside config/traefik.yml — falling back to the
    install-era TLS_ENABLED/ACME_EMAIL lines which can go stale."""
    installed_ok = installed()
    p = install_path()
    if not installed_ok or not p:
        return {"ok": True, "installed": False, "has_token": False,
                "setup_token": "", "base_domain": "", "tls_enabled": False,
                "acme_email": "", "panel_url": "", "setup_url": "",
                "parastoo_version": version()}
    env = _read_env(Path(p) / ".env")
    token = env.get("PARASTOO_SETUP_TOKEN", "")
    domain = env.get("BASE_DOMAIN", "")
    fresh = env.get("TRAEFIK_TLS", "").strip().lower()
    legacy = env.get("TLS_ENABLED", "").strip().lower()
    if fresh in ("true", "false"):
        tls = fresh == "true"
    else:
        tls = legacy == "true"
    acme = _acme_from_traefik(p) or env.get("ACME_EMAIL", "")
    scheme = "https" if tls else "http"
    panel = f"{scheme}://panel.{domain}" if domain else ""
    return {
        "ok": True,
        "installed": True,
        "has_token": bool(token),
        "setup_token": token,
        "base_domain": domain,
        "tls_enabled": tls,
        "acme_email": acme,
        "panel_url": panel,
        "setup_url": f"{panel}/setup" if panel else "",
        "parastoo_version": version(),
    }


def _log_dir() -> Path:
    d = home() / "parastoo-lifecycle"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sudo() -> str:
    override = os.environ.get("ACCESS_AGENT_PARASTOO_SUDO")
    if override is not None:
        return override
    return "" if os.geteuid() == 0 else "sudo "


# ---------- log ----------

def log_tail(n: int = LOG_TAIL_DEFAULT) -> list[str]:
    try:
        n = max(1, min(int(n), LOG_TAIL_MAX))
    except (TypeError, ValueError):
        n = LOG_TAIL_DEFAULT
    f = _state.get("log_file") or ""
    if not f:
        return []
    try:
        lines = Path(f).read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[-n:]
    except Exception:
        return []


# ---------- command builders ----------

def _install_script() -> str:
    override = os.environ.get("ACCESS_AGENT_PARASTOO_BOOTSTRAP_CMD")
    if override:
        return override
    s = _sudo()
    d = DEFAULT_BASE_DOMAIN
    return (
        # owner decree 2026-11-09: default install domain is ALWAYS
        # zeolitecenter.ir — install.sh reads this marker when no live .env
        # exists and provisions zone + HTTPS itself (§6d of its contract).
        f"echo {d} | {s}tee /etc/parastoo-domain >/dev/null"
        f" || (echo 'cannot write default domain marker'; exit 1)\n"
        "rm -f /tmp/parastoo-bootstrap.sh\n"
        f"curl -fsSL {BOOTSTRAP_URL} -o /tmp/parastoo-bootstrap.sh"
        f" || curl -fsSL {BOOTSTRAP_PROXY} -o /tmp/parastoo-bootstrap.sh\n"
        "test -s /tmp/parastoo-bootstrap.sh || { echo 'bootstrap.sh download failed'; exit 1; }\n"
        f"{s}bash /tmp/parastoo-bootstrap.sh\n"
    )


_UNINSTALL_TMPL = r"""# ---- Parastoo point-zero uninstall — owner decree 2026-11-09 ----
# NO trace and NO dust of the parastoo project may remain on this host.
# The bridge and its own assets (/etc/access-agent/**, audit, tokens) stay
# untouched — the phone keeps its channel. "Nothing to remove" is SUCCESS,
# never an error (LESSONS): every sweep is guarded and idempotent.
APP_DIR="$(cat __DIR_FILE__ 2>/dev/null || echo /opt/parastoo)"

# 0) inventory of parastoo-only docker artifacts, before anything is removed
PT_IMGS=""
if command -v docker >/dev/null 2>&1; then
  PT_IMGS="$(
    { docker ps -aq --filter name=parastoo- 2>/dev/null || true;
      docker ps -aq --filter label=parastoo.project 2>/dev/null || true; } \
      | xargs -r docker inspect --format '{{.Image}}' 2>/dev/null || true)"
  PT_IMGS="$PT_IMGS $(docker images -q --filter label=parastoo.slug 2>/dev/null || true)"
  PT_IMGS="$PT_IMGS $(docker images -q parastoo/core:latest 2>/dev/null || true)"
fi

# 1) official uninstall (user projects + volumes, stack down -v, CLI, units)
if [ -d "$APP_DIR" ]; then
  cd "$APP_DIR"
  printf 'y\ny\n' | __SUDO__bash uninstall.sh
else
  echo "parastoo dir already absent ($APP_DIR) — nothing to uninstall"
fi

# 2) residual docker sweeps (also cover an absent/pre-deleted install tree)
if command -v docker >/dev/null 2>&1; then
  { docker ps -aq --filter name=parastoo- 2>/dev/null || true;
    docker ps -aq --filter label=parastoo.project 2>/dev/null || true; } \
    | xargs -r docker rm -f 2>/dev/null || true
  docker network ls -q --filter name=parastoo 2>/dev/null | xargs -r docker network rm -f 2>/dev/null || true
  docker volume ls -q --filter name=parastoo 2>/dev/null | xargs -r docker volume rm -f 2>/dev/null || true
  printf '%s\n' $PT_IMGS | sort -u | grep -v '^$' | xargs -r docker rmi -f 2>/dev/null || true
  for repo in traefik gitea/gitea postgres powerdns/pdns-auth-49 alpine; do
    docker images -q "$repo" 2>/dev/null | xargs -r docker rmi 2>/dev/null || true
  done
  docker image prune -f >/dev/null 2>&1 || true
  docker builder prune -af >/dev/null 2>&1 || true
fi

# 3) /etc/docker/daemon.json — drop the installer-injected registry-mirrors;
#    restart docker only when the file actually changed
if command -v python3 >/dev/null 2>&1 && [ -f /etc/docker/daemon.json ]; then
  CHANGED="$(__SUDO__python3 - <<'PYEOF'
import json, os
P = "/etc/docker/daemon.json"
try:
    cfg = json.load(open(P, encoding="utf-8"))
except Exception:
    raise SystemExit(0)
if isinstance(cfg, dict) and "registry-mirrors" in cfg:
    cfg.pop("registry-mirrors", None)
    try:
        if cfg:
            json.dump(cfg, open(P, "w", encoding="utf-8"), indent=2)
        else:
            os.remove(P)
        print("daemon.json: parastoo registry-mirrors removed")
    except Exception:
        pass
raise SystemExit(0)
PYEOF
)" || true
  case "$CHANGED" in
    *removed*)
      __SUDO__systemctl restart docker >/dev/null 2>&1 \
        || __SUDO__service docker restart >/dev/null 2>&1 || true ;;
  esac
fi

# 4) host files — tree, persistent state (TLS store), domain identity, tmp leftovers
__SUDO__rm -rf "$APP_DIR" /var/lib/parastoo
__SUDO__rm -f /etc/parastoo-domain /etc/parastoo-install-path \
  /tmp/parastoo-bootstrap.sh /tmp/get-docker.sh /tmp/parastoo-autoupdate.lock

# 5) systemd leftovers (idempotent — uninstall.sh already did this when the tree existed)
__SUDO__rm -f /etc/systemd/system/parastoo-*.service /etc/systemd/system/parastoo-*.timer
__SUDO__systemctl daemon-reload >/dev/null 2>&1 || true

echo '== point zero reached: no parastoo trace left on this host =='
"""


def _uninstall_script() -> str:
    """نقطهٔ صفر — همهٔ بقایا، نه فقط uninstall.sh رسمی (فرمان مالک 2026-11-09)."""
    s = _sudo()
    df = str(_dir_file())
    return _UNINSTALL_TMPL.replace("__SUDO__", s).replace("__DIR_FILE__", df)


def _update_script() -> str:
    s = _sudo()
    return (
        f'APP_DIR="$(cat {str(_dir_file())} 2>/dev/null || echo /opt/parastoo)"\n'
        'test -d "$APP_DIR" || { echo "parastoo dir missing"; exit 1; }\n'
        f'cd "$APP_DIR" && {s}bash scripts/auto-update.sh --force\n'
    )


def _script_for(action: str) -> str:
    if action == "install":
        return _install_script()
    if action == "uninstall":
        return _uninstall_script()
    if action == "update":
        return _update_script()
    # reinstall = point-zero cleanup then fresh install (single log, single lock)
    return (
        "echo '== reinstall phase 1/2: full uninstall =='\n"
        + _uninstall_script()
        + "\necho '== reinstall phase 2/2: fresh install =='\n"
        + _install_script()
    )


# ---------- runner ----------

def _worker(action: str, script: str, log_file: Path) -> None:
    started = time.monotonic()
    exit_code = -1
    timed_out = False
    try:
        with log_file.open("w", encoding="utf-8") as lf:
            proc = subprocess.Popen(
                ["bash", "-c", script],
                stdout=lf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                exit_code = proc.wait(timeout=MAX_RUNTIME_S)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(proc.pid, 9)
                except Exception:
                    proc.kill()
                exit_code = proc.wait()
                with log_file.open("a", encoding="utf-8") as lf2:
                    lf2.write(f"\n[aborted: exceeded {MAX_RUNTIME_S}s]\n")
    except Exception as e:  # runner itself failed — surface honestly
        try:
            with log_file.open("a", encoding="utf-8") as lf3:
                lf3.write(f"\n[runner error: {type(e).__name__}]\n")
        except Exception:
            pass
    finally:
        dur = int(time.monotonic() - started)
        with _lock:
            _state.update(busy=False, action=action, exit_code=exit_code,
                          ok=(exit_code == 0 and not timed_out),
                          duration_s=dur, finished_at=now_iso())
        audit("admin", f"admin_parastoo_{action}_finish",
              {"exit_code": exit_code, "timed_out": timed_out, "duration_s": dur})


def start(action: str, confirm: str = "") -> dict:
    """Validate and launch a lifecycle operation. Returns an HTTP-mappable dict."""
    if action not in ACTIONS:
        return {"ok": False, "error": "unknown_action", "detail": f"use one of {ACTIONS}",
                "status": 404}
    if action in CONFIRM_REQUIRED and confirm != action:
        return {"ok": False, "error": "confirm_required",
                "detail": f'body must contain {{"confirm": "{action}"}}', "status": 400}
    with _lock:
        if _state.get("busy"):
            return {"ok": False, "error": "busy",
                    "detail": f'operation "{_state.get("action")}" is still running',
                    "status": 409}
        mut = execbridge.mutation_running()  # v0.5.1: opposite side of the guard
        if mut:
            return {"ok": False, "error": "exec_busy",
                    "detail": f"an exec matching '{mut}' is still running — "
                              f"refusing to start a lifecycle op in parallel",
                    "status": 409}
        ins = installed()
        if action in ("uninstall", "update") and not ins:
            return {"ok": False, "error": "nothing_installed",
                    "detail": "parastoo is not installed on this host", "status": 409}
        if action == "install" and ins:
            return {"ok": False, "error": "already_installed",
                    "detail": "parastoo is already installed — use reinstall for a fresh start",
                    "status": 409}
        ts = time.strftime("%Y%m%d-%H%M%S")
        log_file = _log_dir() / f"{action}-{ts}.log"
        script = _script_for(action)
        _state.update(busy=True, action=action, started_at=now_iso(),
                      finished_at="", exit_code=None, ok=None,
                      duration_s=None, log_file=str(log_file))
    threading.Thread(target=_worker, args=(action, script, log_file),
                     daemon=True, name=f"parastoo-{action}").start()
    audit("admin", f"admin_parastoo_{action}_start", {})
    return {"ok": True, "accepted": True, "action": action,
            "log_file": str(log_file), "detail": "poll /api/admin/parastoo/lifecycle-status"}


def status_snapshot() -> dict:
    with _lock:
        snap = dict(_state)
    return {
        "ok": True,
        "installed": installed(),
        "install_path": install_path(),
        "version": version(),
        "busy": snap.get("busy", False),
        "action": snap.get("action", ""),
        "started_at": snap.get("started_at", ""),
        "finished_at": snap.get("finished_at", ""),
        "exit_code": snap.get("exit_code"),
        "ok_last": snap.get("ok"),
        "duration_s": snap.get("duration_s"),
        "log_file": snap.get("log_file", ""),
        "log_tail": log_tail(LOG_TAIL_DEFAULT),
    }
