"""Parastoo lifecycle control from the owner's phone — access_agent.parastoolifecycle.

Owner directive (2026-11-08): the admin must get everything through Parastoo
Mobile, never logging into the server — install, full uninstall with all
belongings, reinstall, and forced update.

Rules (non-negotiable):
- Admin realm only (guard lives in server.py); every transition audited;
  no secret ever reaches the log or audit (installer prints none by contract).
- Max ONE lifecycle operation at a time; a second call gets 409 busy.
- Operations run in a background thread; output appends to a log file under
  ACCESS_AGENT_HOME/parastoo-lifecycle/ (root-only directory, chmod 600).
- "Full uninstall" = uninstall.sh answered y/y (drop projects/volumes) PLUS
  removal of the install folder and /var/lib/parastoo — explicitly ordered by
  the owner («حذف و پاکسازی کامل پرستو با تمام متعلقات»). The stock installer
  would keep the TLS store; the owner's explicit full-cleanup order overrides
  that, and the app dialog repeats the consequence before firing.
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

_state = {
    "busy": False, "action": "", "started_at": "", "finished_at": "",
    "exit_code": None, "ok": None, "duration_s": None, "log_file": "",
}
_lock = threading.Lock()


# ---------- environment / paths ----------

def _dir_file() -> Path:
    return Path(os.environ.get(
        "ACCESS_AGENT_PARASTOO_DIR_FILE", "/etc/parastoo-install-path"))


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
    return (
        "rm -f /tmp/parastoo-bootstrap.sh\n"
        f"curl -fsSL {BOOTSTRAP_URL} -o /tmp/parastoo-bootstrap.sh"
        f" || curl -fsSL {BOOTSTRAP_PROXY} -o /tmp/parastoo-bootstrap.sh\n"
        "test -s /tmp/parastoo-bootstrap.sh || { echo 'bootstrap.sh download failed'; exit 1; }\n"
        f"{s}bash /tmp/parastoo-bootstrap.sh\n"
    )


def _uninstall_script() -> str:
    s = _sudo()
    df = str(_dir_file())
    return (
        f'APP_DIR="$(cat {df} 2>/dev/null || echo /opt/parastoo)"\n'
        # LESSONS rule: "nothing to remove" is SUCCESS, not an error — a missing
        # dir must never abort the cleanup before it finishes (field 2026-11-08).
        f'if [ -d "$APP_DIR" ]; then\n'
        f'  cd "$APP_DIR"\n'
        f'  printf \'y\\ny\\n\' | {s}bash uninstall.sh\n'
        "else\n"
        '  echo "parastoo dir already absent ($APP_DIR) — nothing to uninstall"\n'
        "fi\n"
        # owner-ordered full cleanup: install folder + persistent TLS store
        f"{s}rm -rf \"$APP_DIR\" /var/lib/parastoo /tmp/parastoo-bootstrap.sh\n"
        "echo '== full cleanup done =='\n"
    )


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
    # reinstall = full cleanup then fresh install (single log, single lock)
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
