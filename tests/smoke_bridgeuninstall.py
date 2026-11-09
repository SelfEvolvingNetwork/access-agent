#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی حذف خود پل (v0.5.7) — کاملاً آفلاین.

اجرا:  python tests/smoke_bridgeuninstall.py
قلاب تست: ACCESS_AGENT_BRIDGE_UNINSTALL_CMD کل فرمانِ زمان‌بندی‌شده را جایگزین
می‌کند (بدون systemd) — همین یک فرمانِ قلابی یک فایل نشانگر می‌سازد تا ثابت
شود فرمانِ پاک‌سازی واقعاً اجرا شده است. قرارداد busy با یک bootstrap قلابیِ
منتظرِ فایل GO آزموده می‌شود (همان الگوی smoke_lifecycle).
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GREEN, RED, YELLOW, NC = "\033", "\033", "\033", "\033"
n_pass = n_fail = 0
failures: list[str] = []


def ch(name: str, cond: bool, extra: str = "") -> None:
    global n_pass, n_fail
    if cond:
        n_pass += 1
        print(f"{GREEN}[✓]{NC} {name}")
    else:
        n_fail += 1
        failures.append(name)
        print(f"{RED}[✗]{NC} {name} {YELLOW}{extra}{NC}")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def req(method: str, path: str, token: str = "", body: dict | None = None,
        timeout: float = 15) -> tuple[int, dict | bytes]:
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


# ---------- fixture ----------
TMP = tempfile.mkdtemp(prefix="access-agent-bridgeuninstall.")
FAKE = Path(TMP) / "fake-parastoo"
TPL = Path(TMP) / "tpl-parastoo"
GO = Path(TMP) / "go"
DIRF = Path(TMP) / "pdir-file"
MARKER = Path(TMP) / "purge-marker"

(TPL / "core" / "app").mkdir(parents=True)
(TPL / "install.sh").write_text("#!/usr/bin/env bash\necho installed\n", encoding="utf-8")
(TPL / "core" / "app" / "config.py").write_text('VERSION: str = "0.9.9-test"\n', encoding="utf-8")

BOOTSTRAP = (
    f'while [ ! -f {GO} ]; do sleep 0.1; done; '
    f'cp -r {TPL}/. {FAKE}/ && echo {FAKE} > {DIRF} && printf "bootstrap-ok\\n"'
)
# فرمان قلابیِ «پاک‌سازی» — فقط نشانگر می‌سازد؛ همان قرارداد پاسخ 202
PURGE_CMD = f"touch {MARKER} && printf purged"

# ---------- start server ----------
PORT = free_port()
ADMIN = "adm_" + os.urandom(24).hex()
AGENT = "aa_" + os.urandom(24).hex()

(Path(TMP) / "tokens.json").write_text(json.dumps({
    "admin_sha": hashlib.sha256(ADMIN.encode()).hexdigest(),
    "agent_sha": hashlib.sha256(AGENT.encode()).hexdigest(),
}), encoding="utf-8")

env = dict(os.environ)
env.update({
    "PYTHONUNBUFFERED": "1",
    "ACCESS_AGENT_HOME": TMP,
    "ACCESS_AGENT_PORT": str(PORT),
    "ACCESS_AGENT_NO_TLS": "1",
    "ACCESS_AGENT_PARASTOO_DIR_FILE": str(DIRF),
    "ACCESS_AGENT_PARASTOO_BOOTSTRAP_CMD": BOOTSTRAP,
    "ACCESS_AGENT_PARASTOO_SUDO": "",
    "ACCESS_AGENT_BRIDGE_UNINSTALL_CMD": PURGE_CMD,
    "ACCESS_AGENT_BRIDGE_SUDO": "",
})
server_log = open(Path(TMP) / "server.log", "w", encoding="utf-8")
proc = subprocess.Popen(
    [sys.executable, "-m", "access_agent.server"],
    cwd=str(REPO), env=env, stdout=server_log, stderr=server_log,
    stdin=subprocess.DEVNULL,
)
atexit.register(lambda: server_log.close())

up = False
for _ in range(50):
    try:
        code, _body = req("GET", "/healthz", timeout=2)
        if code == 200:
            up = True
            break
    except Exception:
        pass
    time.sleep(0.2)
ch("healthz: سرور بالا آمد", up)


def wait_done(timeout: float = 20) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        code, b = req("GET", "/api/admin/parastoo/lifecycle-status", ADMIN)
        if code == 200 and isinstance(b, dict) and not b.get("busy"):
            return b
        time.sleep(0.2)
    raise AssertionError("lifecycle operation did not finish in time")


def teardown() -> None:
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def main() -> int:
    try:
        run_all()
    finally:
        teardown()
    print(f"\n# جمع‌بندی: {GREEN}{n_pass} سبز{NC}، {RED}{n_fail} قرمز{NC}")
    if failures:
        print("# شکست‌ها:")
        for f in failures:
            print(f"  - {f}")
    return 1 if n_fail else 0


def run_all() -> None:
    # ---------- گارد‌ها ----------
    code, b = req("GET", "/api/admin/bridge/uninstall", ADMIN)
    ch("GET روی مسیر POST = 405", code == 405)
    code, b = req("POST", "/api/admin/bridge/uninstall")
    ch("بدون توکن = 401", code == 401)
    code, b = req("POST", "/api/admin/bridge/uninstall", AGENT, {"confirm": "uninstall"})
    ch("توکن عامل = 403 — عامل هرگز حق حذف پل ندارد", code == 403)
    code, b = req("POST", "/api/admin/bridge/uninstall", ADMIN, {"confirm": "wrong"})
    ch("تأیید نادرست = 400 confirm_required", code == 400 and b.get("error") == "confirm_required")

    # ---------- هم‌زمانی با lifecycle ----------
    if GO.exists():
        GO.unlink()
    code, b = req("POST", "/api/admin/parastoo/install", ADMIN, {})
    ch("نصب قلابی برای تست busy شروع شد", code == 202 and b.get("ok") is True)
    code, b = req("POST", "/api/admin/bridge/uninstall", ADMIN, {"confirm": "uninstall"})
    ch("در جریانِ lifecycle = 409 lifecycle_busy",
       code == 409 and b.get("error") == "lifecycle_busy")
    GO.touch()
    st = wait_done()
    ch("lifecycle قلابی تمام شد", st.get("exit_code") == 0)
    time.sleep(0.3)

    # ---------- فرمان درست ----------
    if MARKER.exists():
        MARKER.unlink()
    code, b = req("POST", "/api/admin/bridge/uninstall", ADMIN, {"confirm": "uninstall"})
    ch("فرمان درست = 202 + accepted + واحد گذرا",
       code == 202 and b.get("ok") is True and b.get("accepted") is True
       and b.get("unit") == "access-agent-self-purge" and b.get("grace_s", 0) >= 1)
    deadline = time.time() + 5
    while time.time() < deadline and not MARKER.exists():
        time.sleep(0.1)
    ch("فرمانِ پاک‌سازی واقعاً اجرا شده (نشانگرِ قلابی ساخته شد)", MARKER.exists())

    # ---------- audit ----------
    code, b = req("GET", "/api/admin/audit?tail=200", ADMIN)
    actions = [json.loads(l).get("action", "") for l in b.get("lines", []) if l.strip()]
    ch("audit: رویداد شروع حذف پل ثبت شده", "admin_bridge_uninstall_start" in actions)
    ch("audit: ردِ توکن عامل ثبت شده (forbidden)",
       any("forbidden" in a or "auth_fail" in a for a in actions))


teardown_guard = None
if not up:
    print(f"{RED}ERROR:{NC} server did not start on port {PORT} — log tail:")
    try:
        server_log.flush()
        print((Path(TMP) / "server.log").read_text()[-2000:])
    except Exception:
        pass
    teardown()
    raise SystemExit(1)


if __name__ == "__main__":
    raise SystemExit(main())
