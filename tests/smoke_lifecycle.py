#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی چرخهٔ عمر پرستو (v0.5) — کاملاً آفلاین با اسکریپت‌های قلابی.

اجرا:  python tests/smoke_lifecycle.py
قلاب‌های تست: ACCESS_AGENT_PARASTOO_DIR_FILE / _BOOTSTRAP_CMD / _SUDO —
نصبِ قلابی فقط یک پوشهٔ قلابی را از قالب کپی می‌کند و مسیر را در فایل مسیر می‌نویسد؛
همان قرارداد bootstrap واقعی (درخت + /etc/parastoo-install-path) بدون شبکه.
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


# ---------- fixture: fake parastoo tree ----------
TMP = tempfile.mkdtemp(prefix="access-agent-lifecycle.")
FAKE = Path(TMP) / "fake-parastoo"
TPL = Path(TMP) / "tpl-parastoo"
GO = Path(TMP) / "go"
DIRF = Path(TMP) / "pdir-file"

(TPL / "core" / "app").mkdir(parents=True)
(TPL / "scripts").mkdir(parents=True)
(TPL / "install.sh").write_text("#!/usr/bin/env bash\necho installed\n", encoding="utf-8")
(TPL / "uninstall.sh").write_text(
    "#!/usr/bin/env bash\necho \"answers: $(cat)\"\necho removed\n", encoding="utf-8")
(TPL / "scripts" / "auto-update.sh").write_text(
    "#!/usr/bin/env bash\necho updated\n", encoding="utf-8")
(TPL / "core" / "app" / "config.py").write_text(
    'VERSION: str = "0.9.9-test"\n', encoding="utf-8")

BOOTSTRAP = (
    f'while [ ! -f {GO} ]; do sleep 0.1; done; '
    f'cp -r {TPL}/. {FAKE}/ && echo {FAKE} > {DIRF} && printf "bootstrap-ok\\n"'
)

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
        code, body = req("GET", "/healthz", timeout=2)
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
    # ---------- auth & fresh state ----------
    code, b = req("GET", "/api/admin/parastoo/lifecycle-status")
    ch("lifecycle-status بدون توکن = 401", code == 401)
    code, b = req("GET", "/api/admin/parastoo/lifecycle-status", AGENT)
    ch("lifecycle-status با توکن عامل = 403 (فقط ادمین)", code == 403)
    code, b = req("GET", "/api/admin/parastoo/lifecycle-status", ADMIN)
    ch("lifecycle-status ادمین: نصب‌نشده", code == 200 and b.get("installed") is False
       and b.get("busy") is False)
    code, b = req("POST", "/api/admin/parastoo/uninstall", ADMIN, {"confirm": "uninstall"})
    ch("حذف روی نصب‌نشده = 409 nothing_installed", code == 409 and b.get("error") == "nothing_installed")
    code, b = req("POST", "/api/admin/parastoo/update", ADMIN, {})
    ch("به‌روزرسانی روی نصب‌نشده = 409", code == 409 and b.get("error") == "nothing_installed")
    code, b = req("POST", "/api/admin/parastoo/nope", ADMIN, {})
    ch("عملیات ناشناخته = 404", code == 404 and b.get("error") == "unknown_action")

    # ---------- install (gated on GO for the busy window) ----------
    code, b = req("POST", "/api/admin/parastoo/install", ADMIN, {})
    ch("نصب پذیرفته شد = 202", code == 202 and b.get("accepted") is True)
    code, b = req("POST", "/api/admin/parastoo/update", ADMIN, {})
    ch("دومین عملیات حین اجرا = 409 busy", code == 409 and b.get("error") == "busy")
    code, b = req("GET", "/api/admin/parastoo/lifecycle-status", ADMIN)
    ch("حین اجرا: busy=true با نام عملیات", b.get("busy") is True and b.get("action") == "install")
    # ---------- v0.5.1: mutual exec↔lifecycle guard («one transparent pipeline») ----------
    code, b = req("POST", "/api/exec", AGENT,
                  {"cmd": "bash /tmp/parastoo-bootstrap.sh", "timeout_s": 5})
    ch("exec هم‌خوان با نصب حین lifecycle = 409 lifecycle_busy",
       code == 409 and b.get("error") == "lifecycle_busy")
    code, b = req("POST", "/api/exec", AGENT,
                  {"cmd": "docker ps --format '{{.Names}}'", "timeout_s": 10})
    ch("exec خواندنی (docker ps) حین lifecycle رد نمی‌شود (409 نه — اجرا می‌شود)",
       code == 200 and b.get("error") is None)
    code, b = req("POST", "/api/exec", AGENT,
                  {"cmd": "echo supervision-continues-during-install", "timeout_s": 10})
    ch("exec عادی حین lifecycle سالم", code == 200 and b.get("exit_code") == 0)
    GO.write_text("go\n")
    b = wait_done()
    ch("نصب تمام شد: exit 0", b.get("exit_code") == 0 and b.get("ok_last") is True)
    ch("نصب تمام شد: نصب‌شده شناسایی شد", b.get("installed") is True
       and b.get("version") == "0.9.9-test")
    ch("لاگ نصب: خروجی bootstrap قلابی هست", "bootstrap-ok" in "\n".join(b.get("log_tail", [])))
    code, b = req("POST", "/api/admin/parastoo/install", ADMIN, {})
    ch("نصب دوم روی نصب‌شده = 409 already_installed", code == 409 and b.get("error") == "already_installed")

    # ---------- lifecycle start حین execِ متضاد = 409 exec_busy ----------
    import threading as _th
    slow_res: list = []

    def _slow_exec() -> None:
        slow_res.append(req("POST", "/api/exec", AGENT,
                            {"cmd": "sleep 2; echo bootstrap.sh", "timeout_s": 10}))
    t = _th.Thread(target=_slow_exec)
    t.start()
    time.sleep(0.5)
    code, b = req("POST", "/api/admin/parastoo/update", ADMIN, {})
    ch("شروع lifecycle حین execِ متضاد = 409 exec_busy",
       code == 409 and b.get("error") == "exec_busy")
    t.join()
    code, b = req("POST", "/api/admin/parastoo/update", ADMIN, {})
    ch("بعد از آزادشدن exec، lifecycle دوباره پذیرفته می‌شود", code == 202)
    b = wait_done()
    ch("آپدیت پس از گارد: exit 0", b.get("exit_code") == 0)

    # ---------- update ----------
    code, b = req("POST", "/api/admin/parastoo/update", ADMIN, {})
    ch("به‌روزرسانی پذیرفته شد", code == 202)
    b = wait_done()
    ch("به‌روزرسانی: exit 0", b.get("exit_code") == 0)
    ch("لاگ به‌روزرسانی: auto-update قلابی اجرا شد", "updated" in "\n".join(b.get("log_tail", [])))

    # ---------- uninstall ----------
    code, b = req("POST", "/api/admin/parastoo/uninstall", ADMIN, {})
    ch("حذف بدون confirm = 400", code == 400 and b.get("error") == "confirm_required")
    code, b = req("POST", "/api/admin/parastoo/uninstall", ADMIN, {"confirm": "uninstall"})
    ch("حذف با confirm پذیرفته شد", code == 202)
    b = wait_done()
    ch("حذف: exit 0", b.get("exit_code") == 0)
    joined = "\n".join(b.get("log_tail", []))
    ch("حذف کامل: uninstall.sh با پاس y/y اجرا شد", "answers: y" in joined and "removed" in joined)
    ch("حذف کامل: پوشهٔ نصب پاک شد (installed=false)", b.get("installed") is False)

    # ---------- reinstall (uninstall + install in one lock) ----------
    code, b = req("POST", "/api/admin/parastoo/reinstall", ADMIN, {"confirm": "reinstall"})
    ch("نصب مجدد پذیرفته شد (روی نصب‌نشده هم مجاز)", code == 202)
    b = wait_done()
    joined = "\n".join(b.get("log_tail", []))
    ch("نصب مجدد: exit 0", b.get("exit_code") == 0)
    ch("نصب مجدد: هر دو فاز در یک لاگ", "phase 1/2" in joined and "phase 2/2" in joined)
    ch("نصب مجدد: در پایان نصب است", b.get("installed") is True)

    # ---------- audit trail ----------
    code, b = req("GET", "/api/admin/audit?tail=200", ADMIN)
    actions = [json.loads(l).get("action", "") for l in b.get("lines", []) if l.strip()]
    ch("audit: رویدادهای شروع/پایان ثبت شده‌اند",
       "admin_parastoo_install_start" in actions and "admin_parastoo_uninstall_finish" in actions)


def teardown() -> None:
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


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
