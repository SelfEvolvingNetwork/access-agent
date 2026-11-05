#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی access-agent — سرور واقعی روی پورت آزاد (بدون TLS در محیط تست).

اجرا:  python tests/smoke_test.py
غیرفعال‌سازی شبکه‌محور: کاملاً آفلاین (اعتبارسنجی گیت‌هاب best-effort است).
"""
from __future__ import annotations

import atexit
import hashlib  # noqa: E402
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GREEN, RED, YELLOW, NC = "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0m"
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


# ---------- start server ----------
PORT = free_port()
TMP = tempfile.mkdtemp(prefix="access-agent-smoke.")
os.environ["ACCESS_AGENT_HOME"] = TMP
os.environ["ACCESS_AGENT_PORT"] = str(PORT)
os.environ["ACCESS_AGENT_NO_TLS"] = "1"

ADMIN = "adm_" + os.urandom(24).hex()
AGENT = "aa_" + os.urandom(24).hex()

(Path(TMP) / "tokens.json").write_text(json.dumps({
    "admin_sha": hashlib.sha256(ADMIN.encode()).hexdigest(),
    "agent_sha": hashlib.sha256(AGENT.encode()).hexdigest(),
}), encoding="utf-8")

env = dict(os.environ)
env["PYTHONUNBUFFERED"] = "1"
server_log = open(Path(TMP) / "server.log", "w", encoding="utf-8")
proc = subprocess.Popen(
    [sys.executable, "-m", "access_agent.server"],
    cwd=str(REPO), env=env,
    stdout=server_log, stderr=server_log,
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
    # ---------- public ----------
    code, b = req("GET", "/healthz")
    ch("healthz 200 بدون توکن", code == 200 and b.get("service") == "access-agent")
    ch("healthz نسخه دارد", isinstance(b.get("version"), str) and b["version"])
    code, b = req("GET", "/")
    ch("/ اطلاعات سرویس", code == 200 and b.get("service") == "access-agent")

    # ---------- auth ----------
    code, b = req("GET", "/api/status")
    ch("status بدون توکن → 401", code == 401 and b.get("error") == "unauthorized")
    code, b = req("GET", "/api/status", token="wrong-token")
    ch("توکن غلط → 401", code == 401)
    code, b = req("GET", "/api/admin/audit", token=AGENT)
    ch("توکن عامل روی مسیر ادمین → 403", code == 403)
    code, b = req("GET", "/api/status", token=ADMIN)
    ch("توکن ادمین superset است", code == 200 and b.get("ok"))
    ch("status فیلدهای کلیدی", all(k in b for k in
        ("version", "uptime_s", "hostname", "kernel", "disk_percent", "docker_path")))
    ch("status parastoo_install_path کلید دارد", "parastoo_install_path" in b)

    # ---------- exec ----------
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "echo hello-agent"})
    ch("exec ساده", code == 200 and b.get("exit_code") == 0
       and b.get("stdout", "").strip() == "hello-agent")
    ch("exec duration_ms دارد", isinstance(b.get("duration_ms"), int) and b["duration_ms"] >= 0)
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "exit 7"})
    ch("exec کدخروج ۷ حفظ می‌شود", code == 200 and b.get("exit_code") == 7)
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "echo err-line >&2"})
    ch("exec stderr جدا", code == 200 and "err-line" in b.get("stderr", "")
       and b.get("stdout", "").strip() == "")
    code, b = req("POST", "/api/exec", token=AGENT,
                  body={"cmd": "sleep 3 && echo after", "timeout_s": 1})
    ch("exec تایم‌اوت: کشتن واقعی", code == 200 and b.get("timed_out") is True
       and b.get("duration_ms", 99999) < 2500)
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "python3 -c 'print(\"x\"*250000)'"})
    ch("exec سقف خروجی ۲۰۰هزار", code == 200
       and len(b.get("stdout", "")) <= 200_000 + 100 and "truncated" in b.get("stdout", ""))
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "x" * 8001})
    ch("exec cmd بلند → cmd_too_long", code == 400 and b.get("error") == "cmd_too_long")
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "true", "timeout_s": 601})
    ch("exec تایم‌اوت ۶۰۱ → رد", code == 400 and b.get("error") == "timeout_out_of_range")
    code, b = req("POST", "/api/exec", token=AGENT,
                  body={"cmd": "true", "cwd": "/nonexistent-dir-xyz"})
    ch("exec cwd ناموجود → رد", code == 400 and b.get("error") == "cwd_not_found")
    code, b = req("POST", "/api/exec", token=AGENT,
                  body={"cmd": "read -t 1 x; echo stdin:${x:-none}"})
    ch("exec stdin همیشه /dev/null (درس پرستو)", code == 200 and "stdin:none" in b.get("stdout", ""))
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "true"})
    ch("exec بدون اثر stdin (exit 0)", code == 200 and b.get("exit_code") == 0)
    code, b = req("POST", "/api/exec", token=AGENT,
                  body={"cmd": "true", "timeout_s": "abc"})
    ch("exec تایم‌اوت غیرعددی → رد", code == 400 and b.get("error") == "bad_timeout")
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "   "})
    ch("exec خالی → رد", code == 400 and b.get("error") == "cmd_required")
    tmpdir = tempfile.mkdtemp(prefix="cwdtest.")
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "pwd", "cwd": tmpdir})
    ch("exec با cwd درست", code == 200 and b.get("stdout", "").strip() == tmpdir)

    # ---------- concurrency (429) ----------
    results = []
    def slow_exec():
        results.append(req("POST", "/api/exec", token=AGENT,
                           body={"cmd": "sleep 1.5", "timeout_s": 10}))
    t1 = threading.Thread(target=slow_exec); t2 = threading.Thread(target=slow_exec)
    t1.start(); t2.start()
    time.sleep(0.5)
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "echo busy-test"})
    ch("سقف هم‌زمانی ۲ → ۴۲۹ busy", code == 429 and b.get("error") == "busy")
    t1.join(); t2.join()
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "echo after-busy"})
    ch("بعد از آزادشدن، exec برمی‌گردد", code == 200 and b.get("exit_code") == 0)

    # ---------- http edge cases ----------
    code, b = req("GET", "/api/exec", token=AGENT)
    ch("GET روی مسیر POST → 405", code == 405)
    code, b = req("GET", "/api/unknown", token=AGENT)
    ch("مسیر ناشناخته → 404", code == 404 and b.get("error") == "not_found")
    url = f"http://127.0.0.1:{PORT}/api/exec"
    r = urllib.request.Request(url, data=b"{invalid-json", method="POST")
    r.add_header("Authorization", f"Bearer {AGENT}")
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            code = resp.status
    except urllib.error.HTTPError as e:
        code = e.code
    ch("بدنهٔ JSON خراب → 400", code == 400)
    big = json.dumps({"cmd": "true", "pad": "y" * 300_000}).encode()
    r = urllib.request.Request(url, data=big, method="POST")
    r.add_header("Authorization", f"Bearer {AGENT}")
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            code = resp.status
    except urllib.error.HTTPError as e:
        code = e.code
    ch("بدنهٔ >۱۰۰KB → 413", code == 413)

    # ---------- github broker ----------
    code, b = req("POST", "/api/github/token", token=AGENT,
                  body={"purpose": "push access-agent v0.1 to github"})
    ch("افشا بدون توکن ذخیره‌شده → 409", code == 409 and b.get("error") == "no_stored_token")
    code, b = req("POST", "/api/admin/set-github-token", token=ADMIN, body={"token": ""})
    ch("set-github-token خالی → 400", code == 400 and b.get("error") == "token_required")
    code, b = req("POST", "/api/admin/set-github-token", token=ADMIN,
                  body={"token": "ghp_smokeTestFakeToken000000000000000000"})
    ch("set-github-token ذخیره می‌کند", code == 200 and b.get("stored") is True
       and "validation" in b)
    code, b = req("POST", "/api/github/token", token=AGENT, body={"purpose": "short"})
    ch("افشا با هدف کوتاه → 400", code == 400 and b.get("error") == "purpose_required")
    code, b = req("POST", "/api/github/token", token=AGENT,
                  body={"purpose": "push parastoo docs update", "ttl_min": 30})
    ch("افشا با هدف معتبر → توکن برمی‌گردد", code == 200 and b.get("ok") is True
       and b.get("token", "").startswith("ghp_"))
    ch("رکورد grant با ttl و purpose", b.get("grant", {}).get("ttl_min") == 30
       and "push parastoo docs update" in b.get("grant", {}).get("purpose", ""))
    code, b = req("GET", "/api/admin/sessions?tail=10", token=ADMIN)
    ch("sessions ادمین grants را می‌بیند", code == 200 and len(b.get("grants", [])) >= 1)
    code, b = req("POST", "/api/github/token", token=ADMIN,
                  body={"purpose": "admin can also disclose"})
    ch("ادمین هم می‌تواند افشا کند", code == 200 and b.get("ok") is True)

    # ---------- audit ----------
    code, b = req("GET", "/api/admin/audit?tail=50", token=ADMIN)
    actions = [json.loads(l).get("action", "") for l in b.get("lines", [])]
    ch("audit رکورد exec دارد", "exec" in actions)
    ch("audit رکورد auth_fail دارد", "auth_fail" in actions)
    ch("audit رکورد disclose دارد", "github_token_disclosed" in actions)
    code, b = req("GET", "/api/admin/audit?tail=5", token=ADMIN)
    ch("audit tail محدود به ۵", len(b.get("lines", [])) <= 5)

    # ---------- token rotation / revoke ----------
    code, b = req("POST", "/api/admin/rotate-agent-token", token=ADMIN)
    new_token = b.get("agent_token", "")
    ch("rotate توکن جدید می‌دهد", code == 200 and new_token.startswith("aa_")
       and new_token != AGENT)
    code, b = req("GET", "/api/status", token=AGENT)
    ch("توکن کهنه بعد از rotate → 401", code == 401)
    code, b = req("GET", "/api/status", token=new_token)
    ch("توکن تازه کار می‌کند", code == 200)
    code, b = req("POST", "/api/admin/revoke-agent-token", token=ADMIN)
    ch("revoke عامل را قطع می‌کند", code == 200)
    code, b = req("GET", "/api/status", token=new_token)
    ch("بعد از revoke توکن عامل → 401", code == 401)
    code, b = req("GET", "/api/status", token=ADMIN)
    ch("ادمین بعد از revoke سالم", code == 200)
    code, b = req("POST", "/api/admin/rotate-agent-token", token=ADMIN)
    ch("rotate دوباره عامل را برمی‌گرداند", code == 200
       and (b.get("agent_token") or "").startswith("aa_"))

    # ---------- persistence ----------
    tok_file = Path(TMP) / "tokens.json"
    ch("tokens.json روی دیسک (600)", tok_file.exists()
       and oct(tok_file.stat().st_mode & 0o777) == "0o600")
    gh_file = Path(TMP) / "github.env"
    ch("github.env ذخیره شده (600)", gh_file.exists()
       and oct(gh_file.stat().st_mode & 0o777) == "0o600")
    sess = Path(TMP) / "sessions.jsonl"
    ch("sessions.jsonl ثبت شده", sess.exists() and len(sess.read_text().splitlines()) >= 2)

    # ---------- handoff block (v0.1.3) ----------
    sys.path.insert(0, str(REPO))
    from access_agent import handoff
    (Path(TMP) / "config.json").write_text(json.dumps(
        {"ip": "203.0.113.9", "port": PORT, "version": "0.1.3"}), encoding="utf-8")
    (Path(TMP) / "secrets").mkdir(exist_ok=True)
    (Path(TMP) / "secrets" / "agent-token").write_text(AGENT + "\n", encoding="utf-8")
    tls = Path(TMP) / "tls"
    tls.mkdir(exist_ok=True)
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "3", "-subj", "/CN=smoke",
                        "-keyout", str(tls / "key.pem"), "-out", str(tls / "cert.pem")],
                       capture_output=True)
    ch("گواهی آزمون handoff ساخته شد", r.returncode == 0 and (tls / "cert.pem").exists())
    block = handoff.build_block()
    ch("بلوک handoff با دو خط جداکننده", "HANDOFF BLOCK" in block and "END HANDOFF BLOCK" in block)
    ch("ACCESS_URL از config می‌آید", f"ACCESS_URL:  https://203.0.113.9:{PORT}" in block)
    ch("توکن عامل در بلوک، توکن ادمین نیست", AGENT in block and ADMIN not in block)
    fp = handoff.cert_fingerprint()
    ch("اثرانگشت ۶۴hex در بلوک", len(fp) == 64 and fp.lower() in block.lower())
    ch("هر دو URL مرجع در بلوک", handoff.PROTOCOL_URL in block
       and handoff.PARASTOO_LOOP_URL in block)
    cfg_path = Path(TMP) / "config.json"
    cfg_backup = cfg_path.read_text(encoding="utf-8")
    cfg_path.unlink()
    try:
        handoff.build_block()
        raised = False
    except RuntimeError:
        raised = True
    ch("دادهٔ ناقص → RuntimeError", raised)
    cfg_path.write_text(cfg_backup, encoding="utf-8")


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
