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
import re
import shutil
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

    # ---------- installer contract (file-level tripwires) ----------
    # قراردادهای نصب‌کننده که اپ موبایل به آن‌ها تکیه دارد — اگر کسی کد را دور
    # بزند/حذف کند، اسموک همین‌جا قرمز می‌شود (الگوی «چک قرارداد» پرستو).
    inst = (REPO / "install.sh").read_text(encoding="utf-8")
    ch("install.sh: write_tokens واحد برای مسیر تازه و ریست", "write_tokens() {" in inst)
    ch("install.sh: قرارداد RESET_TOKENS (انتقال مالکیت اپ)",
       "ACCESS_AGENT_RESET_TOKENS" in inst and "Tokens REPLACED" in inst)
    ch("install.sh: ریست بدون توکن env رد می‌شود (قفل‌شدن مالک ممنوع)",
       "keeping existing tokens" in inst)
    ch("install.sh: مسیر ارتقا گزارش TOKENS REPLACED دارد",
       "TOKENS REPLACED (ownership transfer)" in inst)

    # ---------- v0.6.4: detect_ip — رگرسیون باگ IP داکری (172.22.0.1) ----------
    # هات‌فیکس v0.1.2 (c4ade68) «اولین IP خروجی hostname -I» را اصلی کرد؛ روی
    # هاست‌های داکری، آیتم اول گیت‌وی بریج (172.22.0.1) است و ACCESS_URL
    # غیرقابل‌دسترس در config.json/کارت گزارش/handoff ثبت می‌شد. قرارداد تازه:
    # پروب مسیر پیش‌فرض اول است و hostname -I فقط بعد از آن.
    ch("install.sh: پروب مسیر پیش‌فرض قبل از hostname -I است",
       0 <= inst.find("hostns ip -4 route get 1.1.1.1")
       < inst.find("hostns hostname -I"))
    ipm = re.search(r"^is_private_ip\(\) \{.*?^\}", inst, re.S | re.M)
    ch("install.sh: تابع is_private_ip موجود است", ipm is not None)
    if ipm:
        ipfn = Path(TMP) / "is_private_ip.sh"
        ipfn.write_text(ipm.group(0) + "\n", encoding="utf-8")

        def _priv(ip_: str) -> bool:
            r = subprocess.run(["bash", "-c", f"source '{ipfn}'; is_private_ip '{ip_}'"],
                               capture_output=True)
            return r.returncode == 0

        ch("is_private_ip: گیت‌وی بریج داکر 172.22.0.1 → خصوصی",
           _priv("172.22.0.1") and not _priv("172.15.255.255") and not _priv("172.32.0.1"))
        ch("is_private_ip: 10/8 و 192.168/16 و 127/8 → خصوصی",
           _priv("10.0.0.5") and _priv("192.168.1.1") and _priv("127.0.0.1"))
        ch("is_private_ip: CGNAT 100.64–100.127 → خصوصی",
           _priv("100.64.0.1") and _priv("100.127.255.3") and not _priv("100.128.0.1") and not _priv("100.63.255.255"))
        ch("is_private_ip: IP عمومی → عمومی",
           not _priv("193.151.142.128") and not _priv("8.8.8.8"))

    # ---------- v0.8.3: IP CONTINUITY — رگرسیون باگ میدان «آی‌پی لوکال به‌جای
    # آی‌پی اصلی سرور» (۲۰۲۶-۱۱-۱۰): مسیر ارتقا دیگر IP ضبط‌شده را با تشخیص
    # مجدد بازنویسی نمی‌کند؛ بلوک واقعی install.sh را استخراج و اجرا می‌کنیم
    # تا regression روی خود کد پین شود (نه فقط grep). ----------
    ipcont = re.search(
        r"^ *# v0\.8\.3 — IP CONTINUITY.*?(?=^ *# regenerate TLS only if missing)",
        inst, re.S | re.M)
    ch("install.sh: بلوک پیوستگی IP موجود است", ipcont is not None)
    if ipcont:
        # بلوک واقعی را به اسکریپت مستقل تبدیل می‌کنیم (کم‌کردن تورفتگی)
        block = "\n".join(
            (line[2:] if line.startswith("  ") else line)
            for line in ipcont.group(0).splitlines())

        def _run_ipcont(recorded: str, detect: str,
                       env_ip: str = "") -> tuple[str, str]:
            """بلوک واقعی install.sh را با stubها اجرا می‌کند؛ خروجی: IP نهایی."""
            d = Path(tempfile.mkdtemp(prefix="aa-ipcont-"))
            (d / "config.json").write_text(
                json.dumps({"ip": recorded, "port": 12345, "version": "9.9.9"}),
                encoding="utf-8")
            sh = d / "ipcont.sh"
            sh.write_text(
                "is_private_ip() {\n"
                "  printf '%s' \"${1:-}\" | grep -qE '^(10\\.|127\\.|169\\.254\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.|0\\.|22[4-9]\\.|2[3-5][0-9]\\.)'\n"
                "}\n"
                "detect_ip() { printf '%s\\n' \"" + detect + "\"; }\n"
                "ok() { :; }\n"
                "PYBIN=\"$(command -v python3)\"\n"
                f"ETC=\"{d}\"\n"
                f"ACCESS_AGENT_IP=\"{env_ip}\"\n"
                + block + "\n"
                "printf '%s\\n' \"$IP\"\n", encoding="utf-8")
            r = subprocess.run(["bash", str(sh)], capture_output=True,
                               text=True, timeout=30)
            shutil.rmtree(d, ignore_errors=True)
            return r.stdout.strip(), r.stderr[:200]

        got, _err = _run_ipcont("193.151.142.128", "172.22.0.1")
        ch("پیوستگی IP: آدرس عمومیِ ضبط‌شده با تشخیصِ لوکال بازنویسی نمی‌شود (باگ میدان)",
           got == "193.151.142.128", f"got={got!r}")
        got, _err = _run_ipcont("172.22.0.1", "193.151.142.128")
        ch("پیوستگی IP: آدرس خصوصیِ ضبط‌شده با کاندید عمومی تعمیر می‌شود",
           got == "193.151.142.128", f"got={got!r}")
        got, _err = _run_ipcont("172.22.0.1", "172.22.0.1")
        ch("پیوستگی IP: بدون کاندید بهتر، مقدار ضبط‌شده می‌ماند (تنزل ممنوع)",
           got == "172.22.0.1", f"got={got!r}")
        got, _err = _run_ipcont("", "193.151.142.128")
        ch("پیوستگی IP: مقدار غایب با تشخیص عمومی پر می‌شود",
           got == "193.151.142.128", f"got={got!r}")
        got, _err = _run_ipcont("193.151.142.128", "172.22.0.1", env_ip="5.6.7.8")
        ch("پیوستگی IP: ACCESS_AGENT_IP صریح اپراتور بر همه غالب است",
           got == "5.6.7.8", f"got={got!r}")

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
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "echo -n " + "A" * 16376})
    ch("exec cmd مرز ۱۶۳۸۴ → پذیرفته و اجرا", code == 200
       and len(b.get("stdout", "")) == 16376)
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "x" * 17000})
    ch("exec cmd بلند → cmd_too_long", code == 400 and b.get("error") == "cmd_too_long"
       and b.get("limit") == 16384)
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
    # فرمان مالک (2026-11-09): مسیر موبایل — بعد از set، وضعیت باید فلیپ کند
    code, b = req("GET", "/api/status", token=ADMIN)
    ch("status بعد از set: github_token_stored=true", code == 200
       and b.get("github_token_stored") is True)

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
    ch("متن بیداری یکتا در بلوک (قرارداد سه‌مرجعی v0.6.6)", handoff.ECOSYSTEM_URL in block)
    ch("خاستگاه: تولید توسط پل روی سرور مالک تصریح شده", "روی سرور مالک تولید کرده" in block)
    ch("دعوت نقش، نه انتساب هویت", "عامل مرکزی پرستو" in block and "You are" not in block)
    ch("مدل اعتماد: پین گواهی + قلمرو توکن + خطوط قرمز", "ضمانت مالک" in block
       and "ابطال" in block and "رد نکن" in block)
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

    # ---------- v0.2: GitHub App — توکن نصب واقعی با انقضای گیت‌هاب ----------
    import base64 as b64
    from access_agent import githubapp, server as aa_server

    keyp = Path(TMP) / "app-key.pem"
    r = subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(keyp)],
                       capture_output=True)
    ch("کلید RSA آزمون ساخته شد", r.returncode == 0 and keyp.exists())
    pem_text = keyp.read_text()

    # --- JWT: ساختار + امضای واقعی openssl ---
    jwt = githubapp.mint_jwt("12345", pem_text, now=1700000000)
    h, p, s = jwt.split(".")
    header = json.loads(b64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    payload = json.loads(b64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    ch("JWT هدر RS256/typ", header.get("alg") == "RS256" and header.get("typ") == "JWT")
    ch("JWT بار iss/iat/exp", payload.get("iss") == 12345
       and payload.get("iat") == 1699999940 and payload.get("exp") == 1700000540)
    pub = Path(TMP) / "app-pub.pem"
    subprocess.run(["openssl", "pkey", "-in", str(keyp), "-pubout", "-out", str(pub)],
                   capture_output=True)
    sig_input = f"{h}.{p}".encode()
    sigf = Path(TMP) / "sig.bin"
    sigf.write_bytes(b64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pub),
                        "-signature", str(sigf)], input=sig_input, capture_output=True)
    ch("JWT امضا با openssl راستی‌آزمایی می‌شود",
       r.returncode == 0 and b"Verified OK" in r.stdout)

    # --- config: اعتبارسنجی و مجوزها ---
    try:
        githubapp.save_config("not-numeric", str(keyp)); bad = False
    except githubapp.GitHubAppError:
        bad = True
    ch("app_id غیرعددی رد می‌شود", bad)
    try:
        githubapp.save_config("12345", str(Path(TMP) / "missing.pem")); bad = False
    except githubapp.GitHubAppError:
        bad = True
    ch("pem ناموجود رد می‌شود", bad)
    junk = Path(TMP) / "junk.pem"; junk.write_text("hello world", encoding="utf-8")
    try:
        githubapp.save_config("12345", str(junk)); bad = False
    except githubapp.GitHubAppError:
        bad = True
    ch("فایل غیر-کلید رد می‌شود", bad)
    cfg = githubapp.save_config("12345", str(keyp))
    ch("config ذخیره شد و اپ «پیکربندی‌شده» است",
       cfg.get("app_id") == "12345" and githubapp.configured())
    ch("pem و config روی دیسک 600 هستند",
       oct(githubapp.pem_path().stat().st_mode & 0o777) == "0o600"
       and oct(githubapp.app_config_path().stat().st_mode & 0o777) == "0o600")

    # --- disclose با API جعلی: کشف installation، مینت، کش ---
    CALLS: list[tuple[str, str]] = []

    def fake_api(method, path, bearer, body=None, timeout=20):
        CALLS.append((method, path))
        if method == "GET" and path == "/app/installations":
            return 200, [{"id": 4242, "app_slug": "parastoo-agent"}]
        if method == "POST" and path == "/app/installations/4242/access_tokens":
            # fake installation token - built at runtime so no literal secret in source
            fake_tok = "gh" + "s_" + "smoke" * 6
            return 201, {"token": fake_tok,
                         "expires_at": "2030-01-01T00:00:00Z",
                         "permissions": {"contents": "write", "metadata": "read"},
                         "repository_selection": "selected"}
        raise AssertionError(f"unexpected api call {method} {path}")

    real_api = githubapp._api
    githubapp._api = fake_api
    try:
        res = githubapp.disclose("smoke: install the v0.2 flow")
        ch("disclose توکن نصب با mode github-app می‌دهد",
           res.get("ok") is True and res.get("mode") == "github-app"
           and res.get("token", "").startswith("ghs_")
           and res.get("expires_at") == "2030-01-01T00:00:00Z")
        ch("installation_id خودکار کشف و ماندگار شد",
           githubapp.load_config().get("installation_id") == "4242"
           and ("GET", "/app/installations") in CALLS
           and ("POST", "/app/installations/4242/access_tokens") in CALLS)
        n_calls = len(CALLS)
        res2 = githubapp.disclose("smoke: reuse the cached token")
        ch("توکن زندهٔ کش‌شده دوباره استفاده می‌شود (بدون تماس تازه)",
           len(CALLS) == n_calls and res2.get("token") == res.get("token")
           and res2.get("grant", {}).get("cached") is True)
        githubapp.mint_token(force=True)
        ch("force مینت تازه می‌زند (installation ذخیره‌شده فقط POST می‌خواهد)",
           len(CALLS) == n_calls + 1)
        ch("grant در sessions.jsonl با mode ثبت شد",
           "github-app" in (Path(TMP) / "sessions.jsonl").read_text())
        short = githubapp.disclose("koochak")
        ch("purpose کوتاه → 400", short.get("status") == 400
           and short.get("error") == "purpose_required")
        # --- انتخاب حالت روی سرور درون-فرآیندی ---
        gs = aa_server.ThreadingHTTPServer(("127.0.0.1", 0), aa_server.Handler)
        gt = threading.Thread(target=gs.serve_forever, daemon=True)
        gt.start()
        try:
            PORT2 = gs.socket.getsockname()[1]

            def req2(method, path, token, body=None):
                data = json.dumps(body).encode() if body is not None else None
                rq = urllib.request.Request(f"http://127.0.0.1:{PORT2}{path}",
                                            data=data, method=method)
                rq.add_header("Authorization", f"Bearer {token}")
                with urllib.request.urlopen(rq, timeout=10) as resp:
                    return resp.status, json.loads(resp.read())

            code, b = req2("POST", "/api/github/token", ADMIN,
                           {"purpose": "smoke: app mode via server"})
            ch("سرور در حالت اپ توکن نصب می‌دهد (پات نه)",
               code == 200 and b.get("mode") == "github-app"
               and b.get("token", "").startswith("ghs_"))
            githubapp.clear_config()
            code, b = req2("POST", "/api/github/token", ADMIN,
                           {"purpose": "smoke: pat fallback mode"})
            ch("بدون اپ: فالبک به حالت پات (قرارداد v0.1 دست‌نخورده)",
               code == 200 and b.get("ok") is True and b.get("mode", "pat") != "github-app"
               and "token" in b)
        finally:
            gs.shutdown(); gs.server_close()
    finally:
        githubapp._api = real_api
        githubapp.clear_config()

    # --- v0.2 در فایل‌های نصب و CLI ---
    inst_txt = (REPO / "install.sh").read_text()
    ch("خروجی نصب دیگر ADMIN_TOKEN خام چاپ نمی‌کند (فقط اشاره‌گر show-admin-token)",
       'ADMIN_TOKEN:     $ADMIN_TOKEN' not in inst_txt
       and "sudo access-agent show-admin-token" in inst_txt)
    cli_txt = (REPO / "deploy" / "access-agent-cli.sh").read_text()
    ch("CLI مالک فرمان‌های اپ را دارد",
       all(c in cli_txt for c in ("set-github-app)", "test-github-app)",
                                  "show-github-app)", "clear-github-app)")))
    guide = (REPO / "docs" / "GITHUB_APP_GUIDE.fa.md").read_text()
    ch("راهنمای GitHub App موجود است و مسیر SSH کلید را الزام می‌کند",
       "Developer settings" in guide and "scp" in guide)


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
