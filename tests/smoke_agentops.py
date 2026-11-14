#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی v0.12 — عامل‌پذیری: هدرهای خودتوصیف + حافظهٔ بیرونی عامل + dry_run + خطاهای بازگشتی.

چهار ستون v0.12 (توافق مالک–عامل ۲۰۲۶-۱۱-۱۴: «درک و اجرای پروژه برای عامل‌ها آسان‌تر»):
  ۱) هر پاسخ X-API-Version و X-Request-Id دارد؛ پاسخ‌های mutating کلید rid
     (شناسهٔ رکورد audit) می‌برند — قابل نقل در تیکت، بدون راز.
  ۲) GET /api/agent/audit?tail=N — حافظهٔ بیرونی عامل: فقط رویدادهای همین
     نشست (session_sha)؛ عاملِ با بافت بازیافت‌شده اول این را می‌خواند.
  ۳) dry_run روی /api/exec و /api/github/token — پیش‌نمایش بدون اجرا/افشا؛
     همان اعتبارسنجی‌ها (طول/تایم‌اوت/تقابل lifecycle).
  ۴) خطاهای بازگشتی: 401 با info (iid_rate_cap + retry_after_s)؛ busy با
     retry_after_s و سقف هم‌زمانی — عامل خودش را کم می‌کند، نه آزمون‌وخطا.

قرمزها: session_sha فقط هش است (توکن خام هرگز در audit نیست)، /api/agent/audit
فقط نشست زنده می‌بیند (توکن ادمین و بی‌توکن رد)، رویدادهای نشست دیگر جدا است،
dry_run دستور را اجرا نمی‌کند، ?since فقط تغییرات پس از نسخه را می‌دهد.

اجرا:  python tests/smoke_agentops.py   (کاملاً آفلاین، بدون TLS در تست)
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GREEN, RED, YELLOW, NC = "\033[92m", "\033[91m", "\033[93m", "\033[0m"
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
        timeout: float = 15) -> tuple[int, dict, dict]:
    """برمی‌گرداند (code, body, headers) — هدرها برای چک‌های خودتوصیف."""
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read()), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read()), dict(e.headers)
        except Exception:
            return e.code, {}, dict(e.headers)


# ---------- start server ----------
PORT = free_port()
TMP = tempfile.mkdtemp(prefix="access-agent-agentops.")
os.environ["ACCESS_AGENT_HOME"] = TMP
os.environ["ACCESS_AGENT_PORT"] = str(PORT)
os.environ["ACCESS_AGENT_NO_TLS"] = "1"

sys.path.insert(0, str(REPO))
from access_agent.security import mint_invite  # noqa: E402

ADMIN = "adm_" + os.urandom(24).hex()
AGENT = "aa_" + os.urandom(24).hex()   # توکن بلندمدت برای تست نقش agent
(Path(TMP) / "tokens.json").write_text(json.dumps({
    "admin_sha": hashlib.sha256(ADMIN.encode()).hexdigest(),
    "agent_sha": hashlib.sha256(AGENT.encode()).hexdigest(),
}), encoding="utf-8")
(Path(TMP) / "config.json").write_text(json.dumps({
    "ip": "203.0.113.7", "port": 9999, "version": "0.12.0",
}), encoding="utf-8")
(Path(TMP) / "tls").mkdir(exist_ok=True)
subprocess.run(
    ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
     "-keyout", str(Path(TMP) / "tls" / "key.pem"), "-out", str(Path(TMP) / "tls" / "cert.pem"),
     "-days", "2", "-nodes", "-subj", "/CN=access-agent-smoke"],
    check=True, capture_output=True,
)

env = dict(os.environ)
env["PYTHONUNBUFFERED"] = "1"
server_log = open(Path(TMP) / "server.log", "w", encoding="utf-8")
proc = subprocess.Popen(
    [sys.executable, "-m", "access_agent.server"],
    cwd=str(REPO), env=env,
    stdout=server_log, stderr=server_log, stdin=subprocess.DEVNULL,
)
atexit.register(lambda: (proc.terminate(), server_log.close()))


def teardown() -> None:
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        proc.kill()


up = False
for _ in range(50):
    try:
        c, _b, _h = req("GET", "/healthz", timeout=2)
        if c == 200:
            up = True
            break
    except Exception:
        pass
    time.sleep(0.2)


def main() -> int:
    ch("سرور بالا آمد", up)
    if not up:
        print(server_log.read())
        return 1

    # ---------- ۱) هدرهای خودتوصیف روی همهٔ پاسخ‌ها ----------
    c, b, h = req("GET", "/healthz")
    ch("healthz: هدر X-API-Version نسخهٔ سرویس را می‌دهد",
       h.get("X-API-Version") == "0.12.0")
    ch("healthz: هدر X-Request-Id یکتا و غیرخالی دارد",
       bool(h.get("X-Request-Id")))
    rid1 = h.get("X-Request-Id", "")
    c, b, h2 = req("GET", "/healthz")
    ch("X-Request-Id بین دو درخواست فرق می‌کند", h2.get("X-Request-Id") != rid1)
    c, b, h = req("GET", "/api/docs")
    ch("docs: هدر X-API-Version دارد", h.get("X-API-Version") == "0.12.0")
    c, b, h = req("GET", "/api/status", token="bad-token")
    ch("خطای 401 هم هدرهای خودتوصیف دارد", c == 401 and h.get("X-API-Version") == "0.12.0")

    # ---------- ۴) خطای 401 با info بازگشتی ----------
    ch("401: info.iid_rate_cap سقف نرخ‌سنجی iid را می‌گوید",
       "10/5min" in str(b.get("info", {}).get("iid_rate_cap", "")))
    ch("401: info.retry_after_s عدد است",
       isinstance(b.get("info", {}).get("retry_after_s"), int))

    # ---------- ?since روی /api/docs ----------
    c, b, _h = req("GET", "/api/docs?since=0.11.2")
    ch("docs?since=0.11.2: فقط تغییرات پس از آن نسخه",
       c == 200 and [r.get("since") for r in b.get("since_changes", [])] == ["0.12.0"])
    c, b, _h = req("GET", "/api/docs?since=0.9.0")
    ch("docs?since=0.9.0: مقایسهٔ عددی درست (0.11.0 > 0.9.0)",
       len(b.get("since_changes", [])) >= 4)
    c, b, _h = req("GET", "/api/docs?since=0.99.0")
    ch("docs?since آینده: خالی", b.get("since_changes") == [])
    c, b, _h = req("GET", "/api/docs")
    ch("docs بدون since: کلید since_changes ندارد (پاکت کامل)",
       "since_changes" not in b)

    # ---------- اتصال مالک با دعوت (پیش‌نیاز نشست) ----------
    from access_agent.security import claim_invite_session
    iid, _ = mint_invite("مالک-تست", ttl_s=3600, role="owner")
    res = claim_invite_session(iid, ip="127.0.0.1")
    ch("دعوت مالک: توکن pst_ صادر شد", res.get("ok") is True
       and res.get("token", "").startswith("pst_"))
    OTOK = res.get("token", "")

    # ---------- ۲) حافظهٔ بیرونی عامل ----------
    # چند رویداد با نشست مالک بساز
    c, b, _h = req("POST", "/api/exec", token=OTOK,
                   body={"cmd": "echo memory-external-test"})
    ch("مالک: exec موفق", c == 200 and b.get("exit_code") == 0)
    exec_rid = b.get("rid", "")
    ch("exec: کلید rid (شناسهٔ رکورد audit) در پاسخ است",
       isinstance(exec_rid, str) and len(exec_rid) == 12)
    ch("exec: خروجی دستور واقعی است", "memory-external-test" in str(b.get("stdout", "")))

    c, b, _h = req("GET", "/api/agent/audit?tail=50", token=OTOK)
    ch("مالک: /api/agent/audit → 200", c == 200 and b.get("ok") is True)
    evs = b.get("events", [])
    ch("حافظهٔ بیرونی: رویداد exec همین نشست دیده می‌شود",
       any(e.get("action") == "exec" and e.get("rid") == exec_rid for e in evs))
    ch("حافظهٔ بیرونی: رویدادها session_sha دارند",
       all("session_sha" in e for e in evs if e.get("action") == "exec"))
    ch("حافظهٔ بیرونی: مقدار توکن خام در رویدادها نیست",
       OTOK not in json.dumps(evs))

    # نشست دوم (عامل قدیمی aa_) — رویدادها باید جدا باشند
    c, b, _h = req("POST", "/api/exec", token=AGENT, body={"cmd": "echo legacy-agent"})
    ch("عامل قدیمی aa_: exec موفق", c == 200 and b.get("exit_code") == 0)
    c, b, _h = req("GET", "/api/agent/audit?tail=50", token=AGENT)
    evs2 = b.get("events", [])
    ch("جداسازی نشست: عامل قدیمی رویداد exec خودش را می‌بیند",
       any(e.get("action") == "exec" for e in evs2))
    ch("جداسازی نشست: عامل قدیمی رویداد مالک را نمی‌بیند",
       not any(e.get("rid") == exec_rid for e in evs2))

    # توکن ادمین و بی‌توکن رد می‌شوند
    c, b, _h = req("GET", "/api/agent/audit", token=ADMIN)
    ch("توکن ادمین: /api/agent/audit → 403 (فقط نشست عامل)", c == 403)
    c, b, _h = req("GET", "/api/agent/audit")
    ch("بدون توکن: /api/agent/audit → 401", c == 401)
    # سقف tail
    c, b, _h = req("GET", "/api/agent/audit?tail=99999", token=OTOK)
    ch("tail بزرگ: سقف ۱۰۰ اعمال می‌شود", c == 200 and b.get("n", 999) <= 100)

    # ---------- ۳) dry_run ----------
    marker = f"agentops-dryrun-{os.urandom(4).hex()}"
    c, b, _h = req("POST", "/api/exec", token=OTOK,
                   body={"cmd": f"echo {marker}", "dry_run": True})
    ch("exec dry_run: 200 با dry_run=true", c == 200 and b.get("dry_run") is True)
    ch("exec dry_run: executed=false", b.get("executed") is False)
    ch("exec dry_run: rid دارد", len(str(b.get("rid", ""))) == 12)
    # اطمینان: دستور واقعاً اجرا نشده — اجرای بعدی بدون dry_run نباید آن را در
    # خروجی ببیند (echo جداست)؛ اما مطمئن‌تر: فایل نشانه نسازیم، فقط چک کنیم
    # پاسخ dry_run خروجی stdout ندارد
    ch("exec dry_run: stdout ندارد (پیش‌نمایش، نه اجرا)",
       "stdout" not in b or not b.get("stdout"))
    # اعتبارسنجی‌ها در dry_run هم فعال‌اند
    c, b, _h = req("POST", "/api/exec", token=OTOK,
                   body={"cmd": "echo x", "timeout_s": 99999, "dry_run": True})
    ch("exec dry_run: تایم‌اوت نامعتبر → 400 timeout_out_of_range",
       c == 400 and b.get("error") == "timeout_out_of_range")
    c, b, _h = req("POST", "/api/exec", token=OTOK,
                   body={"cmd": "x" * 20000, "dry_run": True})
    ch("exec dry_run: cmd طولانی → 400 cmd_too_long",
       c == 400 and b.get("error") == "cmd_too_long")
    c, b, _h = req("POST", "/api/exec", token=OTOK,
                   body={"cmd": "echo ok && docker compose up -d", "dry_run": True})
    ch("exec dry_run: تقابل lifecycle را می‌گوید (lifecycle_conflict)",
       c == 200 and b.get("lifecycle_conflict") is True
       and b.get("would_reject_if_busy", {}).get("error") == "lifecycle_busy")

    # github/token dry_run — بدون ساخت grant و بدون افشا
    c, b, _h = req("POST", "/api/github/token", token=OTOK,
                   body={"purpose": "dry run preview test", "dry_run": True})
    ch("github/token dry_run: 200 با dry_run=true", c == 200 and b.get("dry_run") is True)
    ch("github/token dry_run: mode را می‌گوید (pat-fallback)",
       b.get("mode") in ("pat-fallback", "github-app"))
    ch("github/token dry_run: توکنی افشا نمی‌شود",
       "token" not in b or not b.get("token"))
    grants_file = Path(TMP) / "sessions.jsonl"
    grants_before = grants_file.read_text(encoding="utf-8") if grants_file.exists() else ""
    c, b, _h = req("POST", "/api/github/token", token=OTOK,
                   body={"purpose": "another dry run preview test", "dry_run": True})
    grants_after = grants_file.read_text(encoding="utf-8") if grants_file.exists() else ""
    ch("github/token dry_run: grant ثبت نمی‌شود (sessions.jsonl تغییر نکرد)",
       grants_before == grants_after)

    # نقش user: dry_run هم ممنوع است (قلمرو، نه ابزار)
    from access_agent.security import mint_agent_session
    utok, _rec = mint_agent_session(ttl_s=3600, role="user")
    c, b, _h = req("POST", "/api/exec", token=utok,
                   body={"cmd": "echo x", "dry_run": True})
    ch("کاربر: exec dry_run هم → 403 agent_scope_forbidden",
       c == 403 and b.get("error") == "agent_scope_forbidden")

    # ---------- ۴) busy با info ----------
    # دو exec بلند هم‌زمان + سومی → busy با retry_after_s
    import threading
    held = threading.Semaphore(0)
    done = threading.Semaphore(0)

    def long_exec():
        held.release()
        try:
            req("POST", "/api/exec", token=OTOK,
                body={"cmd": "sleep 3", "timeout_s": 10}, timeout=20)
        finally:
            done.release()

    t1 = threading.Thread(target=long_exec)
    t2 = threading.Thread(target=long_exec)
    t1.start(); t2.start()
    held.acquire(); held.acquire()
    time.sleep(0.5)  # هر دو داخل bash باشند
    c, b, _h = req("POST", "/api/exec", token=OTOK, body={"cmd": "echo third", "timeout_s": 5})
    if c == 429 and b.get("error") == "busy":
        ch("busy: retry_after_s عدد است", isinstance(b.get("retry_after_s"), int))
        ch("busy: info.exec_concurrent_max سقف را می‌گوید",
           b.get("info", {}).get("exec_concurrent_max") == 2)
    else:
        # اگر ریسه‌ها هنوز داخل سمافر نبودند (race نادر)، چک نکنیم
        ch("busy: سومین exec هم‌زمان → 429 busy", False,
           f"got {c} {b.get('error')}")
    done.acquire(); done.acquire()
    t1.join(); t2.join()

    # ---------- روی دیسک: فقط هش ----------
    al = (Path(TMP) / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    ch("audit: مقدار توکن‌ها هرگز نوشته نشده",
       OTOK not in al and AGENT not in al and ADMIN not in al)
    ch("audit: رکوردها rid و request_id دارند",
       '"rid"' in al and '"request_id"' in al)
    ch("audit: رویداد dry_run ثبت شده (exec_dry_run)",
       "exec_dry_run" in al)
    ch("audit: رویداد github_token_dry_run ثبت شده",
       "github_token_dry_run" in al)
    ch("audit: agent_audit_self ثبت شده", "agent_audit_self" in al)
    # رویداد user 403 هم session_sha دارد؟ (user هم نقش agent در _role است)
    ch("audit: رویداد agent_scope_forbidden ثبت شد", "agent_scope_forbidden" in al)

    # 405 روی متد اشتباه
    c, b, _h = req("POST", "/api/agent/audit", token=OTOK, body={})
    ch("POST /api/agent/audit → 405", c == 405)

    teardown()
    print(f"\n# جمع‌بندی: {GREEN}{n_pass} سبز{NC}، {RED}{n_fail} قرمز{NC}")
    if failures:
        print("# شکست‌ها:")
        for f in failures:
            print(f"  - {f}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
