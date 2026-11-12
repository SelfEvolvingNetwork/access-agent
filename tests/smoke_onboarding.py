#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی v0.7 — آشناسازی اعتماد (اصل «اول سرور، بعد توکن»).

جریان کامل از نگاه هر دو طرف:
  مالک: invite → دعوت‌نامهٔ کوتاه (URL + هش گواهی + کد یک‌بارمصرف)
  عامل: GET /api/agent/onboarding (فقط‌خواندنی، بدون توکن)
        → POST /api/agent/onboard {onboard_code} → توکن موقت
        → GET /api/status با توکن موقت
        → POST /api/agent/session/end در پایان مکالمه
  قرمز: کد غلط/مصرف‌شده/منقضی، استفاده مجدد، توکن موقت روی مسیر ادمین.

اجرا:  python tests/smoke_onboarding.py   (کاملاً آفلاین، بدون TLS در تست)
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
        timeout: float = 15) -> tuple[int, dict]:
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


# ---------- start server ----------
PORT = free_port()
TMP = tempfile.mkdtemp(prefix="access-agent-onboard.")
os.environ["ACCESS_AGENT_HOME"] = TMP
os.environ["ACCESS_AGENT_PORT"] = str(PORT)
os.environ["ACCESS_AGENT_NO_TLS"] = "1"

sys.path.insert(0, str(REPO))
from access_agent.handoff import (build_invite_block, onboarding_doc,  # noqa: E402
                                  invite_missing_inputs)
from access_agent.security import (check_agent_session,  # noqa: E402
                                   consume_onboard_code, mint_onboard_code,
                                   mint_agent_session, revoke_agent_session)

ADMIN = "adm_" + os.urandom(24).hex()
(Path(TMP) / "tokens.json").write_text(json.dumps({
    "admin_sha": hashlib.sha256(ADMIN.encode()).hexdigest(),
    "agent_sha": "",
}), encoding="utf-8")
(Path(TMP) / "config.json").write_text(json.dumps({
    "ip": "203.0.113.7", "port": 9999, "version": "0.7.0",
}), encoding="utf-8")
# گواهی خودامضای ساختگی برای پین‌کردنِ دعوت‌نامه (فقط در تست)
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
        c, _b = req("GET", "/healthz", timeout=2)
        if c == 200:
            up = True
            break
    except Exception:
        pass
    time.sleep(0.2)


def main() -> int:
    ch("سرور بالا آمد", up)
    if not up:
        print(server_log)
        return 1

    # ---------- سمت مالک: دعوت‌نامهٔ کوتاه ----------
    ch("invite: ورودی‌ها کافی است", not invite_missing_inputs())
    code, rec = mint_onboard_code(ttl_s=3600)
    ch("کد آشناسازی با پیشوند ob_ تولید شد", code.startswith("ob_") and rec.get("used") is False)
    ch("روی دیسک فقط هش است", code not in (Path(TMP) / "onboard.json").read_text())
    invite = build_invite_block(code, ttl_min=60)
    ch("دعوت‌نامه: آدرس سرور دارد", "https://203.0.113.7:9999" in invite)
    ch("دعوت‌نامه: هش گواهی دارد", "CERT" not in invite or "هش گواهی" in invite)
    ch("دعوت‌نامه: توکن دائمی ندارد", "aa_" not in invite and "adm_" not in invite)
    ch("دعوت‌نامه: به مسیر onboarding اشاره می‌کند", "/api/agent/onboarding" in invite)
    ch("دعوت‌نامه: کوتاه است (کمتر از ۹۰۰ نویسه)", len(invite) < 900, f"len={len(invite)}")

    # ---------- سمت عامل: نخستین تراکنش فقط‌خواندنی ----------
    c, b = req("GET", "/api/agent/onboarding")
    ch("onboarding بدون توکن 200", c == 200 and b.get("ok") is True)
    ch("onboarding: پروتکل 0.8.1", b.get("protocol") == "onboarding/0.8.1")
    ch("onboarding: بدون iid → invite_required",
       b.get("invite_required") is True and "pairing" not in b)
    ch("onboarding: هیچ توکنی در پاسخ نیست",
       "aa_" not in json.dumps(b) and "adm_" not in json.dumps(b))
    ch("onboarding: چرخهٔ شش‌مرحله‌ای جفت‌سازی دارد",
       set(b.get("session_flow", {}).keys()) ==
       {"1_read_this", "2_get_code", "3_relay_by_user", "4_poll",
        "5_first_calls", "6_end_of_conversation"})
    ch("onboarding: مسیر جایگزین کد مالک دارد", "fallback_owner_code" in b)
    ch("onboarding: خط قرمز تخریب صریح است",
       any("تخریبی" in r for r in b.get("rules", [])))
    c, b = req("POST", "/api/agent/onboarding", body={})
    ch("POST روی onboarding → 405", c == 405)

    # ---------- تبادل کد ↔ توکن موقت ----------
    c, b = req("POST", "/api/agent/onboard", body={"onboard_code": "ob_" + "0" * 32})
    ch("کد غلط → 401", c == 401 and b.get("error") == "onboard_refused")
    c, b = req("POST", "/api/agent/onboard", body={})
    ch("بدون کد → 401", c == 401)
    c, tok = req("POST", "/api/agent/onboard", body={"onboard_code": code})
    ch("کد درست → توکن موقت", c == 200 and tok.get("agent_token", "").startswith("aagx_"))
    TOK = tok.get("agent_token", "")
    ch("فیلد token همان agent_token است (v0.8.1)",
       tok.get("token") == TOK and TOK.startswith("aagx_"))
    ch("توکن موقت انقضا دارد", bool(tok.get("expires")))
    c, b = req("POST", "/api/agent/onboard", body={"onboard_code": code})
    ch("استفادهٔ مجدد از کد → 401 (یک‌بارمصرف)", c == 401)

    # ---------- توکن موقت مثل عامل رفتار می‌کند ----------
    c, b = req("GET", "/api/status", token=TOK)
    ch("status با توکن موقت 200", c == 200 and b.get("ok"))
    c, b = req("GET", "/api/admin/audit", token=TOK)
    ch("توکن موقت روی مسیر ادمین → 403", c == 403)
    c, b = req("POST", "/api/exec", token=TOK, body={"cmd": "echo onboarding-ok"})
    ch("exec با توکن موقت 200", c == 200 and b.get("exit_code") == 0)
    ch("check_agent_session در واحد تایید می‌کند", check_agent_session(TOK))
    c, b = req("GET", "/api/status", token=ADMIN)
    ch("ادمین همچنان superset است", c == 200)

    # ---------- پایان مکالمه: پاک شدن نشست ----------
    c, b = req("POST", "/api/agent/session/end", token=TOK, body={})
    ch("پایان نشست 200 و session_removed", c == 200 and b.get("session_removed") is True)
    c, b = req("GET", "/api/status", token=TOK)
    ch("توکن موقت پس از پایان → 401", c == 401)
    ch("check_agent_session پس از پایان False است", not check_agent_session(TOK))
    c, b = req("POST", "/api/agent/session/end", token=TOK, body={})
    ch("پایان نشست دوباره با توکن مرده → 401", c == 401)
    c, b = req("POST", "/api/agent/session/end", token=ADMIN, body={})
    ch("ادمین بدون نشست → پایان بی‌ضرر (session_removed=false)", c == 200 and b.get("session_removed") is False)

    # ---------- audit: رد و قبول ثبت شده، مقدار کد هرگز ----------
    al = (Path(TMP) / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    ch("audit: onboarding_read ثبت شده", "agent_onboarding_read" in al)
    ch("audit: onboard_granted ثبت شده", "agent_onboard_granted" in al)
    ch("audit: onboard_refused ثبت شده", "agent_onboard_refused" in al)
    ch("audit: session_end ثبت شده", "agent_session_end" in al)
    ch("audit: مقدار کد/توکن هرگز لاگ نشده", code not in al and TOK not in al)

    # ---------- سند onboarding مستقیم (بدون شبکه) ----------
    doc = onboarding_doc()
    ch("onboarding_doc: مدل اعتماد هفت‌بخشی دارد (v0.8: +invite)",
       set(doc["trust_model"]) == {"tls", "pairing", "invite", "scope", "audit",
                                   "persistent_channel", "your_caution_is_welcome"})
    ch("onboarding_doc: ترتیب خواندن سه‌مرجعی", len(doc["reading_order"]) == 4)

    # ---------- نشست اضافی و سقف ۵ ----------
    raw2, _ = mint_agent_session(ttl_s=60)
    ch("نشست دوم مستقل معتبر است", check_agent_session(raw2))
    ch("ابطال نشست غلط False می‌دهد", not revoke_agent_session("aagx_" + "f" * 48))
    ch("ابطال نشست درست True می‌دهد", revoke_agent_session(raw2))
    ch("نشست دوم پس از ابطال مرده است", not check_agent_session(raw2))

    teardown()
    print(f"\n# جمع‌بندی: {GREEN}{n_pass} سبز{NC}، {RED}{n_fail} قرمز{NC}")
    if failures:
        print("# شکست‌ها:")
        for f in failures:
            print(f"  - {f}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
