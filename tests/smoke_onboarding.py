#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی v0.10 — الگوی اتصال مالک/کاربر + پاسخ الگوی مالک + مسیر gardesh + /api/docs.

جریان کامل، از نگاه هر دو طرف:
  مالک:  GET /api/admin/invite?role=owner|user&for=<کاربر> ← دعوت‌نامهٔ یک‌خطی:
         «لطفا با api من یک اتصال پایدار ایجاد کنید: https://…/onboarding/gardesh/pinv_…»
  عامل:  GET همان URL ← مستقیماً توکن نقش‌دار pst_ + انقضای UTC-Z + docs؛
         نه رمز، نه claim، نه poll
         → نقش مالک: status کامل + exec + توکن گیت‌هاب مجاز
         → نقش کاربر: status فیلترشده؛ exec و توکن گیت‌هاب → 403 agent_scope_forbidden
         → POST /api/agent/session/end در پایان مکالمه

فرمان مالک ۲۰۲۶-۱۱-۱۳ (الگوی اتصال): پاسخ دقیقاً به الگوی خودِ مالک —
message (تک‌مصرف) + agent_token + expires (Z) + auth_note + storage_hint + docs؛
دستورهای رفتاری (next/tell_user/store_token) از پاسخ حذف شد — مرجع فنی کامل
حالا روی GET /api/docs (عمومی) زندگی می‌کند. پورت رایج: 443 در URL نمی‌آید.

قرمزها: iid غلط/مصرف‌شده/منقضی، یک دعوت = یک عامل، نرخ‌سنجی خطای iid،
نقش از رکورد دعوت (نه از رشتهٔ توکن)، فقط هش روی دیسک، audit بدون مقدار
iid/توکن، user نمی‌تواند exec/گیت‌هاب/ادمین، status کاربر فیلترشده.

اجرا:  python tests/smoke_onboarding.py   (کاملاً آفلاین، بدون TLS در تست)
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
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
from access_agent import appcore  # noqa: E402
from access_agent.handoff import build_invite, onboarding_doc  # noqa: E402
from access_agent.security import (check_agent_session, live_invite_stats,  # noqa: E402
                                   mint_agent_session, mint_invite,
                                   revoke_agent_session, INVITE_ROLE_PREFIXES)

ADMIN = "adm_" + os.urandom(24).hex()
AGENT = "aa_" + os.urandom(24).hex()   # توکن بلندمدت برای تست 403
(Path(TMP) / "tokens.json").write_text(json.dumps({
    "admin_sha": hashlib.sha256(ADMIN.encode()).hexdigest(),
    "agent_sha": hashlib.sha256(AGENT.encode()).hexdigest(),
}), encoding="utf-8")
(Path(TMP) / "config.json").write_text(json.dumps({
    "ip": "203.0.113.7", "port": 9999, "version": "0.10.0",
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
        c, _b = req("GET", "/healthz", timeout=2)
        if c == 200:
            up = True
            break
    except Exception:
        pass
    time.sleep(0.2)


def get_invite(label: str = "", role: str = "user") -> tuple[str, str]:
    """برمی‌گرداند (iid, invite_text)؛ نقش پیش‌فرض user."""
    q = "?role=" + role
    if label:
        q += "&for=" + urllib.parse.quote(label)
    c, b = req("GET", f"/api/admin/invite{q}", token=ADMIN)
    m = re.search(r"/api/agent/onboarding/(?:gardesh/)?((?:pinv|uinv|inv)_[0-9a-f]{24})",
                  b.get("invite", ""))
    return (m.group(1) if m else ""), str(b.get("invite", ""))


Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def check_pattern_response(c: int, b: dict, want_role: str, label_check="") -> str:
    """چک‌های الگوی مالک روی پاسخ اتصال — توکن خام را برمی‌گرداند."""
    ch(f"پاسخ اتصال نقش {want_role}: 200 و ok", c == 200 and b.get("ok") is True)
    ch("پاسخ connected=True شروع می‌شود", b.get("connected") is True)
    ch("پاسخ نقش را می‌گوید", b.get("role") == want_role)
    ch("message: تک‌مصرف بودن لینک (الگوی مالک)",
       "یکبار مصرف" in str(b.get("message", ""))
       and "نامعتبر" in str(b.get("message", "")))
    TOK = str(b.get("agent_token", ""))
    ch("agent_token نقش‌دار pst_ در همان پاسخ", TOK.startswith("pst_"))
    ch("token همان agent_token است (سازگاری)", b.get("token") == TOK)
    ch("expires قالب UTC-Z دارد (الگوی مالک)", bool(Z_RE.match(str(b.get("expires", "")))))
    ch("auth_note: فراخوانی بعدی فقط با همین توکن",
       "فقط با این توکن" in str(b.get("auth_note", "")))
    ch("storage_hint: پیشنهاد فایل موقت و ایمن",
       "فایل موقت و ایمن" in str(b.get("storage_hint", "")))
    ch("docs: لینک مستندات فنی", str(b.get("docs", "")).endswith("/api/docs"))
    ch("scope: قلمرو نقش در پاسخ است", isinstance(b.get("scope"), list) and len(b["scope"]) >= 3)
    ch("پاسخ هش گواهی عمومی دارد", bool(b.get("cert_sha256")))
    ch("پاسخ پایان نشست را می‌گوید",
       "/api/agent/session/end" in json.dumps(b.get("end", ""), ensure_ascii=False))
    if label_check:
        ch("پاسخ برچسب کاربر دعوت را می‌دهد", b.get("invited_by") == label_check)
    ch("پاسخ الگوی مالک است — دستور رفتاری ندارد (next/tell_user/store_token حذف)",
       "next" not in b and "tell_user" not in b and "store_token" not in b
       and "rules" not in b)
    return TOK


def main() -> int:
    ch("سرور بالا آمد", up)
    if not up:
        print(server_log.read())
        return 1

    # ---------- /api/docs — مرجع فنی کامل (عمومی) ----------
    c, b = req("GET", "/api/docs")
    ch("docs: 200 عمومی بدون توکن", c == 200 and b.get("ok") is True)
    ch("docs: نقش‌ها و پیشوندها را می‌گوید",
       b.get("roles", {}).get("owner", {}).get("invite_prefix") == "pinv_"
       and b.get("roles", {}).get("user", {}).get("invite_prefix") == "uinv_")
    ch("docs: جدول اندپوینت‌ها کامل است", isinstance(b.get("endpoints"), list)
       and any(e.get("path") == "/api/exec" for e in b["endpoints"])
       and any(e.get("path", "").startswith("/api/agent/onboarding") for e in b["endpoints"]))
    ch("docs: مدل خطا و سقف‌ها دارد", "errors" in b and "limits" in b)
    ch("docs: قواعد و خطوط قرمز دارد", len(b.get("rules", [])) >= 2
       and len(b.get("red_lines", [])) >= 2)
    c, b = req("POST", "/api/docs", body={})
    ch("POST /api/docs → 405", c == 405)

    # ---------- سند آشناسازی بدون iid ----------
    c, b = req("GET", "/api/agent/onboarding")
    ch("onboarding بدون iid → 200 و invite_required=True",
       c == 200 and b.get("invite_required") is True)
    ch("onboarding بدون iid → connected=False", b.get("connected") is False)
    ch("onboarding: قالب gardesh و پیشوندها را معرفی می‌کند",
       "gardesh/pinv_" in str(b.get("how_to_connect", ""))
       and "gardesh/uinv_" in str(b.get("how_to_connect", "")))
    ch("onboarding: لینک مستندات دارد", str(b.get("docs", "")).endswith("/api/docs"))
    ch("onboarding: هیچ توکنی در پاسخ نیست",
       "pst_" not in json.dumps(b) and "adm_" not in json.dumps(b))
    c, b = req("POST", "/api/agent/onboarding", body={})
    ch("POST روی onboarding → 405", c == 405)
    c, b = req("POST", "/api/agent/onboarding/gardesh/pinv_" + "0" * 24, body={})
    ch("POST روی قالب gardesh → 405 (فقط GET)", c == 405)
    c, b = req("GET", "/api/agent/onboarding/gardesh/")
    ch("GET /api/agent/onboarding/gardesh/ (بدون iid) → سند کوتاه 200",
       c == 200 and b.get("connected") is False)

    # ---------- iid غلط → 404 ----------
    c, b = req("GET", "/api/agent/onboarding/gardesh/pinv_deadbeef" + "0" * 16)
    ch("iid غلط روی gardesh → 404 unknown_invite",
       c == 404 and b.get("error") == "unknown_invite")
    c, b = req("GET", "/api/agent/onboarding/inv_deadbeef" + "0" * 16)
    ch("iid غلط روی قالب ساده → 404 unknown_invite",
       c == 404 and b.get("error") == "unknown_invite")
    ch("خطای iid: توضیح فارسی یک‌خطی (دعوت تازه از مالک)",
       "دعوت" in str(b.get("detail", "")) and "مالک" in str(b.get("detail", "")))

    # ---------- مسیرهای بازنشسته → 404 ----------
    for path in ("/api/agent/claim", "/api/agent/claim/poll", "/api/agent/onboard"):
        c, b = req("POST", path, body={"x": 1})
        ch(f"POST {path} (بازنشسته) → 404 not_found",
           c == 404 and b.get("error") == "not_found")

    # ---------- دعوت‌نامهٔ مالک (pinv_) از اپ/ادمین ----------
    c, b = req("GET", "/api/admin/invite?role=owner")
    ch("invite بدون توکن → 401", c == 401)  # noqa — متغیر b دوباره استفاده می‌شود
    c, b = req("GET", "/api/admin/invite?role=owner", token=AGENT)
    ch("invite با توکن عامل → 403", c == 403)
    c, b = req("GET", "/api/admin/invite?role=owner&for=" + urllib.parse.quote("مهنامالک"),
               token=ADMIN)
    ch("invite مالک با role=owner → 200", c == 200 and b.get("ok") is True)
    ch("invite مالک: role=owner در JSON پاسخ", b.get("role") == "owner")
    inv_txt = str(b.get("invite", ""))
    ch("invite: متن دقیقاً یک خط به الگوی مالک است",
       inv_txt.count("\n") == 0
       and inv_txt.startswith("لطفا با api من یک اتصال پایدار ایجاد کنید: https://"))
    ch("invite مالک: URL روی قالب gardesh/pinv_ است",
       "https://203.0.113.7:9999/api/agent/onboarding/gardesh/pinv_" in inv_txt)
    m = re.search(r"/api/agent/onboarding/gardesh/(pinv_[0-9a-f]{24})$", inv_txt)
    ch("invite مالک: فقط iid در انتهای URL", bool(m))
    OWNER_IID = m.group(1) if m else ""
    ch("invite مالک: هیچ کد/توکن/هش اضافه ندارد",
       "pst_" not in inv_txt and "adm_" not in inv_txt and "SHA" not in inv_txt)
    ch("invite: JSON برچسب و انقضا را جدا می‌دهد",
       b.get("invited_by") == "مهنامالک" and bool(b.get("expires")))

    # ---------- عامل مالک: GET با pinv_ → توکن نقش‌دار مستقیم ----------
    c, b = req("GET", f"/api/agent/onboarding/gardesh/{OWNER_IID}")
    OTOK = check_pattern_response(c, b, "owner", "مهنامالک")

    # نقش مالک: قلمرو کامل
    c, b = req("GET", "/api/status", token=OTOK)
    ch("مالک: status کامل 200", c == 200 and "parastoo_install_path" in b)
    c, b = req("POST", "/api/exec", token=OTOK, body={"cmd": "echo owner-ok"})
    ch("مالک: exec مجاز 200", c == 200 and b.get("exit_code") == 0)
    c, b = req("POST", "/api/github/token", token=OTOK, body={"purpose": "test"})
    ch("مالک: توکن گیت‌هاب از گارد نقش رد می‌شود (خطا اگر باشد، 403 نیست)",
       c != 403 and b.get("error") != "agent_scope_forbidden")
    c, b = req("GET", "/api/admin/audit", token=OTOK)
    ch("مالک: مسیر ادمین → 403 (نشست، هر نقشی، ادمین نیست)", c == 403)

    # یک دعوت = یک عامل
    c, b = req("GET", f"/api/agent/onboarding/gardesh/{OWNER_IID}")
    ch("GET دوباره با همان pinv_ → 404 (یک دعوت = یک عامل)",
       c == 404 and b.get("error") == "unknown_invite")

    # ---------- دعوت کاربر (uinv_) ----------
    U_IID, U_TXT = get_invite("رضا", role="user")
    ch("invite کاربر: uinv_ روی gardesh",
       U_IID.startswith("uinv_") and "/onboarding/gardesh/uinv_" in U_TXT)
    # قالب ساده هم باید همان iid را قبول کند (آزادی پارسر)
    c, b = req("GET", f"/api/agent/onboarding/{U_IID}")
    ch("uinv_ روی قالب ساده هم پذیرفته می‌شود (پارسر آزاد)", c == 200 and b.get("ok") is True)
    UTOK = check_pattern_response(c, b, "user", "رضا")

    # نقش کاربر: قلمرو محدود
    c, b = req("GET", "/api/status", token=UTOK)
    ch("کاربر: status فیلترشده 200 (بدون مسیرهای داخلی)",
       c == 200 and "parastoo_install_path" not in b and "docker_path" not in b
       and "github_token_stored" not in b and "hostname" not in b)
    ch("کاربر: status فیلترشده سنجه‌های عمومی را دارد",
       "disk_percent" in b and "mem_avail_mb" in b and "version" in b)
    c, b = req("POST", "/api/exec", token=UTOK, body={"cmd": "echo user-nope"})
    ch("کاربر: exec → 403 agent_scope_forbidden",
       c == 403 and b.get("error") == "agent_scope_forbidden")
    c, b = req("POST", "/api/github/token", token=UTOK, body={"purpose": "x"})
    ch("کاربر: توکن گیت‌هاب → 403 agent_scope_forbidden",
       c == 403 and b.get("error") == "agent_scope_forbidden")
    c, b = req("POST", "/api/admin/revoke-agent-sessions", token=UTOK, body={})
    ch("کاربر: مسیر ادمین → 403", c == 403)
    c, b = req("POST", "/api/agent/session/end", token=UTOK, body={})
    ch("کاربر: پایان نشست خودش 200", c == 200 and b.get("session_removed") is True)
    c, b = req("GET", "/api/status", token=UTOK)
    ch("کاربر: توکن پس از پایان → 401", c == 401)

    # ---------- دعوت قدیمی inv_ (سازگاری) — لایهٔ واحد ----------
    HOME2 = tempfile.mkdtemp(prefix="access-agent-onboard2.")
    real_home = os.environ["ACCESS_AGENT_HOME"]
    os.environ["ACCESS_AGENT_HOME"] = HOME2
    from access_agent import security as S
    try:
        iid_old, _ = S.mint_invite("legacy", ttl_s=3600, role="agent")
        ch("دعوت قدیمی inv_ ساخته می‌شود (سازگاری)",
           iid_old.startswith("inv_") and INVITE_ROLE_PREFIXES["agent"] == "inv_")
        r_old = S.claim_invite_session(iid_old, ip="10.1.1.2")
        ch("دعوت inv_: توکن قدیمی aagx_ با نقش agent",
           r_old.get("ok") is True and r_old.get("token", "").startswith("aagx_")
           and r_old.get("role") == "agent")
        ch("دعوت inv_: انقضای UTC-Z دارد", bool(Z_RE.match(str(r_old.get("expires", "")))))
        ch("check_agent_session توکن قدیمی را می‌پذیرد",
           check_agent_session(r_old.get("token", "")))
        ch("agent_session_role نقش را از رکورد می‌گوید",
           S.agent_session_role(r_old.get("token", "")) == "agent")

        # نقش‌ها و توابع پایه
        ch("برچسب بلند → sanitize به خالی", S.sanitize_invite_label("x" * 41) == "")
        ch("برچسب فارسی مجاز است", S.sanitize_invite_label("  رضا ") == "رضا")
        stats = S.live_invite_stats()
        ch("آمار دعوت زنده بدون مقدار است", set(stats) == {"live", "labeled"})
        raw2, _ = mint_agent_session(ttl_s=60)
        ch("نشست مستقل معتبر است", check_agent_session(raw2))
        ch("ابطال نشست درست True می‌دهد", revoke_agent_session(raw2))
        ch("ابطال نشست غلط False می‌دهد",
           not revoke_agent_session("pst_" + "f" * 48))

        # TTL نقش‌ها
        now_t = time.time()
        raw_o, rec_o = mint_agent_session(ttl_s=S.SESSION_TTL_MAX_S, role="owner")
        ch("مالک: TTL تا ۳۰ روز صادر می‌شود",
           rec_o.get("role") == "owner"
           and abs(float(rec_o.get("expires_ts", 0)) - now_t - S.OWNER_SESSION_TTL_S) < 120)
        raw_u, rec_u = mint_agent_session(ttl_s=S.USER_SESSION_TTL_S, role="user")
        ch("کاربر: نشست با TTL ۲۴ ساعت صادر می‌شود",
           rec_u.get("role") == "user"
           and abs(float(rec_u.get("expires_ts", 0)) - time.time() - S.USER_SESSION_TTL_S) < 120)
        ch("نقش نامعتبر → user (محافظه‌کار)", S.normalize_invite_role("hacker") == "user")
        ch("پیشوند نقش: pinv_→owner، uinv_→user",
           S.role_of_iid("pinv_x") == "owner" and S.role_of_iid("uinv_x") == "user")

        # نرخ‌سنجی خطای iid: فقط ناموفق‌ها شمرده می‌شوند
        iidX, _ = S.mint_invite("t", ttl_s=3600)
        old_w, old_m = S.ONBOARD_FAIL_WINDOW_S, S.ONBOARD_FAIL_MAX
        S.ONBOARD_FAIL_WINDOW_S = 3600
        S.ONBOARD_FAIL_MAX = 3
        try:
            r429 = None
            for i in range(4):
                r429 = S.claim_invite_session("uinv_" + f"{i:024x}", ip="10.1.1.1")
            ch("نرخ‌سنجی: خطای چهارم از همان IP → rate_limited",
               r429.get("error") == "rate_limited" and r429.get("status") == 429)
            r_ok = S.claim_invite_session(iidX, ip="10.1.1.1")
            ch("نرخ‌سنجی: دعوت معتبر همچنان جواب می‌دهد",
               r_ok.get("ok") is True and r_ok.get("token", "").startswith("pst_"))
            r_again = S.claim_invite_session(iidX, ip="10.1.1.9")
            ch("تک‌مصرف: فراخوانی دوبارهٔ همان دعوت → 404",
               r_again.get("ok") is False and r_again.get("status") == 404)
        finally:
            S.ONBOARD_FAIL_WINDOW_S, S.ONBOARD_FAIL_MAX = old_w, old_m
        S._ONBOARD_FAIL_RATE.clear()
        for i in range(600):
            S._ONBOARD_FAIL_RATE[f"10.5.5.{i}"] = [0.0]
        r_bad = S.claim_invite_session("pinv_" + "b" * 24, ip="10.9.9.8")
        ch("جاروی نرخ: کهنه‌ها حذف و خطای تازه پاسخ گرفت",
           r_bad.get("error") == "unknown_invite"
           and len(S._ONBOARD_FAIL_RATE) < 100)
    finally:
        os.environ["ACCESS_AGENT_HOME"] = real_home

    # ---------- فقط هش روی دیسک ----------
    invites_txt = (Path(TMP) / "invites.json").read_text(encoding="utf-8")
    sess_txt = (Path(TMP) / "agent_sessions.json").read_text(encoding="utf-8")
    ch("روی دیسک فقط هش است (iid/توکن خام نیست)",
       OWNER_IID not in invites_txt and OWNER_IID not in sess_txt
       and OTOK not in sess_txt and UTOK not in sess_txt)
    data = json.loads(invites_txt)
    used_recs = [i for i in data["invites"] if i.get("used")]
    ch("دیسک: رکورد مصرف با claims=1 و نقش ثبت‌شده",
       bool(used_recs) and all(int(i.get("claims", 0) or 0) == 1 for i in used_recs)
       and any(i.get("role") in ("owner", "user") for i in used_recs))

    # ---------- کلید اضطراری مالک ----------
    IID4, _ = get_invite("sara", role="user")
    c, b = req("GET", f"/api/agent/onboarding/gardesh/{IID4}")
    TOK2 = b.get("agent_token", "")
    ch("اتصال سوم (sara) مستقیم موفق", TOK2.startswith("pst_"))
    sess_txt2 = (Path(TMP) / "agent_sessions.json").read_text(encoding="utf-8")
    ch("دیسک: نشست‌های زنده نقش دارند (مالک + کاربر)",
       '"owner"' in sess_txt2 and '"user"' in sess_txt2)
    ch("دیسک: هیچ توکن خام در رکورد نشست نیست", OTOK not in sess_txt2 and TOK2 not in sess_txt2)
    c, b = req("POST", "/api/admin/revoke-agent-sessions", token=ADMIN, body={})
    ch("ابطال همهٔ نشست‌ها → removed>=1", c == 200 and b.get("removed", 0) >= 1)
    c, b = req("GET", "/api/status", token=TOK2)
    ch("توکن ابطال‌شده → 401", c == 401)
    c, b = req("GET", "/api/status", token=OTOK)
    ch("توکن مالک هم ابطال شد (کلید اضطراری همه را می‌کشد)", c == 401)

    # ---------- audit: رویدادها هست، مقدار iid/توکن هرگز ----------
    al = (Path(TMP) / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    for ev in ("agent_onboarding_read", "agent_onboarding_granted",
               "agent_onboarding_refused", "admin_invite_served",
               "admin_revoke_agent_sessions", "agent_scope_forbidden",
               "status_filtered_role", "api_docs_read"):
        ch(f"audit: {ev} ثبت شده", ev in al)
    ch("audit: مقدار iid هرگز لاگ نشده", OWNER_IID not in al)
    ch("audit: مقدار توکن هرگز لاگ نشده", OTOK not in al and UTOK not in al and TOK2 not in al)
    ch("audit: برچسب کاربر (غیرمخفی) هست", "رضا" in al)

    # ---------- core-config: نقشهٔ اندپوینت‌های تازه ----------
    c, b = req("GET", "/api/admin/app/core-config", token=ADMIN)
    cfg_json = b.get("config_json", "")
    ch("core-config: docs در نقشه است", '"/api/docs"' in cfg_json)
    ch("core-config: agent_approve حذف شده",
       "/api/admin/agent-approve" not in cfg_json)
    ch("core-config: revision 6 است",
       b.get("revision") == appcore.DEFAULT_PAYLOAD["revision"] == 6)

    # ---------- سند onboarding مستقیم (بدون شبکه) ----------
    doc = onboarding_doc()
    ch("onboarding_doc: کوتاه و invite_required",
       doc["invite_required"] is True and "trust_model" not in doc)
    ch("onboarding_doc: قواعد دوردیفه", len(doc["rules"]) == 2)
    ch("onboarding_doc: docs دارد و hint بدون-iid",
       str(doc.get("docs", "")).endswith("/api/docs")
       and "بدون iid" in str(doc.get("note", "")))
    # build_invite — قالب gardesh + پورت رایج
    ch("build_invite: یک خط با متن الگوی مالک",
       build_invite("pinv_" + "a" * 24).count("\n") == 0
       and build_invite("pinv_" + "a" * 24).startswith(
           "لطفا با api من یک اتصال پایدار ایجاد کنید: https://"))
    ch("build_invite: pinv_/uinv_ روی gardesh و inv_ روی قالب ساده",
       build_invite("pinv_" + "a" * 24).endswith("/api/agent/onboarding/gardesh/pinv_" + "a" * 24)
       and build_invite("uinv_" + "a" * 24).endswith("/api/agent/onboarding/gardesh/uinv_" + "a" * 24)
       and build_invite("inv_" + "a" * 24).endswith("/api/agent/onboarding/inv_" + "a" * 24))
    # پورت 443 → بدون :443 (config تست پورت 9999 دارد؛ جدا می‌سازیم)
    (Path(TMP) / "config.json").write_text(json.dumps({
        "ip": "203.0.113.7", "port": 443, "version": "0.10.0",
    }), encoding="utf-8")
    ch("build_invite: پورت 443 هرگز در URL نمی‌آید (پورت رایج)",
       "https://203.0.113.7/api/agent/onboarding/gardesh/pinv_" in build_invite("pinv_" + "a" * 24)
       and ":443" not in build_invite("pinv_" + "a" * 24))
    (Path(TMP) / "config.json").write_text(json.dumps({
        "ip": "203.0.113.7", "port": 9999, "version": "0.10.0",
    }), encoding="utf-8")
    # host دامنه‌ای → URL با دامنه (دعوت کاربر پس از استقرار دامنه)
    (Path(TMP) / "config.json").write_text(json.dumps({
        "ip": "203.0.113.7", "port": 443, "host": "panel.example.ir",
        "version": "0.10.0",
    }), encoding="utf-8")
    ch("build_invite: host ثبت‌شده بر ip غالب است (الگوی دعوت کاربر با دامنه)",
       build_invite("uinv_" + "a" * 24).startswith(
           "لطفا با api من یک اتصال پایدار ایجاد کنید: https://panel.example.ir/"))
    (Path(TMP) / "config.json").write_text(json.dumps({
        "ip": "203.0.113.7", "port": 9999, "version": "0.10.0",
    }), encoding="utf-8")

    teardown()
    print(f"\n# جمع‌بندی: {GREEN}{n_pass} سبز{NC}، {RED}{n_fail} قرمز{NC}")
    if failures:
        print("# شکست‌ها:")
        for f in failures:
            print(f"  - {f}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
