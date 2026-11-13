#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی v0.9 — اتصال مستقیم با دعوت‌نامه (حذف تشریفات، فرمان مالک ۲۰۲۶-۱۱-۱۳).

جریان کامل، از نگاه هر دو طرف:
  مالک:  GET /api/admin/invite?for=<کاربر> ← دعوت‌نامهٔ یک‌خطی:
         «لطفا این لینک را دنبال کنید: https://…/api/agent/onboarding?iid=inv_…»
  عامل:  GET /api/agent/onboarding?iid=<iid> ← مستقیماً توکن موقت aagx_ +
         انقضا + راهنمای کوتاه؛ نه رمز، نه claim، نه poll
         → GET /api/status → POST /api/agent/session/end در پایان مکالمه

قرمزها: iid غلط/مصرف‌شده/منقضی، یک دعوت = یک عامل، نرخ‌سنجی خطای iid،
مسیرهای بازنشسته (claim/claim-poll/onboard/agent-approve → 404)، فقط هش روی
دیسک، audit بدون مقدار iid/توکن، core-config بدون agent_approve.

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
                                   mint_agent_session, revoke_agent_session)

ADMIN = "adm_" + os.urandom(24).hex()
AGENT = "aa_" + os.urandom(24).hex()   # توکن بلندمدت برای تست 403
(Path(TMP) / "tokens.json").write_text(json.dumps({
    "admin_sha": hashlib.sha256(ADMIN.encode()).hexdigest(),
    "agent_sha": hashlib.sha256(AGENT.encode()).hexdigest(),
}), encoding="utf-8")
(Path(TMP) / "config.json").write_text(json.dumps({
    "ip": "203.0.113.7", "port": 9999, "version": "0.9.0",
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


def get_invite(label: str = "") -> str:
    q = "?for=" + urllib.parse.quote(label) if label else ""
    c, b = req("GET", f"/api/admin/invite{q}", token=ADMIN)
    m = re.search(r"\?iid=(inv_[0-9a-f]{24})", b.get("invite", ""))
    return m.group(1) if m else ""


def main() -> int:
    ch("سرور بالا آمد", up)
    if not up:
        print(server_log.read())
        return 1

    # ---------- سند آشناسازی بدون iid: کوتاه ----------
    c, b = req("GET", "/api/agent/onboarding")
    ch("onboarding بدون iid → 200 و پروتکل 0.9.0",
       c == 200 and b.get("protocol") == "onboarding/0.9.0")
    ch("onboarding بدون iid → invite_required=True",
       b.get("invite_required") is True)
    ch("onboarding: هیچ توکنی در پاسخ نیست",
       "aagx_" not in json.dumps(b) and "adm_" not in json.dumps(b))
    ch("onboarding: سند کوتاه است (بدون trust_model/session_flow)",
       "trust_model" not in b and "session_flow" not in b
       and "reading_order" not in b and "fallback_owner_code" not in b)
    ch("onboarding: قواعد کوتاه دارد",
       len(b.get("rules", [])) == 2
       and any("تخریبی" in r for r in b.get("rules", [])))
    doc_s = json.dumps(b, ensure_ascii=False)
    ch("onboarding: مسیر iid را می‌گوید", "iid=" in doc_s)
    c, b = req("POST", "/api/agent/onboarding", body={})
    ch("POST روی onboarding → 405", c == 405)

    # ---------- iid غلط → 404 ----------
    c, b = req("GET", "/api/agent/onboarding?iid=inv_deadbeef" + "0" * 16)
    ch("onboarding با iid غلط → 404 unknown_invite",
       c == 404 and b.get("error") == "unknown_invite")
    ch("onboarding با iid غلط: بدون جزئیات چت", "detail" in b)

    # ---------- مسیرهای بازنشسته → 404 ----------
    for path in ("/api/agent/claim", "/api/agent/claim/poll",
                 "/api/agent/onboard"):
        c, b = req("POST", path, body={"x": 1})
        ch(f"POST {path} (بازنشسته) → 404 not_found",
           c == 404 and b.get("error") == "not_found")
    c, b = req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": "12345"})
    ch("POST /api/admin/agent-approve (بازنشسته) → 404", c == 404)

    # ---------- دعوت‌نامهٔ یک‌خطی از اپ/ادمین ----------
    c, b = req("GET", "/api/admin/invite")
    ch("invite بدون توکن → 401", c == 401)
    c, b = req("GET", "/api/admin/invite", token=AGENT)
    ch("invite با توکن عامل → 403", c == 403)
    c, b = req("GET", "/api/admin/invite?for=" + urllib.parse.quote("رضا"), token=ADMIN)
    ch("invite ادمین با for=رضا → 200", c == 200 and b.get("ok") is True)
    inv = str(b.get("invite", ""))
    ch("invite: متن دقیقاً یک خط است",
       inv.count("\n") == 0 and inv.startswith("لطفا این لینک را دنبال کنید: "))
    ch("invite: URL کامل با iid دارد",
       "https://203.0.113.7:9999/api/agent/onboarding?iid=inv_" in inv)
    m = re.search(r"\?iid=(inv_[0-9a-f]{24})$", inv)
    ch("invite: فقط iid در URL (بدون هیچ چیز دیگر)", bool(m))
    IID = m.group(1) if m else ""
    ch("invite: هیچ کد/توکن/هش اضافه ندارد",
       "ob_" not in inv and "adm_" not in inv and "aclsk_" not in inv
       and "SHA" not in inv and "aagx_" not in inv)
    ch("invite: JSON برچسب کاربر و انقضا را جدا می‌دهد",
       b.get("invited_by") == "رضا" and bool(b.get("expires")))

    # ---------- عامل: GET با iid → توکن مستقیم (بدون رمز/claim/poll) ----------
    c, b = req("GET", f"/api/agent/onboarding?iid={IID}")
    ch("onboarding با iid معتبر → 200", c == 200 and b.get("ok") is True)
    TOK = str(b.get("token", ""))
    ch("توکن مستقیم aagx_ در همان پاسخ", TOK.startswith("aagx_"))
    ch("agent_token همان توکن است (سازگاری)", b.get("agent_token") == TOK)
    ch("پاسخ برچسب کاربر دعوت را می‌دهد", b.get("invited_by") == "رضا")
    ch("پاسخ انقضا دارد", bool(b.get("expires")))
    ch("پاسخ هش گواهی عمومی دارد", bool(b.get("cert_sha256")))
    ch("پاسخ پروتکل 0.9.0 دارد", b.get("protocol") == "onboarding/0.9.0")
    ch("پاسخ گام بعدی و پایان را می‌گوید",
       "/healthz" in str(b.get("next", "")) and
       "/api/agent/session/end" in json.dumps(b.get("end", ""), ensure_ascii=False))
    ch("پاسخ قواعد کوتاه دارد", len(b.get("rules", [])) == 2)
    ch("پاسخ هیچ pairing/claim/code ندارد",
       "pairing" not in b and "code" not in b and "claim_id" not in b)
    ch("پاسخ کوتاه است (بدون سند بلند)",
       "trust_model" not in b and "session_flow" not in b)

    # ---------- فقط هش روی دیسک ----------
    invites_txt = (Path(TMP) / "invites.json").read_text(encoding="utf-8")
    sess_txt = (Path(TMP) / "agent_sessions.json").read_text(encoding="utf-8")
    ch("روی دیسک فقط هش است (iid/توکن خام نیست)",
       IID not in invites_txt and IID not in sess_txt and TOK not in sess_txt
       and "aclsk_" not in sess_txt)

    # ---------- یک دعوت = یک عامل ----------
    c, b = req("GET", f"/api/agent/onboarding?iid={IID}")
    ch("GET دوباره با همان iid → 404 (یک دعوت = یک عامل)",
       c == 404 and b.get("error") == "unknown_invite")

    # ---------- رکورد نشست: origin=invite + invited_by ----------
    ch("نشست origin=invite دارد", '"invite"' in sess_txt)
    ch("نشست برچسب invited_by دارد", "رضا" in sess_txt)

    # ---------- توکن مثل عامل رفتار می‌کند ----------
    c, b = req("GET", "/api/status", token=TOK)
    ch("status با توکن مستقیم 200", c == 200 and b.get("ok"))
    c, b = req("GET", "/api/admin/audit", token=TOK)
    ch("توکن روی مسیر ادمین → 403", c == 403)
    c, b = req("POST", "/api/exec", token=TOK, body={"cmd": "echo direct-ok"})
    ch("exec با توکن مستقیم 200", c == 200 and b.get("exit_code") == 0)
    ch("check_agent_session در واحد تایید می‌کند", check_agent_session(TOK))
    c, b = req("GET", "/api/status", token=ADMIN)
    ch("ادمین همچنان superset است", c == 200)

    # ---------- پایان مکالمه ----------
    c, b = req("POST", "/api/agent/session/end", token=TOK, body={})
    ch("پایان نشست 200 و session_removed",
       c == 200 and b.get("session_removed") is True)
    c, b = req("GET", "/api/status", token=TOK)
    ch("توکن پس از پایان → 401", c == 401)
    c, b = req("POST", "/api/agent/session/end", token=ADMIN, body={})
    ch("ادمین بدون نشست → پایان بی‌ضرر", c == 200 and b.get("session_removed") is False)

    # ---------- دعوت بدون برچسب (خودِ مالک) ----------
    IID2 = get_invite()
    c, b = req("GET", f"/api/agent/onboarding?iid={IID2}")
    ch("دعوت بدون برچسب هم توکن مستقیم می‌دهد (invited_by خالی)",
       c == 200 and b.get("token", "").startswith("aagx_")
       and b.get("invited_by", "x") == "")

    # ---------- دعوت منقضی → 404 ----------
    IID3 = get_invite("t")
    data = json.loads((Path(TMP) / "invites.json").read_text(encoding="utf-8"))
    for inv_rec in data["invites"]:
        if inv_rec.get("invited_by") == "t" and not inv_rec.get("used"):
            inv_rec["expires_ts"] = time.time() - 1
    (Path(TMP) / "invites.json").write_text(json.dumps(data), encoding="utf-8")
    c, b = req("GET", f"/api/agent/onboarding?iid={IID3}")
    ch("دعوت منقضی → 404 unknown_invite",
       c == 404 and b.get("error") == "unknown_invite")

    # ---------- ttl_h خارج از محدوده → محدود می‌شود ----------
    c, b = req("GET", "/api/admin/invite?for=x&ttl_h=99999", token=ADMIN)
    exp_ts = 0.0
    try:
        from datetime import datetime
        exp_ts = datetime.fromisoformat(str(b.get("expires", ""))).timestamp()
    except Exception:
        pass
    ch("ttl_h=99999 → به ۱۶۸ ساعت محدود شد",
       c == 200 and time.time() + 167 * 3600 <= exp_ts <= time.time() + 169 * 3600)

    # ---------- کلید اضطراری مالک: ابطال همهٔ نشست‌ها ----------
    IID4 = get_invite("sara")
    c, b = req("GET", f"/api/agent/onboarding?iid={IID4}")
    TOK2 = b.get("token", "")
    ch("اتصال سوم (sara) مستقیم موفق", TOK2.startswith("aagx_"))
    c, b = req("POST", "/api/admin/revoke-agent-sessions", token=ADMIN, body={})
    ch("ابطال همهٔ نشست‌ها → removed>=1", c == 200 and b.get("removed", 0) >= 1)
    c, b = req("GET", "/api/status", token=TOK2)
    ch("توکن ابطال‌شده → 401", c == 401)
    c, b = req("POST", "/api/admin/revoke-agent-sessions", token=AGENT, body={})
    ch("عامل نمی‌تواند نشست‌ها را ابطال کند → 403", c == 403)

    # ---------- audit: رویدادها هست، مقدار iid/توکن هرگز ----------
    al = (Path(TMP) / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    for ev in ("agent_onboarding_read", "agent_onboarding_granted",
               "agent_onboarding_refused", "admin_invite_served",
               "admin_revoke_agent_sessions"):
        ch(f"audit: {ev} ثبت شده", ev in al)
    ch("audit: مقدار iid هرگز لاگ نشده", IID not in al and IID2 not in al)
    ch("audit: مقدار توکن هرگز لاگ نشده", TOK not in al and TOK2 not in al)
    ch("audit: برچسب کاربر (غیرمخفی) هست", "رضا" in al)

    # ---------- core-config: نقشهٔ اندپوینت‌های تازه ----------
    c, b = req("GET", "/api/admin/app/core-config", token=ADMIN)
    cfg_json = b.get("config_json", "")
    ch("core-config: agent_invite در نقشه است", "/api/admin/invite" in cfg_json)
    ch("core-config: agent_approve حذف شده",
       "/api/admin/agent-approve" not in cfg_json)
    ch("core-config: revision 5 است",
       b.get("revision") == appcore.DEFAULT_PAYLOAD["revision"] == 5)

    # ---------- لایهٔ واحد (خانهٔ دوم): برچسب، آمار، نشست مستقل ----------
    HOME2 = tempfile.mkdtemp(prefix="access-agent-onboard2.")
    real_home = os.environ["ACCESS_AGENT_HOME"]
    os.environ["ACCESS_AGENT_HOME"] = HOME2
    from access_agent import security as S
    try:
        ch("برچسب بلند → sanitize به خالی",
           S.sanitize_invite_label("x" * 41) == "")
        ch("برچسب با نویسهٔ کنترلی → خالی",
           S.sanitize_invite_label("a\tb") == "")
        ch("برچسب فارسی مجاز است", S.sanitize_invite_label("  رضا ") == "رضا")
        stats = S.live_invite_stats()
        ch("آمار دعوت زنده بدون مقدار است",
           set(stats) == {"live", "labeled"})
        raw2, _ = mint_agent_session(ttl_s=60)
        ch("نشست دوم مستقل معتبر است", check_agent_session(raw2))
        ch("ابطال نشست غلط False می‌دهد",
           not revoke_agent_session("aagx_" + "f" * 48))
        ch("ابطال نشست درست True می‌دهد", revoke_agent_session(raw2))
        ch("نشست دوم پس از ابطال مرده است", not check_agent_session(raw2))

        # نرخ‌سنجی خطای iid: فقط ناموفق‌ها شمرده می‌شوند؛ پنجرهٔ کوتاه تست
        iidX, _ = S.mint_invite("t", ttl_s=3600)
        old_w, old_m = S.ONBOARD_FAIL_WINDOW_S, S.ONBOARD_FAIL_MAX
        S.ONBOARD_FAIL_WINDOW_S = 3600
        S.ONBOARD_FAIL_MAX = 3
        try:
            r429 = None
            for i in range(4):
                r429 = S.claim_invite_session("inv_" + f"{i:024x}", ip="10.1.1.1")
            ch("نرخ‌سنجی: خطای چهارم از همان IP → rate_limited",
               r429.get("error") == "rate_limited" and r429.get("status") == 429)
            r_ok = S.claim_invite_session(iidX, ip="10.1.1.1")
            ch("نرخ‌سنجی: دعوت معتبر همچنان جواب می‌دهد (فقط خطا شمرده می‌شود)",
               r_ok.get("ok") is True and r_ok.get("token", "").startswith("aagx_"))
        finally:
            S.ONBOARD_FAIL_WINDOW_S, S.ONBOARD_FAIL_MAX = old_w, old_m
        # جاروی دیکشنری نرخ: با آدرس‌های کهنهٔ بسیار، حافظه بی‌کران نگردد
        S._ONBOARD_FAIL_RATE.clear()
        for i in range(600):
            S._ONBOARD_FAIL_RATE[f"10.5.5.{i}"] = [0.0]   # همه کهنه
        r_bad = S.claim_invite_session("inv_" + "b" * 24, ip="10.9.9.8")
        ch("جاروی نرخ: کهنه‌ها حذف و خطای تازه پاسخ گرفت",
           r_bad.get("error") == "unknown_invite"
           and len(S._ONBOARD_FAIL_RATE) < 100)
        ch("جاروی نرخ: آدرس درخواست‌کننده در دیکشنری مانده",
           "10.9.9.8" in S._ONBOARD_FAIL_RATE)
    finally:
        os.environ["ACCESS_AGENT_HOME"] = real_home

    # ---------- سند onboarding مستقیم (بدون شبکه) ----------
    doc = onboarding_doc()
    ch("onboarding_doc: کوتاه و invite_required",
       doc["invite_required"] is True and "trust_model" not in doc)
    ch("onboarding_doc: قواعد دوردیفه", len(doc["rules"]) == 2)
    ch("build_invite: یک خط با قالب مالک",
       build_invite("inv_" + "a" * 24).count("\n") == 0
       and build_invite("inv_" + "a" * 24).startswith("لطفا این لینک را دنبال کنید: https://"))

    teardown()
    print(f"\n# جمع‌بندی: {GREEN}{n_pass} سبز{NC}، {RED}{n_fail} قرمز{NC}")
    if failures:
        print("# شکست‌ها:")
        for f in failures:
            print(f"  - {f}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
