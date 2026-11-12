#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی v0.8 — جفت‌سازی عامل با رمز «سرورساخته» + دعوت کاربر-مند.

جریان کامل، از نگاه هر سه طرف (فرمان مالک 2026-11-12 — بازنگری v0.7.1:
عامل دیگر رمز نمی‌سازد؛ سرور می‌سازد و عامل فقط چاپ می‌کند):
  مالک:  GET /api/admin/invite?for=<کاربر> ← دعوت‌نامهٔ بی‌رمز با URL حامل
         شناسهٔ دعوت (iid) که به نام همان کاربر صادر شده است
  عامل:  GET /api/agent/onboarding?iid=<iid> ← رمز ۵ رقمی یک‌بارمصرفِ
         «سرورساخته» + claim_id + claim_secret (هیچ محاسبه‌ای برای عامل نیست؛
         فقط همان رمز را برای کاربر چاپ می‌کند)
  کاربر: رمز را از مسیر امن اپلیکیشن موبایل برای مالک می‌فرستد
  مالک:  POST /api/admin/agent-approve {code} (پرستو موبایل / SSH) — پاسخ
         برچسب invited_by را می‌دهد تا مالک بداند پای کدام کاربر بوده است
  عامل:  POST /api/agent/claim/poll ← توکن موقت aagx_
         ... کار ... POST /api/agent/session/end

قرمزها: iid غلط/مصرف‌شده، بازنشسته‌شدن مسیر عامل‌ساخته (410)، تأیید غلط،
برداشت دوباره، سقف ادعا، نرخ‌سنجی، انقضای پنجره‌ها، یک دعوت = یک عامل،
audit بدون مقدار رمز/iid/توکن، فقط هش روی دیسک.

اجرا:  python tests/smoke_pairing.py   (کاملاً آفلاین، بدون TLS در تست)
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
TMP = tempfile.mkdtemp(prefix="access-agent-pairing.")
os.environ["ACCESS_AGENT_HOME"] = TMP
os.environ["ACCESS_AGENT_PORT"] = str(PORT)
os.environ["ACCESS_AGENT_NO_TLS"] = "1"

sys.path.insert(0, str(REPO))
from access_agent import security  # noqa: E402

ADMIN = "adm_" + os.urandom(24).hex()
AGENT = "aa_" + os.urandom(24).hex()   # توکن بلندمدت برای تست 403
(Path(TMP) / "tokens.json").write_text(json.dumps({
    "admin_sha": hashlib.sha256(ADMIN.encode()).hexdigest(),
    "agent_sha": hashlib.sha256(AGENT.encode()).hexdigest(),
}), encoding="utf-8")
(Path(TMP) / "config.json").write_text(json.dumps({
    "ip": "203.0.113.7", "port": 9999, "version": "0.8.0",
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


def poll(claim_id: str, secret: str) -> tuple[int, dict]:
    return req("POST", "/api/agent/claim/poll",
               body={"claim_id": claim_id, "claim_secret": secret})


def main() -> int:
    ch("سرور بالا آمد", up)
    if not up:
        print(server_log.read())
        return 1

    # ---------- سند آشناسازی بدون iid: فقط دستورالعمل ----------
    c, b = req("GET", "/api/agent/onboarding")
    ch("onboarding بدون iid → 200 و پروتکل 0.8.1",
       c == 200 and b.get("protocol") == "onboarding/0.8.1")
    ch("onboarding بدون iid → invite_required=True",
       b.get("invite_required") is True)
    ch("onboarding: بدون iid هیچ رمزی نمی‌دهد", "pairing" not in b)
    ch("onboarding: مدل اعتماد شامل pairing و invite است",
       {"pairing", "invite"} <= set(b.get("trust_model", {})))
    sf = b.get("session_flow", {})
    ch("onboarding: جریان get_code/relay/poll دارد",
       {"2_get_code", "3_relay_by_user", "4_poll"} <= set(sf))
    ch("onboarding: get_code → poll در همان نوبت (تک‌پیامی)",
       "قطع نکن" in str(sf.get("2_get_code", {}).get("note", "")))
    ch("onboarding: relay → نتیجه از سرور، نه کاربر",
       "نه کاربر" in str(sf.get("3_relay_by_user", "")))
    ch("onboarding: poll → فیلد token و برداشت تکرارپذیر",
       "فیلد token" in str(sf.get("4_poll", {}).get("note", ""))
       and "تکرارپذیر" in str(sf.get("4_poll", {}).get("note", "")))
    doc_s = json.dumps(b, ensure_ascii=False)
    ch("onboarding: هیچ مقدار توکنی در پاسخ نیست",
       re.search(r"aagx_[0-9a-f]{48}", doc_s) is None
       and "adm_" not in doc_s and "aclsk_" not in doc_s)

    # ---------- iid غلط → 404 ----------
    c, b = req("GET", "/api/agent/onboarding?iid=inv_deadbeef" + "0" * 19)
    ch("onboarding با iid غلط → 404 unknown_invite",
       c == 404 and b.get("error") == "unknown_invite")
    c, b = req("GET", "/api/agent/onboarding?iid=inv_" + "f" * 24 + "&x=y")
    ch("onboarding با iid غلط + پارامتر اضافه → 404", c == 404)

    # ---------- مسیر عامل‌ساخته بازنشسته → 410 ----------
    c, b = req("POST", "/api/agent/claim", body={"code": "82419"})
    ch("POST /api/agent/claim (عامل‌ساخته) → 410 retired",
       c == 410 and b.get("error") == "agent_made_codes_retired")
    c, b = req("POST", "/api/agent/claim", body={"code": "12345"})
    ch("claim عامل‌ساخته با رمز ضعیف هم → 410 (نه weak_code)", c == 410)

    # ---------- دعوت‌نامهٔ کاربر-مند از اپ/ادمین ----------
    c, b = req("GET", "/api/admin/invite")
    ch("invite بدون توکن → 401", c == 401)
    c, b = req("GET", "/api/admin/invite", token=AGENT)
    ch("invite با توکن عامل → 403", c == 403)
    c, b = req("GET", "/api/admin/invite?for=" + urllib.parse.quote("رضا"), token=ADMIN)
    ch("invite ادمین با for=رضا → 200", c == 200 and b.get("ok") is True)
    inv = b.get("invite", "")
    ch("invite: invited_by در پاسخ JSON هست", b.get("invited_by") == "رضا")
    ch("invite: آدرس کامل با آدرس دعوت دارد",
       len(inv) > 200 and "https://203.0.113.7:9999/api/agent/onboarding?iid=inv_" in inv)
    ch("invite: متن سادهٔ v0.8.1 است (بدون برچسب کاربر/نسخه)",
       "سرویس پرستو" in inv and "رضا" not in inv
       and "هش گواهی TLS" in inv and "access-agent" not in inv)
    m = re.search(r"\?iid=(inv_[0-9a-f]{24})", inv)
    ch("invite: شناسهٔ دعوت inv_ با ۲۴ هگز است", bool(m))
    IID = m.group(1) if m else ""
    ch("invite: هیچ کد/توکن واقعی ندارد",
       "ob_" not in inv and "adm_" not in inv and "aclsk_" not in inv
       and re.search(r"aagx_[0-9a-f]{48}", inv) is None
       and re.search(r"aa_[0-9a-f]{48}", inv) is None
       and re.search(r"\?iid=inv_[0-9a-f]{24}", inv) is not None)

    # ---------- عامل: GET با iid → رمز سرورساخته ----------
    c, b = req("GET", f"/api/agent/onboarding?iid={IID}")
    ch("onboarding با iid معتبر → 200", c == 200 and b.get("ok") is True)
    p = b.get("pairing", {})
    CODE = str(p.get("code", ""))
    ch("رمز سرورساخته دقیقاً ۵ رقم ASCII است",
       len(CODE) == 5 and CODE.isascii() and CODE.isdigit())
    ch("پاسخ برچسب کاربر دعوت را می‌دهد", p.get("invited_by") == "رضا")
    ch("پاسخ دستور چاپ بدون محاسبه را می‌دهد",
       "چاپ" in str(p.get("print_for_user", "")))
    ch("پاسخ دستور چاپ، poll در همان نوبت را هم می‌گوید",
       "claim/poll" in str(p.get("print_for_user", ""))
       and "قطع" in str(p.get("print_for_user", "")))
    CID, SEC = str(p.get("claim_id", "")), str(p.get("claim_secret", ""))
    ch("claim_id/claim_secret در پاسخ است",
       CID.startswith("acl_") and SEC.startswith("aclsk_"))
    ch("پنجره‌ها: تأیید ۹۰۰ ثانیه (کد از مسیر اپ می‌آید)، برداشت ۱۸۰۰ ثانیه",
       p.get("approve_window_s") == 900 and p.get("pickup_window_s") == 1800)

    # ---------- فقط هش روی دیسک ----------
    pairing_txt = (Path(TMP) / "pairing.json").read_text(encoding="utf-8")
    invites_txt = (Path(TMP) / "invites.json").read_text(encoding="utf-8")
    ch("روی دیسک فقط هش است (رمز/راز/iid)",
       CODE not in pairing_txt and SEC not in pairing_txt
       and IID not in pairing_txt and IID not in invites_txt
       and "aclsk_" not in pairing_txt)

    # ---------- GET دوباره با همان iid → رمز تازه (تا پیش از تأیید) ----------
    c, b2 = req("GET", f"/api/agent/onboarding?iid={IID}")
    ch("GET دوباره با همان iid → رمز تازه",
       c == 200 and b2.get("pairing", {}).get("code", "") != CODE)

    # ---------- سقف ادعای هم‌زمان هر IP = ۲ → سومی busy ----------
    c, b3 = req("GET", f"/api/agent/onboarding?iid={IID}")
    ch("سومین رمزِ در انتظار از همان IP → 429 busy",
       c == 429 and b3.get("error") == "busy")

    # ---------- برداشت ----------
    c, b = poll("acl_" + "0" * 24, SEC)
    ch("poll با claim_id غلط → unknown", c == 200 and b.get("status") == "unknown")
    c, b = poll(CID, "aclsk_" + "f" * 48)
    ch("poll با راز غلط → unknown", c == 200 and b.get("status") == "unknown")
    c, b = poll(CID, SEC)
    ch("poll پیش از تأیید → pending", c == 200 and b.get("status") == "pending")

    # ---------- تأیید انسانی ----------
    c, b = req("POST", "/api/admin/agent-approve", token=AGENT, body={"code": CODE})
    ch("توکن عامل نمی‌تواند تأیید کند → 403", c == 403)
    c, b = req("POST", "/api/admin/agent-approve", body={"code": CODE})
    ch("بدون توکن نمی‌تواند تأیید کند → 401", c == 401)
    c, b = req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": "55555"})
    ch("تأیید رمز غلط → 404", c == 404 and b.get("error") == "no_pending_claim")
    c, b = req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": CODE})
    ch("تأیید رمز درست → 200 با invited_by=رضا",
       c == 200 and b.get("ok") is True and b.get("invited_by") == "رضا")

    c, b = poll(CID, SEC)
    ch("poll پس از تأیید → approved + توکن aagx_ در فیلد token",
       c == 200 and b.get("status") == "approved"
       and b.get("token", "").startswith("aagx_"))
    TOK = b.get("token", "")
    ch("agent_token همان توکن است (سازگاری)", b.get("agent_token") == TOK)
    ch("توکن انقضا دارد", bool(b.get("expires")))

    # ---------- رکورد نشست (پیش از پایانش): origin=pairing + invited_by ----------
    sess_txt = (Path(TMP) / "agent_sessions.json").read_text(encoding="utf-8")
    ch("نشست جفت‌سازی origin=pairing دارد", '"pairing"' in sess_txt)
    ch("نشست برچسب invited_by دارد", "رضا" in sess_txt)

    c, b = poll(CID, SEC)
    ch("برداشت دوم در پنجره → approved با توکن تازه (v0.8.1)",
       c == 200 and b.get("status") == "approved"
       and b.get("token", "").startswith("aagx_")
       and b.get("token", "") != TOK)
    TOK2 = b.get("token", "")
    c, b = req("GET", "/api/status", token=TOK)
    ch("توکن پیشینِ همان ادعا باطل شده → 401", c == 401)
    c, b = req("GET", "/api/status", token=TOK2)
    ch("توکن تازه کار می‌کند → 200", c == 200)
    c, b = req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": CODE})
    ch("تأیید دوباره همان رمز → 404 (ادعا مصرف شده)", c == 404)

    # ---------- یک دعوت = یک عامل ----------
    c, b = req("GET", f"/api/agent/onboarding?iid={IID}")
    ch("GET با iid مصرف‌شده → 404 (یک دعوت = یک عامل)",
       c == 404 and b.get("error") == "unknown_invite")

    # ---------- توکن جفت‌شده مثل عامل رفتار می‌کند ----------
    c, b = req("GET", "/api/status", token=TOK2)
    ch("status با توکن جفت‌شده 200", c == 200 and b.get("ok"))
    c, b = req("GET", "/api/admin/audit", token=TOK2)
    ch("توکن جفت‌شده روی مسیر ادمین → 403", c == 403)
    c, b = req("POST", "/api/exec", token=TOK2, body={"cmd": "echo pairing-ok"})
    ch("exec با توکن جفت‌شده 200", c == 200 and b.get("exit_code") == 0)
    c, b = req("POST", "/api/agent/session/end", token=TOK2, body={})
    ch("پایان نشست 200", c == 200 and b.get("session_removed") is True)
    c, b = req("GET", "/api/status", token=TOK2)
    ch("توکن پس از پایان → 401", c == 401)

    # ---------- دعوت بدون برچسب (خودِ مالک) ----------
    c, b = req("GET", "/api/admin/invite", token=ADMIN)
    ch("invite بدون for → 200", c == 200 and b.get("invited_by") == "")
    m2 = re.search(r"\?iid=(inv_[0-9a-f]{24})", b.get("invite", ""))
    IID2 = m2.group(1) if m2 else ""
    c, b = req("GET", f"/api/agent/onboarding?iid={IID2}")
    ch("دعوت بدون برچسب هم رمز می‌دهد (invited_by خالی)",
       c == 200 and b.get("pairing", {}).get("invited_by", "x") == "")
    CODE2 = str(b.get("pairing", {}).get("code", ""))
    c, b = req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": CODE2})
    ch("تأیید دعوت بدون برچسب → invited_by خالی",
       c == 200 and b.get("invited_by", "x") == "")
    c, b = poll(b.get("claim_id", ""), "")
    ch("poll با راز غلط → unknown", c == 200 and b.get("status") == "unknown")

    # ---------- ttl_h خارج از محدوده → محدود می‌شود ----------
    c, b = req("GET", "/api/admin/invite?for=x&ttl_h=99999", token=ADMIN)
    exp_iso = str(b.get("expires", ""))
    try:
        from datetime import datetime
        exp_ts = datetime.fromisoformat(exp_iso).timestamp()
    except Exception:
        exp_ts = 0.0
    ch("ttl_h=99999 → به ۱۶۸ ساعت محدود شد (پاسخ expires)",
       c == 200 and time.time() + 167 * 3600 <= exp_ts
       and exp_ts <= time.time() + 169 * 3600)

    # ---------- کلید اضطراری مالک: ابطال همهٔ نشست‌ها ----------
    c, b = req("GET", "/api/admin/invite?for=" + urllib.parse.quote("sara"), token=ADMIN)
    m3 = re.search(r"\?iid=(inv_[0-9a-f]{24})", b.get("invite", ""))
    c, b = req("GET", f"/api/agent/onboarding?iid={m3.group(1) if m3 else ''}")
    CODE3 = str(b.get("pairing", {}).get("code", ""))
    req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": CODE3})
    c, b = poll(str(b.get("pairing", {}).get("claim_id", "")),
                str(b.get("pairing", {}).get("claim_secret", "")))
    TOK2 = b.get("token", "")
    ch("جفت‌سازی سوم (sara) موفق", b.get("status") == "approved" and TOK2.startswith("aagx_"))
    c, b = req("POST", "/api/admin/revoke-agent-sessions", token=ADMIN, body={})
    ch("ابطال همهٔ نشست‌ها → removed>=1", c == 200 and b.get("removed", 0) >= 1)
    c, b = req("GET", "/api/status", token=TOK2)
    ch("توکن ابطال‌شده → 401", c == 401)
    c, b = req("POST", "/api/admin/revoke-agent-sessions", token=AGENT, body={})
    ch("عامل نمی‌تواند نشست‌ها را ابطال کند → 403", c == 403)

    # ---------- audit: رویدادها هست، مقدار رمز/iid/توکن هرگز ----------
    al = (Path(TMP) / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    for ev in ("agent_onboarding_read", "agent_onboarding_code_issued",
               "agent_onboarding_refused", "agent_pairing_claim_retired",
               "admin_agent_approve", "agent_pairing_token_issued",
               "admin_revoke_agent_sessions", "admin_invite_served"):
        ch(f"audit: {ev} ثبت شده", ev in al)
    ch("audit: مقدار رمز هرگز لاگ نشده",
       CODE not in al and CODE2 not in al and CODE3 not in al)
    ch("audit: مقدار iid هرگز لاگ نشده", IID not in al and IID2 not in al)
    ch("audit: مقدار توکن هرگز لاگ نشده",
       TOK not in al and TOK2 not in al)
    ch("audit: برچسب کاربر (غیرمخفی) در تأیید هست", "رضا" in al)

    # ---------- هستهٔ هات: اندپوینت‌های جفت‌سازی ----------
    c, b = req("GET", "/api/admin/app/core-config", token=ADMIN)
    ch("core-config: agent_approve در نقشهٔ اندپوینت‌هاست",
       c == 200 and "/api/admin/agent-approve" in b.get("config_json", ""))
    ch("core-config: agent_invite در نقشه است",
       "/api/admin/invite" in b.get("config_json", ""))

    # ---------- لایهٔ امنیت (خانهٔ دوم): انقضا، نرخ، برچسب ----------
    HOME2 = tempfile.mkdtemp(prefix="access-agent-pairing2.")
    real_home = os.environ["ACCESS_AGENT_HOME"]
    os.environ["ACCESS_AGENT_HOME"] = HOME2
    try:
        # برچسب: بیش از ۴۰ نویسه یا نویسهٔ کنترلی → رد به «خالی»
        ch("برچسب بلند → sanitize به خالی",
           security.sanitize_invite_label("x" * 41) == "")
        ch("برچسب با نویسهٔ کنترلی → خالی",
           security.sanitize_invite_label("a\tb") == "")
        ch("برچسب فارسی مجاز است", security.sanitize_invite_label("  رضا ") == "رضا")

        # انقضای دعوت: دعوت با انقضای گذشته → unknown_invite
        raw_i, _rec = security.mint_invite("t", ttl_s=300)
        data = json.loads((Path(HOME2) / "invites.json").read_text(encoding="utf-8"))
        data["invites"][0]["expires_ts"] = time.time() - 1
        (Path(HOME2) / "invites.json").write_text(json.dumps(data), encoding="utf-8")
        r = security.mint_server_pairing(raw_i, ip="10.1.1.1")
        ch("دعوت منقضی → unknown_invite",
           r.get("error") == "unknown_invite" and r.get("status") == 404)

        # انقضای پنجرهٔ تأیید (۹۰۰ ثانیه → ۱ ثانیه در تست)
        raw_j, _ = security.mint_invite("t2", ttl_s=3600)
        rc = security.mint_server_pairing(raw_j, ip="10.2.2.2", approve_window_s=1)
        time.sleep(1.3)
        ra = security.approve_pairing_code(rc.get("code", ""), actor="t")
        ch("انقضای پنجرهٔ تأیید → no_pending_claim",
           ra.get("error") == "no_pending_claim")
        rp = security.collect_pairing_token(rc.get("claim_id", ""),
                                            rc.get("claim_secret", ""))
        ch("poll پس از انقضای تأیید → expired", rp.get("status") == "expired")

        # انقضای پنجرهٔ برداشت
        raw_k, _ = security.mint_invite("t3", ttl_s=3600)
        rc2 = security.mint_server_pairing(raw_k, ip="10.2.2.3")
        security.approve_pairing_code(rc2.get("code", ""), actor="t")
        old_pickup = security.PAIRING_PICKUP_WINDOW_S
        security.PAIRING_PICKUP_WINDOW_S = -1
        try:
            rp2 = security.collect_pairing_token(rc2.get("claim_id", ""),
                                                 rc2.get("claim_secret", ""))
        finally:
            security.PAIRING_PICKUP_WINDOW_S = old_pickup
        ch("انقضای پنجرهٔ برداشت → unknown (جاروب شده)",
           rp2.get("status") == "unknown")

        # نرخ‌سنجی: پنجرهٔ کوتاه در تست
        raw_n, _ = security.mint_invite("t4", ttl_s=3600)
        old_window = security.PAIRING_RATE_WINDOW_S
        old_per_ip = security.PAIRING_PENDING_PER_IP
        security.PAIRING_RATE_WINDOW_S = 1
        security.PAIRING_PENDING_PER_IP = 10
        try:
            for i in range(security.PAIRING_RATE_MAX):
                security.mint_server_pairing(raw_n, ip="10.8.8.8")
            rr = security.mint_server_pairing(raw_n, ip="10.8.8.8")
            ch("نرخ‌سنجی: رمز ششم در پنجره → rate_limited",
               rr.get("error") == "rate_limited" and rr.get("status") == 429)
        finally:
            security.PAIRING_RATE_WINDOW_S = old_window
            security.PAIRING_PENDING_PER_IP = old_per_ip

        # جاروی دیکشنری نرخ: با آدرس‌های کهنهٔ بسیار، حافظه نگردد
        security._PAIRING_RATE.clear()
        for i in range(600):
            security._PAIRING_RATE[f"10.5.5.{i}"] = [0.0]   # همه کهنه
        raw_m, _ = security.mint_invite("t5", ttl_s=3600)
        rr = security.mint_server_pairing(raw_m, ip="10.9.9.8")
        ch("جاروی نرخ: کهنه‌ها حذف و رمز تازه صادر شد",
           rr.get("ok") and len(security._PAIRING_RATE) < 100)
        ch("جاروی نرخ: آدرس درخواست‌کننده در دیکشنری مانده",
           "10.9.9.8" in security._PAIRING_RATE)

        # آمار دعوت‌های زنده (گزارش مالک)
        stats = security.live_invite_stats()
        ch("آمار دعوت زنده: live>=1 و بدون مقدار", stats.get("live", 0) >= 1)
    finally:
        os.environ["ACCESS_AGENT_HOME"] = real_home

    teardown()
    print(f"\n# جمع‌بندی: {GREEN}{n_pass} سبز{NC}، {RED}{n_fail} قرمز{NC}")
    if failures:
        print("# شکست‌ها:")
        for f in failures:
            print(f"  - {f}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
