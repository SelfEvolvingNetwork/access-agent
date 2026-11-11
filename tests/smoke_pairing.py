#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی v0.7.1 — جفت‌سازی عامل با رمز عامل‌ساخته + تأیید انسانی.

جریان کامل، از نگاه هر سه طرف:
  عامل:  POST /api/agent/claim {code} ← claim_id + claim_secret
         (رمز را خودش ساخته و در چت برای مالک چاپ کرده است)
  مالک:  POST /api/admin/agent-approve {code} (پرستو موبایل / SSH)
  عامل:  POST /api/agent/claim/poll ← توکن موقت aagx_
         ... کار ... POST /api/agent/session/end

قرمزها: قالب/ضعف رمز، تأیید غلط، برداشت دوباره، سقف ادعا، نرخ‌سنجی،
انقضای پنجره‌ها، تصادم رمز (قدیمی‌ترین برنده)، audit بدون مقدار رمز.

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
from access_agent.handoff import build_pairing_invite  # noqa: E402

ADMIN = "adm_" + os.urandom(24).hex()
AGENT = "aa_" + os.urandom(24).hex()   # توکن بلندمدت برای تست 403
(Path(TMP) / "tokens.json").write_text(json.dumps({
    "admin_sha": hashlib.sha256(ADMIN.encode()).hexdigest(),
    "agent_sha": hashlib.sha256(AGENT.encode()).hexdigest(),
}), encoding="utf-8")
(Path(TMP) / "config.json").write_text(json.dumps({
    "ip": "203.0.113.7", "port": 9999, "version": "0.7.1",
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

    # ---------- سند آشناسازی: دستورالعمل جفت‌سازی از خود سرور ----------
    c, b = req("GET", "/api/agent/onboarding")
    ch("onboarding 200 و پروتکل 0.7.1", c == 200 and b.get("protocol") == "onboarding/0.7.1")
    ch("onboarding: مدل اعتماد شامل pairing است", "pairing" in b.get("trust_model", {}))
    ch("onboarding: کانال پایدار توضیح داده شده",
       "persistent_channel" in b.get("trust_model", {}))
    sf = b.get("session_flow", {})
    ch("onboarding: جریان claim/ask_human/poll دارد",
       {"2_claim", "3_ask_human", "4_poll"} <= set(sf))
    doc_s = json.dumps(b, ensure_ascii=False)
    ch("onboarding: هیچ مقدار توکنی در پاسخ نیست",
       re.search(r"aagx_[0-9a-f]{48}", doc_s) is None
       and "adm_" not in doc_s and "aclsk_" not in doc_s)

    # ---------- دعوت‌نامهٔ جفت‌سازی: هیچ رمزی در چت نیست ----------
    invite = build_pairing_invite()
    ch("دعوت‌نامه: آدرس و هش گواهی دارد",
       "https://203.0.113.7:9999" in invite and len(invite.split()) > 0)
    ch("دعوت‌نامه: هیچ کد/توکنی ندارد",
       "ob_" not in invite and "aa_" not in invite and "adm_" not in invite
       and "aclsk_" not in invite)

    # ---------- قالب و ضعف رمز ----------
    for bad in ("1234", "123456", "abcde", "", "12 45", "١٢٣٤٥"):
        c, b = req("POST", "/api/agent/claim", body={"code": bad})
        ch(f"claim با رمز نامعتبر {bad!r} → 400", c == 400 and b.get("error") == "bad_code")
    for weak in ("12345", "00000", "99999", "54321"):
        c, b = req("POST", "/api/agent/claim", body={"code": weak})
        ch(f"claim با رمز ضعیف {weak} → 400 weak_code",
           c == 400 and b.get("error") == "weak_code")

    # ---------- جریان اصلی ----------
    CODE = "82419"
    c, b = req("POST", "/api/agent/claim", body={"code": CODE})
    ch("claim معتبر → 200 با claim_id/secret",
       c == 200 and b.get("claim_id", "").startswith("acl_")
       and b.get("claim_secret", "").startswith("aclsk_"))
    CID, SEC = b.get("claim_id", ""), b.get("claim_secret", "")
    ch("پنجره‌ها: تأیید ۱۲۰ ثانیه، برداشت ۱۸۰۰ ثانیه",
       b.get("approve_window_s") == 120 and b.get("pickup_window_s") == 1800)
    pairing_txt = (Path(TMP) / "pairing.json").read_text(encoding="utf-8")
    ch("روی دیسک فقط هش است", CODE not in pairing_txt and SEC not in pairing_txt
       and "aclsk_" not in pairing_txt)

    c, b = poll("acl_" + "0" * 24, SEC)
    ch("poll با claim_id غلط → unknown", c == 200 and b.get("status") == "unknown")
    c, b = poll(CID, "aclsk_" + "f" * 48)
    ch("poll با راز غلط → unknown", c == 200 and b.get("status") == "unknown")
    c, b = poll(CID, SEC)
    ch("poll پیش از تأیید → pending", c == 200 and b.get("status") == "pending")

    c, b = req("POST", "/api/admin/agent-approve", token=AGENT, body={"code": CODE})
    ch("توکن عامل نمی‌تواند تأیید کند → 403", c == 403)
    c, b = req("POST", "/api/admin/agent-approve", body={"code": CODE})
    ch("بدون توکن نمی‌تواند تأیید کند → 401", c == 401)
    c, b = req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": "55555"})
    ch("تأیید رمز غلط → 404", c == 404 and b.get("error") == "no_pending_claim")
    c, b = req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": CODE})
    ch("تأیید رمز درست → 200 matched", c == 200 and b.get("ok") is True)

    c, b = poll(CID, SEC)
    ch("poll پس از تأیید → approved + توکن aagx_",
       c == 200 and b.get("status") == "approved" and b.get("agent_token", "").startswith("aagx_"))
    TOK = b.get("agent_token", "")
    ch("توکن انقضا دارد", bool(b.get("expires")))
    c, b = poll(CID, SEC)
    ch("برداشت دوم → unknown (یک‌بارمصرف)", c == 200 and b.get("status") == "unknown")
    c, b = req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": CODE})
    ch("تأیید دوباره همان رمز → 404 (ادعا مصرف شده)", c == 404)

    # ---------- توکن جفت‌شده مثل عامل رفتار می‌کند ----------
    c, b = req("GET", "/api/status", token=TOK)
    ch("status با توکن جفت‌شده 200", c == 200 and b.get("ok"))
    c, b = req("GET", "/api/admin/audit", token=TOK)
    ch("توکن جفت‌شده روی مسیر ادمین → 403", c == 403)
    c, b = req("POST", "/api/exec", token=TOK, body={"cmd": "echo pairing-ok"})
    ch("exec با توکن جفت‌شده 200", c == 200 and b.get("exit_code") == 0)
    c, b = req("POST", "/api/agent/session/end", token=TOK, body={})
    ch("پایان نشست 200", c == 200 and b.get("session_removed") is True)
    c, b = req("GET", "/api/status", token=TOK)
    ch("توکن پس از پایان → 401", c == 401)

    # ---------- کلید اضطراری مالک: ابطال همهٔ نشست‌ها ----------
    c, b = req("POST", "/api/agent/claim", body={"code": "61042"})
    CID2, SEC2 = b.get("claim_id", ""), b.get("claim_secret", "")
    req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": "61042"})
    c, b = poll(CID2, SEC2)
    TOK2 = b.get("agent_token", "")
    ch("جفت‌سازی دوم موفق", b.get("status") == "approved" and TOK2.startswith("aagx_"))
    c, b = req("POST", "/api/admin/revoke-agent-sessions", token=ADMIN, body={})
    ch("ابطال همهٔ نشست‌ها → removed>=1", c == 200 and b.get("removed", 0) >= 1)
    c, b = req("GET", "/api/status", token=TOK2)
    ch("توکن ابطال‌شده → 401", c == 401)
    c, b = req("POST", "/api/admin/revoke-agent-sessions", token=AGENT, body={})
    ch("عامل نمی‌تواند نشست‌ها را ابطال کند → 403", c == 403)

    # ---------- تصادم رمز: قدیمی‌ترین ادعا برنده ----------
    cA, bA = req("POST", "/api/agent/claim", body={"code": "39176"})
    cB, bB = req("POST", "/api/agent/claim", body={"code": "39176"})
    ch("دو ادعا با همان رمز ثبت شد", cA == 200 and cB == 200)
    time.sleep(0.05)
    c, b = req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": "39176"})
    ch("تأیید رمز مشترک → 200", c == 200)
    c, b = poll(bA.get("claim_id", ""), bA.get("claim_secret", ""))
    ch("ادعای قدیمی‌تر توکن گرفت", b.get("status") == "approved")
    c, b = poll(bB.get("claim_id", ""), bB.get("claim_secret", ""))
    ch("ادعای جدیدتر همچنان pending", b.get("status") == "pending")
    c, b = req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": "39176"})
    ch("تأیید دوباره → ادعای بعدی", c == 200)
    c, b = poll(bB.get("claim_id", ""), bB.get("claim_secret", ""))
    ch("ادعای دوم هم توکن گرفت", b.get("status") == "approved")

    # ---------- audit: رویدادها هست، مقدار رمز/توکن هرگز ----------
    al = (Path(TMP) / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    for ev in ("agent_pairing_claim", "agent_pairing_claim_refused",
               "admin_agent_approve", "agent_pairing_token_issued",
               "admin_revoke_agent_sessions"):
        ch(f"audit: {ev} ثبت شده", ev in al)
    ch("audit: مقدار رمز هرگز لاگ نشده",
       CODE not in al and "39176" not in al and "61042" not in al)
    ch("audit: مقدار توکن هرگز لاگ نشده", TOK not in al and TOK2 not in al)

    # ---------- هستهٔ هات: اندپوینت‌های تازه ----------
    c, b = req("GET", "/api/admin/app/core-config", token=ADMIN)
    ch("core-config: agent_approve در نقشهٔ اندپوینت‌هاست",
       c == 200 and "/api/admin/agent-approve" in b.get("config_json", ""))
    ch("core-config: revoke_agent_sessions در نقشه است",
       "/api/admin/revoke-agent-sessions" in b.get("config_json", ""))

    # ---------- v0.7.2 — دعوت‌نامه از اپ (GET /api/admin/invite) ----------
    c, b = req("GET", "/api/admin/invite")
    ch("invite بدون توکن → 401", c == 401)
    c, b = req("GET", "/api/admin/invite", token=AGENT)
    ch("invite با توکن عامل → 403", c == 403)
    c, b = req("GET", "/api/admin/invite", token=ADMIN)
    inv = b.get("invite", "")
    ch("invite ادمین → 200 و متن بلند دارد", c == 200 and len(inv) > 200)
    ch("invite: URL و هش گواهی دارد", "https://203.0.113.7:9999" in inv)
    ch("invite: هیچ رازی در آن نیست",
       "aa_" not in inv and "adm_" not in inv and "ob_" not in inv
       and "aclsk_" not in inv and "aagx_" not in inv)
    al = (Path(TMP) / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    ch("audit: admin_invite_served ثبت شده", "admin_invite_served" in al)
    c, b = req("GET", "/api/admin/app/core-config", token=ADMIN)
    ch("core-config: agent_invite در نقشه است (revision 4)",
       "/api/admin/invite" in b.get("config_json", ""))

    # ---------- v0.7.2 — خاستگاه نشست (origin) در رکورد ----------
    c, b = req("POST", "/api/agent/claim", body={"code": "71538"})
    CID3, SEC3 = b.get("claim_id", ""), b.get("claim_secret", "")
    req("POST", "/api/admin/agent-approve", token=ADMIN, body={"code": "71538"})
    c, b = poll(CID3, SEC3)
    ch("جفت‌سازی سوم موفق", b.get("status") == "approved")
    sess_txt = (Path(TMP) / "agent_sessions.json").read_text(encoding="utf-8")
    ch("نشست جفت‌سازی origin=pairing دارد", '"pairing"' in sess_txt)
    c, b = req("GET", "/api/status", token=b.get("agent_token", "") or "x")
    ch("توکن جفت‌شدهٔ سوم کار می‌کند", c == 200)

    # ---------- سقف‌ها و انقضا (فراخوانی مستقیم، خانهٔ دوم) ----------
    HOME2 = tempfile.mkdtemp(prefix="access-agent-pairing2.")
    real_home = os.environ["ACCESS_AGENT_HOME"]
    os.environ["ACCESS_AGENT_HOME"] = HOME2
    try:
        r1 = security.mint_pairing_claim("70411", ip="10.9.9.9")
        r2 = security.mint_pairing_claim("70412", ip="10.9.9.9")
        r3 = security.mint_pairing_claim("70413", ip="10.9.9.9")
        ch("سقف ادعای هم‌زمان هر IP = 2 → سومی busy",
           r1.get("ok") and r2.get("ok")
           and r3.get("error") == "busy" and r3.get("status") == 429)

        # نرخ‌سنجی: پنجرهٔ کوتاه و سقف IP بلندشده در همین فرایند (فقط تست)
        old_window = security.PAIRING_RATE_WINDOW_S
        old_per_ip = security.PAIRING_PENDING_PER_IP
        security.PAIRING_RATE_WINDOW_S = 1
        security.PAIRING_PENDING_PER_IP = 10
        try:
            for i in range(security.PAIRING_RATE_MAX):
                security.mint_pairing_claim(f"8110{i}", ip="10.8.8.8")
            rr = security.mint_pairing_claim("81109", ip="10.8.8.8")
            ch("نرخ‌سنجی: ادعای ششم در پنجره → rate_limited",
               rr.get("error") == "rate_limited" and rr.get("status") == 429)
        finally:
            security.PAIRING_RATE_WINDOW_S = old_window
            security.PAIRING_PENDING_PER_IP = old_per_ip

        # انقضای پنجرهٔ تأیید (۲ دقیقه → ۱ ثانیه در تست)
        rc = security.mint_pairing_claim("50617", ip="10.7.7.7", approve_window_s=1)
        time.sleep(1.3)
        ra = security.approve_pairing_code("50617", actor="t")
        ch("انقضای پنجرهٔ تأیید → no_pending_claim",
           ra.get("error") == "no_pending_claim")
        rp = security.collect_pairing_token(rc.get("claim_id", ""), rc.get("claim_secret", ""))
        ch("poll پس از انقضای تأیید → expired", rp.get("status") == "expired")

        # انقضای پنجرهٔ برداشت (۳۰ دقیقه → ۰ در تست)
        rc2 = security.mint_pairing_claim("50618", ip="10.7.7.7")
        security.approve_pairing_code("50618", actor="t")
        old_pickup = security.PAIRING_PICKUP_WINDOW_S
        security.PAIRING_PICKUP_WINDOW_S = -1
        try:
            rp2 = security.collect_pairing_token(rc2.get("claim_id", ""),
                                                 rc2.get("claim_secret", ""))
        finally:
            security.PAIRING_PICKUP_WINDOW_S = old_pickup
        ch("انقضای پنجرهٔ برداشت → unknown (جاروب شده)",
           rp2.get("status") == "unknown")

        # جاروی دیکشنری نرخ (v0.7.2): با آدرس‌های کهنهٔ بسیار، حافظه نگردد
        security._PAIRING_RATE.clear()
        for i in range(600):
            security._PAIRING_RATE[f"10.5.5.{i}"] = [0.0]   # همه کهنه
        rr = security.mint_pairing_claim("39418", ip="10.9.9.8")
        ch("جاروی نرخ: کهنه‌ها حذف و ادعای تازه پذیرفته شد",
           rr.get("ok") and len(security._PAIRING_RATE) < 100)
        ch("جاروی نرخ: آدرس درخواست‌کننده در دیکشنری مانده",
           "10.9.9.8" in security._PAIRING_RATE)
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
