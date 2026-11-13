"""Tokens, audit and config paths — access_agent.security.

All secrets live under ACCESS_AGENT_HOME (default /etc/access-agent, root-only).
Tokens are stored as SHA-256 hashes only; presented tokens are compared
constant-time. Nothing here ever logs a token value.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path


def home() -> Path:
    return Path(os.environ.get("ACCESS_AGENT_HOME", "/etc/access-agent"))


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------- tokens ----------

def load_tokens() -> dict:
    """tokens.json: {"admin_sha": "...", "agent_sha": "...|empty", "updated_at": iso}"""
    p = home() / "tokens.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("tokens.json must be an object")
        return data
    except Exception:
        return {"admin_sha": "", "agent_sha": "", "updated_at": ""}


def save_tokens(data: dict) -> None:
    p = home() / "tokens.json"
    data["updated_at"] = now_iso()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass


def check_token(presented: str, role: str) -> bool:
    """role: "admin" | "agent". Empty stored hash = realm disabled."""
    if not presented:
        return False
    stored = load_tokens().get(f"{role}_sha", "")
    if not stored:
        return False
    return hmac.compare_digest(sha256_hex(presented), stored)


# ---------- audit (append-only JSONL; contractual red line: agent must not edit it) ----------

def audit(actor: str, action: str, detail: dict | None = None, ip: str = "") -> None:
    d = home() / "audit"
    d.mkdir(parents=True, exist_ok=True)
    rec = {"ts": now_iso(), "ip": ip, "actor": actor, "action": action}
    if detail:
        rec.update(detail)
    with (d / "audit.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def audit_tail(n: int) -> list[str]:
    p = home() / "audit" / "audit.jsonl"
    if not p.exists():
        return []
    try:
        with p.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        return [l.rstrip("\n") for l in lines[-max(0, min(n, 2000)):]]
    except Exception:
        return []


# ---------- agent-realm pause state (v0.3 — mobile kill switch) ----------
# state.json (chmod 600): {"agent_paused": bool, "reason": str, "ts": iso}
# Paused realm only blocks the agent role; admin stays a full superset and
# public endpoints (/healthz) are untouched. Survives service restarts.

def load_state() -> dict:
    p = home() / "state.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"agent_paused": False, "reason": "", "ts": ""}


def save_state(data: dict) -> None:
    p = home() / "state.json"
    data["ts"] = now_iso()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass


def agent_paused() -> tuple[bool, str]:
    s = load_state()
    return bool(s.get("agent_paused")), str(s.get("reason", ""))


def set_agent_paused(paused: bool, reason: str = "") -> dict:
    s = load_state()
    s["agent_paused"] = bool(paused)
    s["reason"] = str(reason)[:300]
    save_state(s)
    return s


# ---------- admin sessions (v0.4 — ورود با رمز سرور؛ parastoo-mobile) ----------
# توکن ادمین اصلی فقط به‌صورت هش نگه‌داری می‌شود، پس با رمز «نشست» صادر
# می‌کنیم نه آن توکن. sessions.json (chmod 600):
#   {"sessions": [{"sha": "...", "created": iso, "expires": iso,
#                  "label": str, "ip": str}]}
# TTL ۳۰ روز، سقف ۱۰ نشست فعال (کهنه‌ترین حذف می‌شود)؛ هر بررسی، منقضی‌ها
# را پر می‌کند. هیچ رویدادی خودِ رمز یا توکن را لاگ نمی‌کند.

SESSION_TTL_S = 30 * 24 * 3600
SESSIONS_MAX = 10


def load_sessions() -> dict:
    p = home() / "sessions.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("sessions"), list):
            return data
    except Exception:
        pass
    return {"sessions": []}


def save_sessions(data: dict) -> None:
    p = home() / "sessions.json"
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass


def _prune_sessions(sessions: list[dict], now: float | None = None) -> list[dict]:
    now = time.time() if now is None else now
    live = [s for s in sessions if _parse_iso(s.get("expires", "")) > now]
    return live[-SESSIONS_MAX:]


def _parse_iso(value: str) -> float:
    try:
        import datetime
        return datetime.datetime.fromisoformat(value).timestamp()
    except Exception:
        return 0.0


def mint_session(label: str = "", ip: str = "") -> tuple[str, dict]:
    """New admin session — returns (raw_token, record). Raw is shown once."""
    import secrets as pysecrets
    raw = "aasess_" + pysecrets.token_hex(24)
    now = time.time()
    rec = {
        "sha": sha256_hex(raw),
        "created": now_iso(),
        "expires": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now + SESSION_TTL_S)),
        "label": str(label)[:80],
        "ip": ip,
    }
    data = load_sessions()
    data["sessions"] = _prune_sessions(data.get("sessions", []), now) + [rec]
    save_sessions(data)
    return raw, rec


def check_session(presented: str) -> bool:
    """Constant-time compare against live sessions; prunes expired on read."""
    if not presented:
        return False
    data = load_sessions()
    live = _prune_sessions(data.get("sessions", []))
    if len(live) != len(data.get("sessions", [])):
        data["sessions"] = live
        save_sessions(data)
    h = sha256_hex(presented)
    return any(hmac.compare_digest(h, s.get("sha", "")) for s in live)


def revoke_sessions() -> int:
    """Owner-side logout everywhere (v0.4). Returns removed count."""
    data = load_sessions()
    n = len(data.get("sessions", []))
    save_sessions({"sessions": []})
    return n


# ---------- نشست‌های موقت عامل + کد آشناسازی (v0.7 — اصل «اول سرور، بعد توکن») ----------
# قرارداد تازه به فرمان مالک: توکن عامل بلندمدت دیگر از چت عبور نمی‌کند.
#  ۱) مالک با CLI «دعوت‌نامهٔ کوتاه» می‌سازد: URL + هش گواهی + یک کد یک‌بارمصرف
#     (ONBOARD_CODE با TTL کوتاه؛ فقط هشش روی دیسک است).
#  ۲) نخستین تراکنش عامل GET /api/agent/onboarding است — فقط‌خواندنی و عمومی —
#     و دستورالعمل کامل را خود سرور به عامل می‌دهد، نه بلوک اولیهٔ چت.
#  ۳) عامل کد را در POST /api/agent/onboard با توکن موقتِ «نشست» عوض می‌کند:
#     TTL کوتاه (پیش‌فرض ۸ ساعت)، سقف ۵ نشست زنده، ابطال‌پذیر، ثبت در audit.
#  ۴) در آخرین پیام مکالمه، مالک از عامل می‌خواهد نشستش را با
#     POST /api/agent/session/end پاک کند — هیچ اعتباری روی سرور نمی‌ماند.
# هیچ رویدادی مقدار کد یا توکن را لاگ نمی‌کند — فقط هش و بولی.

# ---------- نشست‌های موقت عامل + اتصال مستقیم با دعوت (v0.7/v0.9) ----------
# قرارداد v0.9 (فرمان مالک ۲۰۲۶-۱۱-۱۳ — حذف تشریفات): توکن عامل بلندمدت از
# چت عبور نمی‌کند و اتصال بی‌رمز است:
#  ۱) مالک/ادمین «دعوت‌نامهٔ یک‌خطی» می‌سازد (CLI/اپ/پنل): فقط URL آشناسازی
#     با شناسهٔ دعوت (iid): «لطفا این لینک را دنبال کنید: <URL>»
#  ۲) عامل همان URL را GET می‌کند؛ خودِ iid اعتبار اتصال است — نه رمز
#     تأییدی، نه poll. سرور دعوت را با نخستین توکن مصرف می‌کند (یک دعوت =
#     یک عامل) و توکن موقتِ همین مکالمه را در همان پاسخ می‌دهد.
#  ۳) در آخرین پیام مکالمه، مالک از عامل می‌خواهد نشستش را با
#     POST /api/agent/session/end پاک کند — هیچ اعتباری روی سرور نمی‌ماند.
# هیچ رویدادی مقدار iid یا توکن را لاگ نمی‌کند — فقط هش و بولی.

AGENT_SESSION_TTL_S = 8 * 3600
AGENT_SESSIONS_MAX = 5

# نرخ‌سنجی خطای iid (ضد چکش/بروت‌فورس؛ فقط تلاش‌های ناموفق شمرده می‌شوند)
ONBOARD_FAIL_WINDOW_S = 300
ONBOARD_FAIL_MAX = 10


def load_agent_sessions() -> dict:
    p = home() / "agent_sessions.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("sessions"), list):
            return data
    except Exception:
        pass
    return {"sessions": []}


def save_agent_sessions(data: dict) -> None:
    p = home() / "agent_sessions.json"
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass


def mint_agent_session(ttl_s: int = AGENT_SESSION_TTL_S, ip: str = "",
                        origin: str = "invite",
                        invited_by: str = "") -> tuple[str, dict]:
    """توکن موقت نشست عامل — raw فقط یک بار در پاسخ همین درخواست برمی‌گردد.

    origin: خاستگاه نشست برای forensics — v0.9: "invite" (دعوت با iid؛
    v0.7.2 پیش‌تر pairing/onboard بود). فقط برچسب است؛ هیچ تفاوتی در قلمرو
    ندارد — سرور از روی مسیر صدور می‌داند این عامل از طرف چه کسی آمده است.
    invited_by (v0.8): برچسب کاربری که دعوت‌نامه‌اش به این نشست انجامیده —
    فقط forensics/گزارش مالک؛ راز نیست.
    """
    import secrets as pysecrets
    raw = "aagx_" + pysecrets.token_hex(24)
    now = time.time()
    ttl_s = max(60, min(int(ttl_s), 24 * 3600))
    rec = {
        "sha": sha256_hex(raw),
        "created": now_iso(),
        "expires": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now + ttl_s)),
        "ip": ip,
        "origin": str(origin)[:24],
        "invited_by": str(invited_by)[:40],
    }
    data = load_agent_sessions()
    data["sessions"] = _prune_sessions(data.get("sessions", []), now)[-AGENT_SESSIONS_MAX:] + [rec]
    save_agent_sessions(data)
    return raw, rec


def check_agent_session(presented: str) -> bool:
    if not presented:
        return False
    data = load_agent_sessions()
    live = _prune_sessions(data.get("sessions", []))
    if len(live) != len(data.get("sessions", [])):
        data["sessions"] = live
        save_agent_sessions(data)
    h = sha256_hex(presented)
    return any(hmac.compare_digest(h, s.get("sha", "")) for s in live)


def revoke_agent_session(presented: str) -> bool:
    """خروج خودِ عامل از نشست خودش (پایان مکالمه). True اگر نشستی پاک شد.

    مقدار خام توکن هرگز ورودی مقایسه نیست — فقط هش."""
    if not presented:
        return False
    sha = sha256_hex(presented)
    data = load_agent_sessions()
    live = _prune_sessions(data.get("sessions", []))
    kept = [s for s in live
            if not hmac.compare_digest(sha, str(s.get("sha", "")))]
    if len(kept) == len(live):
        return False
    data["sessions"] = kept
    save_agent_sessions(data)
    return True


# ---------- v0.9 — اتصال مستقیم با دعوت‌نامه (فرمان مالک ۲۰۲۶-۱۱-۱۳) ----------
# خودِ دعوت (iid) اعتبار اتصال است: GET /api/agent/onboarding?iid=... مستقیماً
# توکن موقت صادر می‌کند؛ نه رمز تأییدی هست، نه poll. مسیرهای v0.7/v0.8
# (claim/onboard/agent-approve) و state آن‌ها (pairing.json/onboard.json)
# حذف شدند. روی دیسک فقط هش می‌ماند؛ audit هرگز مقدار iid یا توکن نمی‌نویسد.

# ---------- دعوت‌نامهٔ کاربر-مند (v0.8/v0.9) ----------
# invites.json (chmod 600): {"invites": [{"iid_sha", "invited_by", "created",
# "created_ts", "expires", "expires_ts", "used"}] — شناسهٔ دعوت یک «توانایی»
# است: ۹۶ بیت تصادفی، فقط هش روی دیسک، raw فقط یک بار در دعوت چاپ می‌شود.
# دعوت با نخستین توکنِ صادرشده مصرف می‌شود (یک دعوت = یک عامل)؛ تا پیش از آن
# زنده است و انقضا دارد. برچسب invited_by راز نیست — پاسخ آشناسازی و رکورد
# نشست نشانش می‌دهند تا «پای کدام کاربر» بودن دعوت روشن باشد.

INVITE_TTL_S_DEFAULT = 24 * 3600
INVITE_TTL_S_MAX = 7 * 24 * 3600
INVITES_MAX = 32

_INVITE_LOCK = threading.Lock()
_ONBOARD_FAIL_RATE: dict[str, list[float]] = {}


def _invites_path() -> Path:
    return home() / "invites.json"


def _load_invites() -> list[dict]:
    try:
        data = json.loads(_invites_path().read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("invites"), list):
            return [i for i in data["invites"] if isinstance(i, dict)]
    except Exception:
        pass
    return []


def _save_invites(invites: list[dict]) -> None:
    p = _invites_path()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"invites": invites}, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass


def _sweep_invites(invites: list[dict], now: float | None = None) -> list[dict]:
    """دعوت‌های مصرف‌شده/منقضی را می‌ریزد — فقط زنده‌ها می‌مانند."""
    now = time.time() if now is None else now
    return [i for i in invites
            if not i.get("used") and i.get("expires_ts", 0.0) > now]


def sanitize_invite_label(label: str) -> str:
    """برچسب کاربر دعوت — قابل چاپ، بدون نویسهٔ کنترلی، حداکثر ۴۰ نویسه."""
    label = str(label or "").strip()
    if not label or len(label) > 40:
        return ""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in label):
        return ""
    return label


def mint_invite(invited_by: str = "", ttl_s: int = INVITE_TTL_S_DEFAULT) -> tuple[str, dict]:
    """ساخت دعوت‌نامهٔ کاربر-مند — raw فقط یک بار برمی‌گردد (برای بلوک دعوت).

    invited_by راز نیست؛ در پاسخ آشناسازی عامل و پاسخ تأیید مالک دیده
    می‌شود تا «پای کدام کاربر» بودن دعوت روشن باشد."""
    import secrets as pysecrets
    label = sanitize_invite_label(invited_by)
    ttl_s = max(300, min(int(ttl_s), INVITE_TTL_S_MAX))
    now = time.time()
    raw = "inv_" + pysecrets.token_hex(12)
    rec = {
        "iid_sha": sha256_hex(raw),
        "invited_by": label,
        "created": now_iso(),
        "created_ts": now,
        "expires": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now + ttl_s)),
        "expires_ts": now + ttl_s,
        "used": False,
    }
    with _INVITE_LOCK:
        invites = _sweep_invites(_load_invites(), now)
        if len(invites) >= INVITES_MAX:
            raise RuntimeError("too many live invites — wait for expiry or approve/pair first")
        invites.append(rec)
        _save_invites(invites)
    return raw, rec


def _find_live_invite(raw_iid: str, now: float | None = None):
    """دعوت زندهٔ منطبق — با هش و مقایسهٔ زمان-ثابت؛ وگرنه None."""
    if not raw_iid:
        return None
    now = time.time() if now is None else now
    target = sha256_hex(raw_iid)
    for i in _sweep_invites(_load_invites(), now):
        if hmac.compare_digest(str(i.get("iid_sha", "")), target):
            return i
    return None


def _use_invite(iid_sha: str) -> None:
    """مصرف دعوت با نخستین تأیید (یک دعوت = یک عامل). فقط هش می‌گیرد."""
    now = time.time()
    invites = _sweep_invites(_load_invites(), now)
    for i in invites:
        if hmac.compare_digest(str(i.get("iid_sha", "")), str(iid_sha)):
            i["used"] = True
            i["used_at"] = now_iso()
    _save_invites(invites)


def live_invite_stats() -> dict:
    """خلاصهٔ دعوت‌های زنده برای گزارش مالک — بدون هیچ هش/مقدار."""
    now = time.time()
    invites = _sweep_invites(_load_invites(), now)
    return {"live": len(invites),
            "labeled": sum(1 for i in invites if i.get("invited_by"))}


def claim_invite_session(raw_iid: str, ip: str = "") -> dict:
    """v0.9 — خودِ دعوت اعتبار اتصال است؛ GET با iid مستقیماً توکن می‌دهد.

    دعوت با نخستین توکن مصرف می‌شود (یک دعوت = یک عامل). فقط هش‌ها روی دیسک
    می‌مانند و مقدار iid هرگز ذخیره یا لاگ نمی‌شود. تلاش‌های ناموفق هر IP
    نرخ‌سنجی می‌شوند (ضد بروت‌فورس بی‌معنا روی ۹۶ بیت)."""
    now = time.time()
    global _ONBOARD_FAIL_RATE
    with _INVITE_LOCK:
        invite = _find_live_invite(raw_iid, now)
        if invite is None:
            # جاروی دیکشنری نرخ — با آدرس‌های یکتای بسیار، حافظه بی‌کران نگردد
            if len(_ONBOARD_FAIL_RATE) > 512:
                cutoff = now - ONBOARD_FAIL_WINDOW_S
                _ONBOARD_FAIL_RATE = {k: [t for t in v if t > cutoff]
                                      for k, v in _ONBOARD_FAIL_RATE.items()}
                _ONBOARD_FAIL_RATE = {k: v for k, v in
                                      _ONBOARD_FAIL_RATE.items() if v}
            window = [t for t in _ONBOARD_FAIL_RATE.get(ip, [])
                      if t > now - ONBOARD_FAIL_WINDOW_S]
            if len(window) >= ONBOARD_FAIL_MAX:
                return {"ok": False, "status": 429, "error": "rate_limited",
                        "detail": "تلاش ناموفق زیادی از این نشانی — "
                                  "چند دقیقه بعد دوباره تلاش کنید."}
            window.append(now)
            _ONBOARD_FAIL_RATE[ip] = window
            return {"ok": False, "status": 404, "error": "unknown_invite",
                    "detail": "دعوت ناشناخته، منقضی یا قبلاً مصرف‌شده است — "
                              "از مالک سرور دعوت‌نامهٔ تازه بگیرید."}
        # یک دعوت = یک عامل؛ مصرف با نخستین توکن
        _use_invite(str(invite.get("iid_sha", "")))
        raw, sess = mint_agent_session(ip=ip, origin="invite",
                                       invited_by=str(invite.get("invited_by", "")))
    return {"ok": True, "token": raw, "agent_token": raw,
            "expires": sess.get("expires", ""),
            "invited_by": str(invite.get("invited_by", ""))}


def clear_agent_sessions() -> int:
    """ابطال همهٔ نشست‌های موقت جفت‌سازی (کلید اضطراری مالک). تعداد را می‌دهد."""
    data = load_agent_sessions()
    n = len(_prune_sessions(data.get("sessions", [])))
    save_agent_sessions({"sessions": []})
    return n
