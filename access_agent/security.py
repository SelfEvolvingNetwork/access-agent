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

AGENT_SESSION_TTL_S = 8 * 3600
AGENT_SESSIONS_MAX = 5
ONBOARD_CODE_TTL_S_DEFAULT = 3600


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
                        origin: str = "onboard") -> tuple[str, dict]:
    """توکن موقت نشست عامل — raw فقط یک بار در پاسخ همین درخواست برمی‌گردد.

    origin (v0.7.2): خاستگاه نشست برای forensics — "pairing" (تأیید انسانی)،
    "onboard" (کد یک‌بارمصرف legacy). فقط برچسب است؛ هیچ تفاوتی در قلمرو
    ندارد — سرور از روی مسیر صدور می‌داند این عامل از طرف چه کسی آمده است.
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
    """خروج خودِ عامل از نشست خودش (پایان مکالمه). True اگر نشستی پاک شد."""
    if not presented:
        return False
    h = sha256_hex(presented)
    data = load_agent_sessions()
    live = _prune_sessions(data.get("sessions", []))
    kept = [s for s in live if not hmac.compare_digest(h, s.get("sha", ""))]
    if len(kept) == len(live):
        return False
    data["sessions"] = kept
    save_agent_sessions(data)
    return True


def mint_onboard_code(ttl_s: int = ONBOARD_CODE_TTL_S_DEFAULT) -> tuple[str, dict]:
    """کد یک‌بارمصرف آشناسازی — فقط هشش ذخیره می‌شود؛ raw را مالک به عامل می‌دهد."""
    import secrets as pysecrets
    raw = "ob_" + pysecrets.token_hex(16)
    now = time.time()
    ttl_s = max(60, min(int(ttl_s), 24 * 3600))
    rec = {"code_sha": sha256_hex(raw), "used": False,
           "created": now_iso(),
           "expires": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now + ttl_s))}
    p = home() / "onboard.json"
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass
    return raw, rec


def consume_onboard_code(presented: str) -> bool:
    """کد را یک‌بارمصرف مصرف می‌کند؛ کد نامعتبر/منقضی/مصرف‌شده → False."""
    if not presented:
        return False
    p = home() / "onboard.json"
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return False
    if not isinstance(rec, dict) or rec.get("used"):
        return False
    if _parse_iso(rec.get("expires", "")) <= time.time():
        return False
    if not hmac.compare_digest(sha256_hex(presented), str(rec.get("code_sha", ""))):
        return False
    rec["used"] = True
    rec["used_at"] = now_iso()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass
    return True


# ---------- جفت‌سازی عامل با رمز یک‌بارمصرفِ عامل‌ساخته + تأیید انسانی (v0.7.1) ----------
# فرمان مالک 2026-11-12: رمز پنج‌رقمی را خودِ عامل می‌سازد، در چت برای کاربر
# چاپ می‌کند و کاربر آن را در پرستو موبایل (بخش «تأیید عامل») وارد می‌کند؛
# اپ با کانال ادمین رمز را به پل می‌رساند. هیچ رازی از چت عبور نمی‌کند:
# حلقهٔ اعتماد = چشم مالک + نشست ادمین اپ. مسیرها:
#   POST /api/agent/claim          ادعا: {code} ← claim_id + claim_secret (عمومی، سقف‌دار)
#   POST /api/admin/agent-approve  تأیید مالک: {code} (اپ موبایل / SSH)
#   POST /api/agent/claim/poll     برداشت توکن موقت نشست (فقط یک بار)
# پنجره‌ها: تأیید ۱۲۰ ثانیه از ادعا (فرمان مالک)؛ برداشت ۳۰ دقیقه از تأیید
# (عاملِ چتی بین نوبت‌ها پردازهٔ زنده ندارد و ممکن است دیرتر برگردد).
# هاردنینگ: رمز ضعیف رد؛ سقف ادعای هم‌زمان هر IP و جهانی؛ نرخ‌سنجی؛ هنگام
# تطبیق فقط قدیمی‌ترین ادعا تأیید می‌شود (تصادم رمز قابل سوءاستفاده نیست).
# روی دیسک فقط هش (رمز و راز ادعا) می‌ماند؛ audit هرگز مقدار رمز را نمی‌نویسد.

PAIRING_APPROVE_WINDOW_S = 120     # مهلت تأیید در پرستو موبایل — فرمان مالک: ۲ دقیقه
PAIRING_PICKUP_WINDOW_S = 1800     # مهلت برداشت توکن پس از تأیید
PAIRING_PENDING_MAX = 16           # سقف جهانی ادعاهای در انتظار
PAIRING_PENDING_PER_IP = 2         # سقف ادعای هم‌زمان هر IP
PAIRING_RATE_WINDOW_S = 300        # پنجرهٔ نرخ‌سنجی هر IP
PAIRING_RATE_MAX = 5               # حداکثر ادعا در پنجره

# رمزهای ضعیف — عامل‌های زبانی این‌ها را «تصادفی» انتخاب می‌کنند؛ رد می‌شوند
WEAK_PAIRING_CODES = frozenset({
    "00000", "11111", "22222", "33333", "44444", "55555", "66666",
    "77777", "88888", "99999", "12345", "54321", "01234", "43210",
    "98765", "56789", "67890", "11100", "00111", "10101", "01010",
    "12121", "12321", "11223", "10000", "01000", "00100", "00010",
    "00001", "20000", "30000", "90000", "13579", "24680", "11112", "22221",
})

_PAIRING_LOCK = threading.Lock()
_PAIRING_RATE: dict[str, list[float]] = {}


def _pairing_claims_path() -> Path:
    return home() / "pairing.json"


def _load_claims() -> list[dict]:
    try:
        data = json.loads(_pairing_claims_path().read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("claims"), list):
            return [c for c in data["claims"] if isinstance(c, dict)]
    except Exception:
        pass
    return []


def _save_claims(claims: list[dict]) -> None:
    p = _pairing_claims_path()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"claims": claims}, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass


def _sweep_claims(claims: list[dict], now: float | None = None) -> list[dict]:
    """ادعاهای مرده را می‌ریزد: مصرف‌شده‌ها فوری؛ بقیه تا پایان پنجرهٔ برداشت."""
    now = time.time() if now is None else now
    keep: list[dict] = []
    for c in claims:
        if c.get("consumed"):
            continue
        if c.get("approved"):
            deadline = c.get("approved_ts", 0.0) + PAIRING_PICKUP_WINDOW_S
        else:
            deadline = (c.get("created_ts", 0.0)
                        + (c.get("approve_window_s") or PAIRING_APPROVE_WINDOW_S)
                        + PAIRING_PICKUP_WINDOW_S)
        if now <= deadline:
            keep.append(c)
    return keep


def _claim_pending(c: dict, now: float) -> bool:
    return (not c.get("approved") and not c.get("consumed")
            and c.get("created_ts", 0.0)
            + (c.get("approve_window_s") or PAIRING_APPROVE_WINDOW_S) > now)


def mint_pairing_claim(code: str, ip: str = "",
                       approve_window_s: int = PAIRING_APPROVE_WINDOW_S) -> dict:
    """ثبت ادعای جفت‌سازی — رمز ۵ رقمیِ عامل‌ساخته. فقط هش‌ها ذخیره می‌شوند."""
    code = str(code or "").strip()
    if len(code) != 5 or not (code.isascii() and code.isdigit()):
        return {"ok": False, "status": 400, "error": "bad_code",
                "detail": "code must be exactly 5 ASCII digits (0-9)"}
    if code in WEAK_PAIRING_CODES:
        return {"ok": False, "status": 400, "error": "weak_code",
                "detail": "this code is too predictable — generate a fresh one "
                          "with secure randomness"}
    now = time.time()
    global _PAIRING_RATE  # v0.7.2 — جاروی دیکشنری نرخ ممکن است آن را بازسازی کند
    with _PAIRING_LOCK:
        claims = _sweep_claims(_load_claims(), now)
        # v0.7.2 — جاروی دیکشنری نرخ: با آدرس‌های یکتای بسیار، حافظه بی‌کران
        # نگردد (هر مدخل فقط چند timestamp است؛ کهنه‌ها همین‌جا می‌ریزند).
        if len(_PAIRING_RATE) > 512:
            cutoff = now - PAIRING_RATE_WINDOW_S
            _PAIRING_RATE = {k: [t for t in v if t > cutoff]
                             for k, v in _PAIRING_RATE.items()}
            _PAIRING_RATE = {k: v for k, v in _PAIRING_RATE.items() if v}
        window = [t for t in _PAIRING_RATE.get(ip, [])
                  if t > now - PAIRING_RATE_WINDOW_S]
        if len(window) >= PAIRING_RATE_MAX:
            return {"ok": False, "status": 429, "error": "rate_limited",
                    "detail": "too many claims from this address — wait a few minutes"}
        pending = [c for c in claims if _claim_pending(c, now)]
        if len(pending) >= PAIRING_PENDING_MAX:
            return {"ok": False, "status": 429, "error": "busy",
                    "detail": "too many pending claims — try again later"}
        if sum(1 for c in pending if c.get("ip") == ip) >= PAIRING_PENDING_PER_IP:
            return {"ok": False, "status": 429, "error": "busy",
                    "detail": "too many pending claims from this address"}
        import secrets as pysecrets
        cid = "acl_" + pysecrets.token_hex(12)
        secret = "aclsk_" + pysecrets.token_hex(24)
        claims.append({
            "id": cid,
            "secret_sha": sha256_hex(secret),
            "code_sha": sha256_hex(code),
            "ip": ip,
            "created": now_iso(),
            "created_ts": now,
            "approve_window_s": int(approve_window_s),
            "approved": False,
            "approved_ts": 0.0,
            "consumed": False,
        })
        _save_claims(claims)
        window.append(now)
        _PAIRING_RATE[ip] = window
    return {"ok": True, "claim_id": cid, "claim_secret": secret,
            "approve_window_s": int(approve_window_s),
            "pickup_window_s": PAIRING_PICKUP_WINDOW_S}


def approve_pairing_code(code: str, actor: str = "admin", ip: str = "") -> dict:
    """تأیید انسانی رمز — فقط قدیمی‌ترین ادعای زندهٔ منطبق تأیید می‌شود.

    تطبیق روی هش و مقایسهٔ زمان-ثابت است؛ مقدار رمز هرگز ذخیره یا لاگ نمی‌شود."""
    code = str(code or "").strip()
    if len(code) != 5 or not (code.isascii() and code.isdigit()):
        return {"ok": False, "status": 400, "error": "bad_code",
                "detail": "code must be exactly 5 ASCII digits"}
    target = sha256_hex(code)
    now = time.time()
    with _PAIRING_LOCK:
        claims = _sweep_claims(_load_claims(), now)
        cands = [c for c in claims
                 if _claim_pending(c, now)
                 and hmac.compare_digest(str(c.get("code_sha", "")), target)]
        if not cands:
            _save_claims(claims)
            return {"ok": False, "status": 404, "error": "no_pending_claim",
                    "detail": "no pending claim matches this code (wrong, expired "
                              "or already approved)"}
        oldest = min(cands, key=lambda c: c.get("created_ts", 0.0))
        oldest["approved"] = True
        oldest["approved_ts"] = now
        oldest["approved_at"] = now_iso()
        _save_claims(claims)
    return {"ok": True, "claim_id": oldest.get("id", ""),
            "pickup_window_s": PAIRING_PICKUP_WINDOW_S}


def collect_pairing_token(claim_id: str, claim_secret: str) -> dict:
    """برداشت توکن موقت نشست عامل — فقط یک بار، فقط با راز ادعا.

    وضعیت‌ها: pending / approved (+agent_token) / expired (پنجرهٔ تأیید
    گذشته) / unknown (ناشناخته، مصرف‌شده یا پنجرهٔ برداشت گذشته)."""
    now = time.time()
    with _PAIRING_LOCK:
        claims = _sweep_claims(_load_claims(), now)
        rec = next((c for c in claims if c.get("id") == claim_id), None)
        if rec is None or rec.get("consumed"):
            _save_claims(claims)
            return {"ok": True, "status": "unknown"}
        if not hmac.compare_digest(sha256_hex(claim_secret or ""),
                                   str(rec.get("secret_sha", ""))):
            _save_claims(claims)
            return {"ok": True, "status": "unknown"}
        if rec.get("approved"):
            # ادعای تأییدشده اما با پنجرهٔ برداشت گذشته، همین‌جا در جاروب
            # افتاده و «unknown» گرفته است — رمز تازه لازم است.
            rec["consumed"] = True
            _save_claims(claims)
            raw, sess = mint_agent_session(origin="pairing")
            return {"ok": True, "status": "approved", "agent_token": raw,
                    "expires": sess.get("expires", "")}
        if now > rec.get("created_ts", 0.0) \
                + (rec.get("approve_window_s") or PAIRING_APPROVE_WINDOW_S):
            _save_claims(claims)
            return {"ok": True, "status": "expired"}
        _save_claims(claims)
        remaining = int(rec.get("created_ts", 0.0)
                        + (rec.get("approve_window_s") or PAIRING_APPROVE_WINDOW_S) - now) + 1
        return {"ok": True, "status": "pending", "retry_after_s": max(0, remaining)}


def clear_agent_sessions() -> int:
    """ابطال همهٔ نشست‌های موقت جفت‌سازی (کلید اضطراری مالک). تعداد را می‌دهد."""
    data = load_agent_sessions()
    n = len(_prune_sessions(data.get("sessions", [])))
    save_agent_sessions({"sessions": []})
    return n
