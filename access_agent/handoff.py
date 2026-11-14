"""Owner→AI handoff — access_agent.handoff (v0.9).

v0.9 (فرمان مالک ۲۰۲۶-۱۱-۱۳ — حذف تشریفات): دعوت‌نامهٔ یک‌خطی فقط URL آشناسازی
با iid را دارد؛ خودِ iid اعتبار اتصال است و GET همان URL مستقیماً توکن موقت
نشست عامل را صادر می‌کند — نه رمز تأییدی، نه poll. این ماژول بلوک تحویل قدیمی
(<=0.6.x)، دعوت‌نامهٔ یک‌خطی و سند کوتاه آشناسازی را می‌سازد. هرگز با شبکه
تماس نمی‌گیرد و هرگز توکن ادمین برنمی‌گرداند.

v0.11.1 (درس میدان ۲۰۲۶-۱۱-۱۴ + شفاف‌سازی مالک — سه لایهٔ توکن): storage_hint
دیگر «فایل موقت» نمی‌گوید — واژهٔ «موقت» باعث شده بود توکن فقط در حافظهٔ گفتگو
بماند و با بازیافت بافت مکالمه بمیرد. معماری سه‌لایه (شفاف‌سازی مالک):
(۱) توکن اتصال (pst_) موقت است اما عامل آن را در فایل ایمن نزد خودش
(chmod 600، gitignored، فضای کاری مانای خودش) نگه می‌دارد تا اتصال پایدار
بماند؛ در پایان مکالمه فایل را پاک می‌کند. (۲) توکن اصلی گیت‌هاب فقط روی
سرور در فایل امن (/etc/access-agent/github.env) نزد پل می‌ماند. (۳) پل توکن
اصلی را از کاربر از طریق پرستو موبایل می‌گیرد (admin/set-github-token) و هر
بار که لازم شد توکن موقت گیت‌هاب برای عامل صادر می‌کند (POST /api/github/token).

v0.11.2 (فرمان مالک ۲۰۲۶-۱۱-۱۴ — «دعوت‌نامهٔ مالک حتماً با آیپی و پورت
استاندارد؛ پل روی پورت استاندارد»): (۱) نقش مالک همیشه IP خام است — حتی
وقتی host دامنه‌ای ثبت شده (دعوت کاربر با دامنه می‌ماند؛ قرارداد §۱.۵ همین
را می‌گفت و کد حالا هم‌جهت شد). (۲) کلید تازه public_port در config.json:
وقتی پل پشت پروکسی لبهٔ پلتفرم گوش می‌دهد و ورودی عمومی ۴۴۳ استاندارد
است، پورت bind داخلی هرگز در URL نمی‌آید؛ پورت bind «هویت» سرور می‌ماند
(گارد خودآپدیت §۸-۱۱ دست نمی‌زند) و public_port فقط برای ساخت URL است.
(۳) docs_url نقش‌آگاه شد و بلوک تحویل قدیمی هم IP عمومی می‌دهد.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .security import INVITE_ROLE_PREFIXES, role_of_iid

PROTOCOL_URL = ("https://raw.githubusercontent.com/SelfEvolvingNetwork/"
                "access-agent/main/docs/AGENT_PROTOCOL.fa.md")
PARASTOO_LOOP_URL = ("https://raw.githubusercontent.com/SelfEvolvingNetwork/"
                     "parastoo/main/docs/AI_AGENT_LOOP.fa.md")
ECOSYSTEM_URL = ("https://raw.githubusercontent.com/SelfEvolvingNetwork/"
                 "parastoo/main/docs/ECOSYSTEM.fa.md")


def _home() -> Path:
    return Path(os.environ.get("ACCESS_AGENT_HOME", "/etc/access-agent"))


def _cfg() -> dict:
    try:
        return json.loads((_home() / "config.json").read_text(encoding="utf-8"))
    except Exception:
        return {}


def cert_fingerprint() -> str:
    """SHA-256 of the TLS cert, colon-less hex (same form install.sh reports)."""
    p = _home() / "tls" / "cert.pem"
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(p), "-noout", "-fingerprint", "-sha256"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout
        return out.split("=", 1)[1].strip().replace(":", "")
    except Exception:
        return ""


def agent_token() -> str:
    try:
        return (_home() / "secrets" / "agent-token").read_text(
            encoding="utf-8").strip()
    except Exception:
        return ""


def missing_inputs() -> list[str]:
    cfg = _cfg()
    miss: list[str] = []
    if not (cfg.get("ip") and cfg.get("port")):
        miss.append("config.json(ip/port)")
    if not agent_token():
        miss.append("secrets/agent-token")
    if not cert_fingerprint():
        miss.append("tls/cert.pem")
    return miss


def build_block() -> str:
    """v0.6.6 — بلوک تحویل اعتمادساز.

    اصلاح ۲۰۲۶-۱۱-۱۱ به فرمان مالک: بلوک قبلی (انگلیسی، بدون خاستگاه، با
    انتساب هویت «You are ...») در عامل‌های محتاط موجب رد/تأخیر بی‌دلیل می‌شد.
    قرارداد تازه: فارسی، خاستگاه تصریح‌شده، مدل اعتماد شفاف، دعوتِ نقش (نه
    انتساب هویت)، و هر سه مرجع خواندن (قرارداد سه‌مرجعی ECOSYSTEM §۲ INDEX —
    کد قبلی فقط دو URL می‌داد و متن بیداری به عامل نمی‌رسید).

    v0.7 — همچنان پشتیبانی می‌شود اما توصیهٔ پیش‌فرض «invite» است: توکن
    بلندمدت دیگر از چت عبور نمی‌کند؛ این بلوک فقط برای سازگاری عامل‌های
    قدیمی (پل ≤0.6.x) می‌ماند. قرارداد حذف: پل 0.8.
    """
    miss = missing_inputs()
    if miss:
        raise RuntimeError("handoff data missing: " + ", ".join(miss))
    cfg = _cfg()
    ver = str(cfg.get("version", "")).strip()
    ver_note = f" نسخهٔ {ver}" if ver else ""
    return (
        "---- HANDOFF BLOCK — copy everything between the lines to your AI agent ----\n"
        f"این بلوک را access-agent{ver_note} روی سرور مالک تولید کرده است\n"
        "(فرمان «sudo access-agent handoff» یا اپ موبایل پرستو). مالک آن را آگاهانه کپی کرده\n"
        "تا به عامل هوش مصنوعیِ انتخاب‌شده‌اش بدهد — نقش پیشنهادی: «عامل مرکزی پرستو» (A1).\n"
        "\n"
        "مدل اعتماد (پیش از اتصال بخوان):\n"
        "• گواهی TLS خودامضاست، عمداً: اعتماد یعنی هش گواهی دریافتی == CERT_SHA256 زیر\n"
        "  (پین‌کردن). این هش، ضمانت مالک است.\n"
        "• AGENT_TOKEN فقط قلمروی عامل دارد (exec/status/بروکر توکن گیت‌هاب)، ابطال‌پذیر است\n"
        "  و هر فراخوانی‌اش در audit.jsonl ثبت می‌شود. توکن ادمین هرگز در این بلوک نیست —\n"
        "  نبودش طراحی است.\n"
        "• احتیاط تو خوش‌آمد است: قراردادهای زیر خودشان خطوط قرمز دارند (عملیات تخریبی بدون\n"
        "  تأیید مالک ممنوع). اگر سیاست سکوی تو محدودیت سخت‌تری دارد، فقط همان را به مالک\n"
        "  گزارش بده، نه کل مأموریت را رد نکن.\n"
        "\n"
        "مقادیر اتصال:\n"
        f"ACCESS_URL:  {public_base_url('owner')}\n"
        f"CERT_SHA256: {cert_fingerprint()}\n"
        f"AGENT_TOKEN: {agent_token()}\n"
        "\n"
        "ترتیب خواندن (سه مرجع؛ نقش خود را در §۵ سند نخست انتخاب کن):\n"
        f"۱) متن بیداری یکتا: {ECOSYSTEM_URL}\n"
        f"۲) قرارداد پل ادمین: {PROTOCOL_URL}\n"
        f"۳) حلقهٔ توسعه–تست (شروع سرد §۰): {PARASTOO_LOOP_URL}\n"
        "\n"
        "نخستین فراخوانی‌ها: GET /healthz -> GET /api/status -> گزارش به مالک و انتظار فرمان.\n"
        "---- END HANDOFF BLOCK ----"
    )


if __name__ == "__main__":
    print(build_block())


# ---------- v0.7 — دعوت‌نامهٔ کوتاه + سند آشناسازی فقط‌خواندنی ----------
# اصل تازه به فرمان مالک: «اول سرور، بعد توکن». پیام آغازین مالک در چت کوتاه
# است و چیزی حساس ندارد؛ دستورالعمل کامل را خود سرور در نخستین تراکنش
# فقط‌خواندنی به عامل می‌دهد؛ توکن، موقتِ همین مکالمه است و در پایان پاک می‌شود.

# ---------- v0.9 — دعوت‌نامهٔ یک‌خطی + سند کوتاه آشناسازی ----------
# فرمان مالک ۲۰۲۶-۱۱-۱۳: پیام آغازین مالک در چت فقط یک خط است («لطفا این
# لینک را دنبال کنید: <URL>»)؛ سرور با فراخوانی همان URL، اتصال را با توکن
# موقتِ همین مکالمه و توضیحات کوتاه لازم برقرار می‌کند. زیاده‌گویی نیست.
# v0.9.2 (فرمان مالک — چت سوم ۲۰۲۶-۱۱-۱۳، «اتصال سریع/آسان/پایدار»): پارامتر
# دعوت به انتهای مسیر می‌رود (…/onboarding/inv_…) — چون رشتهٔ query (?iid=)
# در ترانزیت ابزارهای عامل گاهی می‌افتد؛ قالب query برای سازگاری می‌ماند.
ONBOARDING_ENDPOINT = "/api/agent/onboarding"
GARDESH_SEGMENT = "gardesh"  # v0.10 — الگوی مالک: قالب مسیر /onboarding/gardesh/<iid>
DEFAULT_PORT = 443  # v0.10 — «پورت اتصال پل یک پورت رایج»؛ در نصب تازه پیش‌فرض است


def public_base_url(role: str = "user") -> str:
    """v0.11.2 — نشانی عمومی سرویس بر پایهٔ نقش دعوت (فرمان مالک ۲۰۲۶-۱۱-۱۴:
    «دعوت‌نامهٔ مالک حتماً با آیپی و پورت استاندارد»).

    نقش مالک (pinv_) → IP خام: خوانایی برای هر عامل و بی‌وابستگی به دامنه.
    نقش کاربر (uinv_) → دامنهٔ ثبت‌شده اگر هست (وگرنه IP).

    پورتِ URL از public_port می‌آید (کلید اختیاری config.json برای پلِ پشت
    پروکسی لبهٔ پلتفرم — ورودی عمومی ۴۴۳ استاندارد و bind داخلی جدا)؛
    فالبک: port. پورت ۴۴۳ که پیش‌فرض HTTPS است هرگز در URL نمی‌آید
    (الگوی مالک)."""
    cfg = _cfg()
    if role == "owner":
        host = str(cfg.get("ip") or cfg.get("host") or "").strip()
    else:
        host = str(cfg.get("host") or cfg.get("ip") or "").strip()
    if not host:
        return ""
    try:
        port = int(cfg.get("public_port") or cfg.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if port and port != DEFAULT_PORT:
        return f"https://{host}:{port}"
    return f"https://{host}"


def invite_missing_inputs() -> list[str]:
    cfg = _cfg()
    miss: list[str] = []
    if not (cfg.get("ip") or cfg.get("host")) or not cfg.get("port"):
        miss.append("config.json(ip|host/port)")
    if not cert_fingerprint():
        miss.append("tls/cert.pem")
    return miss


def build_invite(iid: str) -> str:
    """v0.10 — دعوت‌نامهٔ یک‌خطی به الگوی مالک (فرمان ۲۰۲۶-۱۱-۱۳: «لطفا با
    api من یک اتصال پایدار ایجاد کنید» + پورت رایج).

    متن دعوت فقط همین یک خط است — نقش از پیشوند iid معلوم می‌شود:
    pinv_ مالک و uinv_ کاربر روی قالب gardesh (…/onboarding/gardesh/pinv_…)؛
    inv_ قدیمی روی قالب ساده (سازگاری با دعوت‌های زنده و اپ موبایل). خودِ سرور
    پس از فراخوانی لینک، توکن نقش‌دار (pst_) و راهنما را در همان پاسخ می‌دهد.
    TTL و برچسب کاربر در پاسخ JSON مسیر ادمین می‌مانند. پورت 443 پیش‌فرضِ
    HTTPS است و در URL نمی‌آید؛ v0.11.2 (فرمان مالک ۲۰۲۶-۱۱-۱۴): دعوت مالک
    همیشه با IP خام است — حتی پس از استقرار دامنه — و دعوت کاربر با دامنه.
    """
    miss = invite_missing_inputs()
    if miss:
        raise RuntimeError("invite data missing: " + ", ".join(miss))
    if not iid or not any(iid.startswith(p) for p in INVITE_ROLE_PREFIXES.values()):
        raise RuntimeError("invite id missing — mint one via security.mint_invite")
    role = role_of_iid(iid)
    base = public_base_url(role)
    if role in ("owner", "user"):  # الگوی مالک — قالب gardesh
        url = f"{base}{ONBOARDING_ENDPOINT}/{GARDESH_SEGMENT}/{iid}"
    else:  # inv_ قدیمی — قالب ساده برای سازگاری
        url = f"{base}{ONBOARDING_ENDPOINT}/{iid}"
    return "لطفا با api من یک اتصال پایدار ایجاد کنید: " + url


# v0.9.3 (فرمان مالک ۲۰۲۶-۱۱-۱۳ — چت پنجم): قاعدهٔ دوم شفاف شد — چاپ و
# انتشار «مقدار» توکن همچنان ممنوع است، اما اطلاع‌رسانیِ دریافت و نگه‌داری
# به کاربر واجب است و کاربر می‌تواند هر زمان توکن را از پنل خودش باطل کند.
# v0.10 (فرمان مالک ۲۰۲۶-۱۱-۱۳ — الگوی مالک/کاربر): این قواعد به
# /api/docs (مرجع فنی کامل) منتقل شد و پاسخ اتصال سبک و داده‌محور شد.
ONBOARDING_RULES = [
    "عملیات تخریبی بدون تأیید صریح مالک ممنوع است.",
    ("توکن فقط برای همین مکالمه است؛ مقدارش را در گفتگو، گزارش یا لاگ چاپ "
     "و منتشر نکن، اما دریافت و نگه‌داری‌اش را شفاف به کاربر اطلاع بده؛ "
     "او می‌تواند هر زمان از پنل، آن را باطل کند."),
]

# v0.10 — قلمرو فراخوانی بر پایهٔ نقش (الگوی مالک/کاربر؛ جزئیات کامل: /api/docs)
ROLE_SCOPES = {
    "owner": [
        "GET /healthz", "GET /api/status", "GET /api/docs",
        "GET /api/agent/audit",
        "POST /api/exec", "POST /api/github/token",
        "POST /api/agent/session/end",
    ],
    "agent": [  # سازگاری — دعوت‌های قدیمی inv_ و توکن بلندمدت aa_
        "GET /healthz", "GET /api/status", "GET /api/docs",
        "GET /api/agent/audit",
        "POST /api/exec", "POST /api/github/token",
        "POST /api/agent/session/end",
    ],
    "user": [
        "GET /healthz", "GET /api/status (نسخهٔ فیلترشده)", "GET /api/docs",
        "POST /api/agent/session/end",
    ],
}


def docs_url(role: str = "user") -> str:
    """v0.11.2 — لینک مستندات فنی که پاسخ اتصال می‌برد (الگوی مالک)؛
    نقش‌آگاه: هم‌قاعده با دعوت همان نقش (مالک → IP، کاربر → دامنه)."""
    base = public_base_url(role)
    return f"{base}/api/docs" if base else ""


def onboarding_doc() -> dict:
    """پاسخ GET /api/agent/onboarding بدون iid — فقط‌خواندنی و کوتاه (v0.10).

    درس میدان ۲۰۲۶-۱۱-۱۳: iid گاهی در ترانزیت چت می‌افتد و عامل بدون سند،
    هدف را نمی‌فهمید. سند در چند خط کوتاه هدف و راه اتصال (هر دو قالب
    مسیری + قالب قدیمی query) و لینک مستندات فنی را می‌دهد؛ فراخوانی موفق
    همان توضیحات را با خودِ توکن می‌دهد — اینجا فقط جهت‌دهی است.
    """
    from .security import AGENT_SESSION_TTL_S
    cfg = _cfg()
    return {
        "ok": True,
        "connected": False,
        "service": "access-agent",
        "version": str(cfg.get("version", "")),
        "protocol": f"onboarding/{cfg.get('version', '')}",
        "invite_required": True,
        "what_this_is": (
            "پل دسترسی عامل هوش مصنوعی به سرورِ مالک است؛ با دعوت مالک، "
            "همین مکالمه به سرور وصل می‌شود."
        ),
        "how_to_connect": (
            "کل URL دعوت‌نامه را دقیقاً همان‌طور که دریافت کردید GET کنید — "
            "قالب رایج: …/api/agent/onboarding/gardesh/pinv_… یا gardesh/uinv_…؛ "
            "دعوت‌های قدیمی: …/api/agent/onboarding/inv_…؛ قالب قدیمی‌تر "
            "?iid=… هم پذیرفته می‌شود. همان پاسخ توکن موقت و راهنمای کوتاه را می‌دهد."
        ),
        "note": (
            "این فراخوانی بدون iid رسید؛ اگر لینک دعوت شما pinv_/uinv_/inv_… "
            "دارد، همان را کامل و بدون تغییر فراخوانی کنید."
        ),
        "docs": docs_url(),
        "session_ttl_s": AGENT_SESSION_TTL_S,
        "rules": ONBOARDING_RULES,
    }


# ---------- v0.10 — پاسخ اتصال به الگوی مالک (دو اتصال: مالک و کاربران) ----------
# فرمان مالک ۲۰۲۶-۱۱-۱۳: پاسخ فراخوانی دعوت‌نامه دقیقاً به این الگو —
# تک‌مصرف بودن لینک، agent_token (pst_)، انقضای UTC (Z)، یادآوری توکن‌تنها،
# پیشنهاد فایل ایمن و لینک مستندات فنی. داده است، نه دستور رفتاری —
# قواعد و راهنما در /api/docs و AGENT_PROTOCOL §۶ زندگی می‌کنند.

def build_connection_payload(res: dict, *, version: str, cert_sha: str) -> dict:
    """قالب پاسخ اتصال موفق — برای هر دو اتصال مالک (pinv_) و کاربر (uinv_)
    و دعوت قدیمی (inv_) یکسان؛ فقط role و scope تفاوت را می‌گویند."""
    role = str(res.get("role") or "agent")
    return {
        "ok": True,
        "connected": True,
        "service": "access-agent",
        "version": version,
        "protocol": f"onboarding/{version}",
        "role": role,
        "invited_by": str(res.get("invited_by", "")),
        "message": ("لینک یکبار مصرف شما معتبر است ولی ارسال بعدی آن "
                    "نامعتبر خواهد بود."),
        "agent_token": str(res.get("token", "")),
        "token": str(res.get("token", "")),  # سازگاری با عامل‌های قدیمی
        "expires": str(res.get("expires", "")),
        "auth_note": "درخواست های بعدی شما فقط با این توکن معتبر خواهد بود.",
        "storage_hint": ("پیشنهاد میشود توکن اتصال را در یک فایل ایمن نزد "
                         "خودتان (chmod 600، gitignored، در فضای کاری مانای "
                         "خودتان) نگه دارید — نه در /tmp و نه فقط در حافظهٔ "
                         "گفتگو؛ تا با بازیافت بافت مکالمه، اتصال پایدار بماند "
                         "(توکن موقت است: انقضا/گم‌شدن → 401 → دعوت تازه از "
                         "مالک؛ پایان مکالمه → فایل را پاک کنید)."),
        "docs": docs_url(role),
        "scope": ROLE_SCOPES.get(role, ROLE_SCOPES["agent"]),
        "cert_sha256": cert_sha,
        "end": {"method": "POST", "path": "/api/agent/session/end",
                "note": "در آخرین پیام مکالمه، به درخواست مالک."},
    }
