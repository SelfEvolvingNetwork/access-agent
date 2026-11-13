"""Owner→AI handoff — access_agent.handoff (v0.9).

v0.9 (فرمان مالک ۲۰۲۶-۱۱-۱۳ — حذف تشریفات): دعوت‌نامهٔ یک‌خطی فقط URL آشناسازی
با iid را دارد؛ خودِ iid اعتبار اتصال است و GET همان URL مستقیماً توکن موقت
نشست عامل را صادر می‌کند — نه رمز تأییدی، نه poll. این ماژول بلوک تحویل قدیمی
(<=0.6.x)، دعوت‌نامهٔ یک‌خطی و سند کوتاه آشناسازی را می‌سازد. هرگز با شبکه
تماس نمی‌گیرد و هرگز توکن ادمین برنمی‌گرداند.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

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
        f"ACCESS_URL:  https://{cfg['ip']}:{cfg['port']}\n"
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
ONBOARDING_ENDPOINT = "/api/agent/onboarding"


def invite_missing_inputs() -> list[str]:
    cfg = _cfg()
    miss: list[str] = []
    if not (cfg.get("ip") and cfg.get("port")):
        miss.append("config.json(ip/port)")
    if not cert_fingerprint():
        miss.append("tls/cert.pem")
    return miss


def build_invite(iid: str) -> str:
    """v0.9 — دعوت‌نامهٔ یک‌خطی به فرمان مالک (۲۰۲۶-۱۱-۱۳).

    متن دعوت فقط همین یک خط است — هیچ رمز/هش/توضیح اضافه ندارد؛ سرور پس از
    فراخوانی لینک، خودش توضیحات لازم را در همان پاسخ می‌دهد (توکن موقت +
    راهنمای کوتاه). TTL و برچسب کاربر در پاسخ JSON مسیر ادمین می‌مانند.
    """
    miss = invite_missing_inputs()
    if miss:
        raise RuntimeError("invite data missing: " + ", ".join(miss))
    if not iid or not iid.startswith("inv_"):
        raise RuntimeError("invite id missing — mint one via security.mint_invite")
    cfg = _cfg()
    return ("لطفا این لینک را دنبال کنید: "
            f"https://{cfg['ip']}:{cfg['port']}{ONBOARDING_ENDPOINT}?iid={iid}")


ONBOARDING_RULES = [
    "عملیات تخریبی بدون تأیید صریح مالک ممنوع است.",
    "توکن فقط برای همین مکالمه است؛ منتشرش نکن و در گزارش‌ها ننویسش.",
]


def onboarding_doc() -> dict:
    """پاسخ GET /api/agent/onboarding بدون iid — فقط‌خواندنی و کوتاه (v0.9.1).

    درس میدان ۲۰۲۶-۱۱-۱۳ (چت دوم مالک): iid گاهی در ترانزیت چت می‌افتد و عامل
    بدون سند، هدف را نمی‌فهمید. سند حالا در سه خط کوتاه هدف و راه اتصال و
    راهنمایِ «کل URL را کامل بفرست» را می‌دهد — فراخوانی موفق همان توضیحات
    را با خودِ توکن می‌دهد؛ اینجا فقط جهت‌دهی است (فرمان مالک: مختصر، پس از
    فراخوانی متد، برای اعتمادسازی).
    """
    from .security import AGENT_SESSION_TTL_S
    cfg = _cfg()
    return {
        "ok": True,
        "connected": False,
        "service": "access-agent",
        "version": str(cfg.get("version", "")),
        "protocol": "onboarding/0.9.1",
        "invite_required": True,
        "what_this_is": (
            "پل دسترسی عامل هوش مصنوعی به سرورِ مالک است؛ با دعوت مالک، "
            "همین مکالمه به سرور وصل می‌شود."
        ),
        "how_to_connect": (
            "کل URL دعوت‌نامه را — همراه ?iid=… — دقیقاً همان‌طور که "
            "دریافت کردید GET کنید؛ همان پاسخ توکن موقت و راهنمای کوتاه را می‌دهد."
        ),
        "note": (
            "این فراخوانی بدون iid رسید؛ اگر لینک دعوت شما ?iid=inv_… دارد، "
            "همان را کامل و بدون تغییر فراخوانی کنید."
        ),
        "session_ttl_s": AGENT_SESSION_TTL_S,
        "rules": ONBOARDING_RULES,
    }
