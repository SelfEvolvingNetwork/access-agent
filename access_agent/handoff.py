"""Owner→AI handoff block — access_agent.handoff (v0.1.3).

Field decision 2026-11-05: after install the owner should have ONE thing to
copy into the chat with the AI agent — not three values to retype. This module
composes that ready-to-paste block from files under ACCESS_AGENT_HOME
(config.json, tls/cert.pem, secrets/agent-token). It never contacts the
network and never returns the admin token.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

PROTOCOL_URL = ("https://raw.githubusercontent.com/SelfEvolvingNetwork/"
                "access-agent/main/docs/AGENT_PROTOCOL.fa.md")
PARASTOO_LOOP_URL = ("https://raw.githubusercontent.com/SelfEvolvingNetwork/"
                     "parastoo/main/docs/AI_AGENT_LOOP.md")
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
