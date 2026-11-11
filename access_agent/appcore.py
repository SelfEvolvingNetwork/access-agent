"""app-core — هستهٔ داده‌محورِ پرستو موبایل (v0.5.8؛ فرمان مالک: «بخشی از اپ
بدون نصب مجدد به‌روز شود و بستر یک بار نصب‌شده بماند»).

اپ 0.4.12+ یک «هستهٔ هات» دارد: یک فایل JSON نسخه‌دار شامل نقشهٔ endpointها،
متن‌های مجازِ انتخابی و فلگ‌ها که از همین پل روی کانال TLS پین‌شده با توکن
ادمین واکشی می‌شود. پوستهٔ اپ (کد امضاشدهٔ APK) یک بار نصب می‌ماند؛ این داده
بدون بیلد تازه به‌روز می‌شود — کاربر هرگز برای تغییرِ داده مجبور به نصب
مجدد نیست.

قواعد امنیتی (سخت‌گیرانه؛ در اپ هم مستقل از این‌جا اعمال می‌شود):
- فقط داده — هیچ کد اجرایی در این فایل جایی ندارد؛ اپ هرگز چیزی را eval
  نمی‌کند و فقط «نقشه/متن/فلگ» را با اعتبارسنجی سخت می‌خواند.
- فقط ادمین — قلمرو عامل حق واکشی این مسیر را ندارد.
- «endpoint» باید با «/» شروع شود؛ «..»، فاصله و مسیر نسبی ممنوع.
- allowlist متن‌ها: فقط متن‌های توصیفیِ غیرتأییدی هات می‌شوند؛ کلمهٔ تأیید
  دولایه، عنوان/برچسب کنش‌های تخریبی و آدرس سرور هرگز از این کانال عوض
  نمی‌شوند (در اپ هم allowlist دومی هست — گارد دوگانه).
- فایل اورراید: ACCESS_AGENT_HOME/app-core/core.json — اگر نامعتبر بود کل
  فایل نادیده گرفته می‌شود و به پیش‌فرض جاسازی‌شده برمی‌گردیم (note در پاسخ).
  ادغام جزئی نداریم: یا کل فایل معتبر است یا هیچ.
- sha256 پوشش دقیقِ متنِ config_json است — اپ همان بایت دریافتی را هش
  می‌کند؛ خرابی کش یا دستکاری در مسیر، در اپ رد می‌شود.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .security import home

SCHEMA = "parastoo-core/1"

# کلیدهای مجاز متن هات — فقط توضیحاتِ غیرتأییدیِ جریان حذف پل؛ عنوان/برچسب/
# کلمهٔ تأیید هات نمی‌شوند (گارد سمت پل؛ گارد دوم در CoreConfig.kt اپ).
STRING_ALLOWLIST = {
    "bridge_uninstall_card_subtitle",
    "bridge_uninstall_confirm_body",
    "bridge_uninstall_scheduled_body",
}

_KEY_RE = re.compile(r"^[a-z0-9_]{1,40}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./?=&]{1,119}$")

# پیش‌فرض جاسازی‌شده — با assets/core/parastoo-core.json اپ هم‌نگه داشته می‌شود.
DEFAULT_PAYLOAD: dict = {
    "schema": SCHEMA,
    "revision": 3,
    "min_version_code": 17,  # اپ 0.4.12 — اولین نسخه با موتور هستهٔ هات
    "config": {
        "endpoints": {
            "healthz": "/healthz",
            "status": "/api/status",
            "audit": "/api/admin/audit",
            "audit_stream": "/api/admin/audit/stream",
            "agent_token": "/api/admin/agent-token",
            "rotate_agent_token": "/api/admin/rotate-agent-token",
            "revoke_agent_token": "/api/admin/revoke-agent-token",
            "pause_realm": "/api/admin/agent-realm/pause",
            "handoff": "/api/admin/handoff",
            "agent_approve": "/api/admin/agent-approve",
            "revoke_agent_sessions": "/api/admin/revoke-agent-sessions",
            "parastoo_lifecycle_status": "/api/admin/parastoo/lifecycle-status",
            "parastoo_setup_token": "/api/admin/parastoo/setup-token",
            "set_github_token": "/api/admin/set-github-token",
            "parastoo_action": "/api/admin/parastoo/",
            "bridge_uninstall": "/api/admin/bridge/uninstall",
            "core_config": "/api/admin/app/core-config",
        },
        "strings": {
            "bridge_uninstall_card_subtitle":
                "این متن از هستهٔ هاتِ پل (revision 3) می‌آید، نه از APK — پس از حذف "
                "کامل پرستو، پل هم خودش را پاک می‌کند و هیچ دسترسی راه‌دوری باقی "
                "نمی‌ماند.",
            "bridge_uninstall_confirm_body":
                "این آخرین فرمان است و بازگشتی ندارد: پل کد، توکن‌های ادمین و عامل، "
                "گواهی، گاوصندوق گیت‌هاب و گزارش رویدادهای خودش را برای همیشه پاک "
                "می‌کند. بعد از آن هیچ‌کس — حتی این اپ — از راه دور وارد سرور "
                "نمی‌شود و اتصال وسط کار قطع می‌شود (این خودش نشانهٔ موفقیت است). "
                "تنها راه بازگشت: جریان «افزودن سرور» با رمز root. برای تأیید "
                "بنویسید: حذف پل",
            "bridge_uninstall_scheduled_body":
                "پل دارد خودش و همهٔ راز‌هایش را پاک می‌کند؛ از این لحظه پاسخ "
                "نگرفتن این سرور «عادی» است — هیچ توکنی دیگر معتبر نیست و هیچ‌کس "
                "از راه دور وارد نمی‌شود. برای برگشتن، از «افزودن سرور» با رمز "
                "root شروع کنید — مثل اولین روز.",
        },
        "flags": {
            "bridge_self_destruct_visible": True,
        },
    },
}

_MAX = {"endpoints": 48, "strings": 96, "flags": 48}


def _config_ok(cfg) -> tuple[bool, str]:
    """اعتبارسنجی سخت‌گیرانهٔ بخش config — رد کامل یا قبول کامل."""
    if not isinstance(cfg, dict):
        return False, "config is not an object"
    for section, cap in _MAX.items():
        val = cfg.get(section, {})
        if not isinstance(val, dict):
            return False, f"{section} is not an object"
        if len(val) > cap:
            return False, f"{section} too large (>{cap})"
    for k, v in (cfg.get("endpoints") or {}).items():
        if not isinstance(k, str) or not _KEY_RE.match(k):
            return False, f"bad endpoint key: {str(k)[:40]!r}"
        if not isinstance(v, str) or not _PATH_RE.match(v) or ".." in v:
            return False, f"bad endpoint path: {str(v)[:40]!r}"
    for k, v in (cfg.get("strings") or {}).items():
        if not isinstance(k, str) or k not in STRING_ALLOWLIST:
            return False, f"string key not allowed: {str(k)[:40]!r}"
        if not isinstance(v, str) or not v.strip() or len(v) > 600:
            return False, f"bad string value for {k}"
    for k, v in (cfg.get("flags") or {}).items():
        if not isinstance(k, str) or not _KEY_RE.match(k):
            return False, f"bad flag key: {str(k)[:40]!r}"
        if not isinstance(v, bool):
            return False, f"flag {k} is not boolean"
    return True, ""


def _payload_ok(payload) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, "payload is not an object"
    if payload.get("schema") != SCHEMA:
        return False, "schema mismatch"
    rev = payload.get("revision")
    if not isinstance(rev, int) or isinstance(rev, bool) or rev < 1:
        return False, "revision must be int >= 1"
    mvc = payload.get("min_version_code", 0)
    if not isinstance(mvc, int) or isinstance(mvc, bool) or mvc < 0:
        return False, "min_version_code must be int >= 0"
    return _config_ok(payload.get("config"))


def _canonical(cfg: dict) -> str:
    """متن متعارف — هش روی همین متن سمت اپ با بایت‌های دریافتی چک می‌شود."""
    return json.dumps(cfg, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read_override() -> tuple[dict | None, str]:
    p = Path(home()) / "app-core" / "core.json"
    if not p.exists():
        return None, ""
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
        ok, why = _payload_ok(payload)
        if not ok:
            return None, f"override ignored ({why})"
        return payload, "override"
    except Exception as e:
        return None, f"override ignored ({type(e).__name__})"


def snapshot() -> dict:
    """پاکت آمادهٔ سرو به اپ — کل فایل معتبر یا پیش‌فرض جاسازی‌شده."""
    override, note = _read_override()
    if override is None:
        payload = DEFAULT_PAYLOAD
        source = "default"
    else:
        payload = override
        source = "override"
    cfg_json = _canonical(payload["config"])
    env: dict = {
        "ok": True,
        "schema": SCHEMA,
        "revision": payload["revision"],
        "min_version_code": payload.get("min_version_code", 0),
        "sha256": _sha256_hex(cfg_json),
        "config_json": cfg_json,
        "source": source,
    }
    if note:
        env["note"] = note  # فقط وقتی اورراید نامعتبر نادیده گرفته شد
    return env
