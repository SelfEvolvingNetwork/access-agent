"""API technical reference — access_agent.apidocs (v0.11).

GET /api/docs (عمومی) — مرجع فنی کامل سرویس برای عامل‌های هوش مصنوعی.
الگوی مالک ۲۰۲۶-۱۱-۱۳: پاسخ اتصال فقط داده است (توکن/انقضا/لینک مستندات)؛
کل راهنمای فنی، قلمرو نقش‌ها، قواعد و خطوط قرمز این‌جا زندگی می‌کند.

v0.11 — پاکت هم‌شکل خانواده: بخش تازه family (نقشهٔ چهار سرویس/مخزن
+ رجیستر INDEX + متن بیداری ECOSYSTEM) و cold_start (زنجیرهٔ خواندن
عامل سرد) + next_reading برای هر نقش اتصال — داده در
access_agent.family زندگی می‌کند؛ متن کامل قرارداد:
docs/FAMILY_PACKETS.fa.md مخزن پرستو.

همه‌چیز داده است، نه دستور رفتاری — عامل‌ها مستندات را می‌خوانند و بر پایهٔ
درخواست صریح مالک/کاربر عمل می‌کنند. هیچ مقدار راز (توکن/iid) این‌جا نیست.
"""
from __future__ import annotations

from .family import cold_start_payload, family_payload, NEXT_READING
from .handoff import ONBOARDING_ENDPOINT, ONBOARDING_RULES, ROLE_SCOPES, docs_url
from .security import (AGENT_SESSION_TTL_S, AGENT_SESSIONS_MAX, INVITE_TTL_S_DEFAULT,
                       INVITE_TTL_S_MAX, INVITES_MAX,
                       OWNER_SESSION_TTL_S, SESSION_TTL_BY_ROLE,
                       USER_SESSION_TTL_S)

MAX_BODY_BYTES = 100_000  # همان سقف server.MAX_BODY — این‌جا تکرار می‌شود تا import چرخه نسازد


def docs_payload(version: str) -> dict:
    """پاکت مستندات فنی — با نسخهٔ سرویس همگام می‌ماند."""
    return {
        "ok": True,
        "service": "access-agent",
        "version": version,
        "protocol": f"onboarding/{version}",
        "language": "fa",
        "updated_for": "v0.11 (پاکت هم‌شکل خانواده)",

        "overview": (
            "پل دسترسی مستقل عامل هوش مصنوعی به سرور مالک — HTTPS + Bearer token. "
            "اتصال فقط با دعوت‌نامهٔ یک‌بارمصرف برقرار می‌شود (یک دعوت = یک عامل)؛ "
            "پاسخ ثبت‌نام، توکن موقت نقش‌دار را در همان نوبت می‌دهد. پس از ثبت‌نام، "
            "همهٔ فراخوانی‌ها با هدر Authorization: Bearer <agent_token> انجام می‌شوند."
        ),

        "roles": {
            "owner": {
                "invite_prefix": "pinv_",
                "token_prefix": "pst_",
                "ttl_s": OWNER_SESSION_TTL_S,
                "scope": ROLE_SCOPES["owner"],
                "next_reading": NEXT_READING["owner"],
                "description": (
                    "اتصال مالک: قلمرو کامل عامل — اجرای دستور روی هاست، وضعیت کامل، "
                    "گرفتن توکن گیت‌هاب. مالک دعوت‌نامه را با CLI (access-agent invite owner) "
                    "یا GET /api/admin/invite?role=owner می‌سازد."
                ),
            },
            "user": {
                "invite_prefix": "uinv_",
                "token_prefix": "pst_",
                "ttl_s": USER_SESSION_TTL_S,
                "scope": ROLE_SCOPES["user"],
                "next_reading": NEXT_READING["user"],
                "description": (
                    "اتصال کاربر: قلمرو محدود — /healthz و /api/status فیلترشده و "
                    "پایان نشست. اجرای دستور (POST /api/exec) و توکن گیت‌هاب "
                    "(POST /api/github/token) برای این نقش ممنوع است و 403 "
                    "agent_scope_forbidden می‌گیرد."
                ),
            },
            "agent": {
                "invite_prefix": "inv_",
                "token_prefix": "aagx_",
                "ttl_s": AGENT_SESSION_TTL_S,
                "scope": ROLE_SCOPES["agent"],
                "next_reading": NEXT_READING["agent"],
                "description": (
                    "سازگاری: دعوت‌های قدیمی (پیش از v0.10) و توکن بلندمدت aa_ — "
                    "قلمرو کامل عامل مانند owner."
                ),
            },
        },

        "onboarding": {
            "flow": [
                "1) مالک دعوت‌نامه می‌سازد: یک خط با URL دعوت",
                "2) عامل همان URL را GET می‌کند — خودِ iid اعتبار اتصال است (نه رمز، نه poll)",
                "3) دعوت با نخستین توکن مصرف می‌شود (یک دعوت = یک عامل؛ فراخوانی دوباره → 404)",
                "4) پاسخ: role + agent_token + expires (UTC, Z) + docs",
                "5) فراخوانی‌های بعدی فقط با Bearer token؛ انقضا/گم‌شدن → 401 → دعوت تازه",
                "6) آخرین پیام مکالمه: POST /api/agent/session/end (به درخواست مالک)",
            ],
            "url_forms": [
                f"{ONBOARDING_ENDPOINT}/gardesh/pinv_<iid>   # مالک (v0.10)",
                f"{ONBOARDING_ENDPOINT}/gardesh/uinv_<iid>   # کاربر (v0.10)",
                f"{ONBOARDING_ENDPOINT}/inv_<iid>            # قدیمی — سازگاری",
                f"{ONBOARDING_ENDPOINT}?iid=<iid>            # قدیمی — سازگاری",
            ],
            "invite_prefixes": {"pinv_": "مالک", "uinv_": "کاربر", "inv_": "قدیمی (سازگاری)"},
            "invite_ttl_s_default": INVITE_TTL_S_DEFAULT,
            "invite_ttl_s_max": INVITE_TTL_S_MAX,
            "invites_max_live": INVITES_MAX,
            "session_ttls_s": SESSION_TTL_BY_ROLE,
            "sessions_max_live": AGENT_SESSIONS_MAX,
        },

        "auth": {
            "type": "bearer",
            "header": "Authorization: Bearer <agent_token>",
            "note": (
                "توکن فقط در همین مکالمه معتبر است؛ مقدارش را در گفتگو/گزارش/لاگ چاپ "
                "و منتشر نکن، اما دریافت و نگه‌داری‌اش را شفاف به کاربر اطلاع بده؛ "
                "او می‌تواند هر زمان آن را از پنل باطل کند."
            ),
            "tls": (
                "گواهی TLS در مرحلهٔ راه‌اندازی (پیش از استقرار دامنه) خودامضاست؛ "
                "اتم اعتماد = تطبیق cert_sha256 پاسخ اتصال با گواهی واقعی سرور. "
                "پس از استقرار دامنه، گواهی معتبر عمومی جایگزین می‌شود."
            ),
        },

        "endpoints": [
            {"method": "GET", "path": "/", "auth": "عمومی",
             "description": "معرفی سرویس"},
            {"method": "GET", "path": "/healthz", "auth": "عمومی",
             "description": "سلامت سبک + cert_sha256 (پیوستگی هویت سرور)"},
            {"method": "GET", "path": "/api/docs", "auth": "عمومی",
             "description": "همین مرجع فنی"},
            {"method": "GET", "path": f"{ONBOARDING_ENDPOINT}[...]", "auth": "عمومی",
             "description": "ثبت‌نام با دعوت‌نامه — بدون iid: سند کوتاه؛ با iid: توکن نقش‌دار"},
            {"method": "GET", "path": "/api/status", "auth": "owner|user|agent",
             "description": "وضعیت میزبان — برای نقش user نسخهٔ فیلترشده (بدون مسیرها و جزئیات داخلی)"},
            {"method": "POST", "path": "/api/exec", "auth": "owner|agent",
             "description": "اجرای دستور روی هاست — body: {cmd, timeout_s<=600, cwd}؛ برای user ممنوع (403)"},
            {"method": "POST", "path": "/api/github/token", "auth": "owner|agent",
             "description": "توکن موقت گیت‌هاب برای پوش — body: {purpose[, ttl_min<=60]}؛ برای user ممنوع (403)"},
            {"method": "POST", "path": "/api/agent/session/end", "auth": "owner|user|agent",
             "description": "پایان همین نشست — هیچ اعتباری روی سرور نمی‌ماند"},
            {"method": "GET", "path": "/api/admin/invite", "auth": "ادمین",
             "description": "ساخت دعوت‌نامه — ?role=owner|user (پیش‌فرض user) + ?for=<برچسب> + ?ttl_h=1..168"},
            {"method": "POST", "path": "/api/admin/revoke-agent-sessions", "auth": "ادمین",
             "description": "ابطال همهٔ نشست‌های موقت عامل (کلید اضطراری)"},
            {"method": "GET", "path": "/api/admin/audit", "auth": "ادمین",
             "description": "دم audit — ?tail=N"},
            {"method": "GET", "path": "/api/admin/audit/stream", "auth": "ادمین",
             "description": "SSE زندهٔ audit — ?cursor=<بایت> ?backfill=N"},
            {"method": "GET", "path": "/api/admin/sessions", "auth": "ادمین",
             "description": "سابقهٔ grantهای گیت‌هاب"},
            {"method": "GET", "path": "/api/admin/agent-token", "auth": "ادمین",
             "description": "متادیتای توکن عامل — هرگز خودِ مقدار"},
            {"method": "POST", "path": "/api/admin/rotate-agent-token", "auth": "ادمین",
             "description": "چرخش توکن بلندمدت عامل — مقدار تازه یک بار چاپ می‌شود"},
            {"method": "POST", "path": "/api/admin/revoke-agent-token", "auth": "ادمین",
             "description": "غیرفعال‌سازی قلمرو عامل تا چرخش بعدی"},
            {"method": "POST", "path": "/api/admin/agent-realm/pause", "auth": "ادمین",
             "description": "کلید توقف قلمرو عامل — body: {paused, reason}؛ ماندگار"},
            {"method": "GET", "path": "/api/admin/handoff", "auth": "ادمین",
             "description": "بلوک تحویل قدیمی (<=0.6.x) — فقط سازگاری"},
            {"method": "POST", "path": "/api/admin/set-github-token", "auth": "ادمین",
             "description": "ذخیرهٔ PAT مالک — body: {token}"},
            {"method": "GET", "path": "/api/admin/parastoo/lifecycle-status", "auth": "ادمین",
             "description": "وضعیت چرخهٔ عمر پرستو"},
            {"method": "GET", "path": "/api/admin/parastoo/setup-token", "auth": "ادمین",
             "description": "توکن ویزارد نصب برای اپ موبایل"},
            {"method": "POST", "path": "/api/admin/parastoo/install|uninstall|reinstall|update",
             "auth": "ادمین", "description": "چرخهٔ عمر پرستو — تخریبی‌ها با confirm"},
            {"method": "POST", "path": "/api/admin/bridge/uninstall", "auth": "ادمین",
             "description": "حذف کامل خود پل — نیاز به {\"confirm\": \"uninstall\"}"},
            {"method": "GET", "path": "/api/admin/app/core-config", "auth": "ادمین",
             "description": "هستهٔ دادهٔ هات اپ موبایل"},
        ],

        "errors": {
            "model": {"ok": False, "error": "<code>", "detail": "<توضیح فارسی یک‌خطی>"},
            "codes": {
                "400": "bad_json | cmd_required | timeout_out_of_range | ...",
                "401": "unauthorized — توکن مفقود/نامعتبر/منقضی → دعوت تازه از مالک",
                "403": "forbidden (نیاز به ادمین) | agent_realm_paused | agent_scope_forbidden (نقش user)",
                "404": "not_found | unknown_invite (ناشناخته/منقضی/مصرف‌شده)",
                "405": "method_not_allowed",
                "409": "lifecycle_busy | invite_unavailable",
                "410": "مسیر بازنشسته",
                "413": "body_too_large",
                "429": "rate_limited (خطای iid؛ حداکثر ۱۰ در ۵ دقیقه از هر IP) | busy (exec)",
            },
        },

        "limits": {
            "body_bytes": MAX_BODY_BYTES,
            "cmd_chars": 16384,
            "exec_timeout_s_max": 600,
            "exec_output_chars": 200000,
            "exec_concurrent_max": 2,
            "github_token_ttl_min_max": 60,
        },

        "conventions": {
            "content_type": "application/json; charset=utf-8",
            "timestamps": "ISO-8601؛ انقضای نشست/توکن همیشه UTC با پسوند Z",
            "audit": "هر فراخوانی در audit.jsonl ثبت می‌شود — بدون هیچ مقدار توکن/iid",
            "secrets_on_disk": "فقط SHA-256؛ توکن خام هرگز ذخیره/لاگ نمی‌شود",
        },

        "rules": ONBOARDING_RULES,
        "red_lines": [
            "عملیات تخریبی (حذف پل، حذف پرستو، uninstall) بدون تأیید صریح مالک ممنوع است.",
            "توکن/کد ادمین هرگز از مسیر عامل نمی‌آید و عامل آن را درخواست نمی‌کند.",
            "مقدار توکن/iid هرگز در گفتگو، گزارش یا لاگ چاپ نمی‌شود.",
        ],
        "family": family_payload(),
        "cold_start": cold_start_payload(),
        "docs": docs_url(),
    }
