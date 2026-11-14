"""نقشهٔ خانوادهٔ پرستو — access_agent.family (v0.11).

قرارداد «پاکت هم‌شکل» (توافق مالک–عامل ۲۰۲۶-۱۱-۱۴): هر سرویس زندهٔ
خانواده یک مرجع فنی خودمعرف (GET /api/docs) با شکل واحد دارد و هر مخزن
سند مرجع یکتای خود را. عامل سرد برای درک کل اکوسیستم فقط پاکت‌های docs
را می‌خواند — کد یک سرویس فقط وقتی خوانده می‌شود که رفتار با قرارداد
ناسازگار باشد؛ داورِ «باگ کد یا کهنگی قرارداد» تست‌های قراردادی
(اسموک)‌اند. متن کامل قرارداد: docs/FAMILY_PACKETS.fa.md مخزن پرستو.

این ماژول فقط داده است — هیچ رازی ندارد و هیچ متغیر محیطی نمی‌خواند.
همگمی با INDEX پرستو (§۱ و §۵-۳): متن بیداری/ورود این‌جا تکرار
نمی‌شود؛ فقط اشاره‌گر به INDEX/ECOSYSTEM/ROLES. مبدأ نقش هر مخزن،
جدول INDEX §۱ است — متن‌ها عیناً همان‌جا ماندگارند.
"""
from __future__ import annotations

from .handoff import ECOSYSTEM_URL, PROTOCOL_URL, docs_url

FAMILY_NAME = "پرستو (SelfEvolvingNetwork)"

# رجیستر خانواده و درگاه‌های ورود — هرگز نسخه/وضعیت زنده این‌جا نمی‌نشیند (INDEX §۴)
INDEX_URL = ("https://github.com/SelfEvolvingNetwork/parastoo/"
             "blob/main/docs/INDEX.fa.md")
ROLES_URL = ("https://github.com/SelfEvolvingNetwork/parastoo/"
             "blob/main/docs/ROLES.fa.md")
CONTRACT_URL = ("https://github.com/SelfEvolvingNetwork/parastoo/"
                "blob/main/docs/FAMILY_PACKETS.fa.md")

FAMILY_PRINCIPLE = (
    "هر سرویس زندهٔ خانواده یک مرجع فنی خودمعرف دارد (GET /api/docs؛ "
    "هم‌شکل: service/version/language/overview/roles/endpoints/errors/"
    "limits/family/cold_start) و هر مخزن هم سند مرجع یکتای خود را. "
    "عامل سرد نقش خود را از ROLES انتخاب می‌کند و فقط مسیر نقش خودش را "
    "می‌خواند؛ متن بیداری یکتا: ECOSYSTEM. پاکت نقشه است، نه محتوا — "
    "شرح عمیق هر سطح فقط در سند مرجع خودش زندگی می‌کند. کد یک سرویس فقط "
    "وقتی خوانده می‌شود که رفتار با این قرارداد ناسازگار باشد؛ داورِ "
    "«باگ کد یا کهنگی قرارداد» تست‌های قراردادی (اسموک)‌اند."
)

# نقش‌ها عیناً از جدول INDEX §۱ — مبدأ همان‌جاست، این‌ها رونوشت‌اند
FAMILY_SERVICES = [
    {
        "name": "access-agent",
        "kind": "سرویس زنده (systemd، بیرون از داکر)",
        "role": ("پل ادمین مستقل — تنها درگاه فرمان عامل به سرور "
                 "(از مرگ پرستو جان می‌بارد)"),
        "repo": "https://github.com/SelfEvolvingNetwork/access-agent",
        "docs": "GET /api/docs همین سرویس",
        "protocol": PROTOCOL_URL,
    },
    {
        "name": "parastoo",
        "kind": "سرویس زنده (داکر)",
        "role": ("هستهٔ پلتفرم سایت‌ساز: پنل، پل عامل پروژه، DNS/TLS، "
                 "بیلد و انتشار"),
        "repo": "https://github.com/SelfEvolvingNetwork/parastoo",
        "docs": ("GET /api/docs روی خود پنل (پاکت هم‌شکل؛ آدرس پنل: "
                 "panel.<دامنهٔ نصب> — دامنهٔ نصب روی سرور در "
                 "/etc/parastoo-domain؛ پیش‌فرض zeolitecenter.ir)"),
        "protocol": ("https://github.com/SelfEvolvingNetwork/parastoo/"
                     "blob/main/docs/AGENT_BRIDGE.fa.md"),
    },
    {
        "name": "parastoo-workbench",
        "kind": "ابزار فقط-سرور (بدون سرویس HTTP — سند مرجع، نه اندپوینت)",
        "role": ("کارگاه/سندباکس دائمی عامل روی سرور مالک "
                 "(توسعهٔ زادهٔ سرور)"),
        "repo": "https://github.com/SelfEvolvingNetwork/parastoo-workbench",
        "docs": ("https://github.com/SelfEvolvingNetwork/parastoo-workbench/"
                 "blob/main/docs/WORKBENCH.fa.md"),
        "protocol": ("https://github.com/SelfEvolvingNetwork/"
                     "parastoo-workbench/blob/main/docs/SERVER_ONLY.fa.md"),
    },
    {
        "name": "parastoo-mobile",
        "kind": "اپ اندروید (مصرف‌کنندهٔ API — سرویس نیست)",
        "role": "اپ اندروید مدیریت و مانیتورینگ سرور",
        "repo": "https://github.com/SelfEvolvingNetwork/parastoo-mobile",
        "docs": ("https://github.com/SelfEvolvingNetwork/"
                     "parastoo-mobile/blob/main/README.md"),
        "protocol": ("https://github.com/SelfEvolvingNetwork/parastoo/"
                     "blob/main/docs/PARASTOO_MOBILE.fa.md"),
    },
]

COLD_START_STEPS = [
    ("۱) نقش خود را از ROLES.fa.md انتخاب کن (A1/A2/I1..I5 یا انسان) و "
     "فقط مسیر همان نقش را بخوان — قاعدهٔ ضد توکن‌سوزی"),
    ("۲) پاکت docs سرویسی که با آن کار می‌کنی (همین پاکت): قلمرو نقش، "
     "اندپوینت‌ها، خطاها، سقف‌ها، خطوط قرمز"),
    ("۳) برای هر سرویس/مخزن دیگر خانواده فقط فیلد docs همان سرویس را "
     "بخوان (family.services) — نه کل مخزن را"),
    ("۴) کلیت در ۶۰ ثانیه: ECOSYSTEM.fa.md · نقشهٔ کامل «موضوع → سند "
     "مرجع»: INDEX.fa.md §۳"),
]

# نقش‌های اتصال همین سرویس → خواندن بعدی (داده است، نه دستور رفتاری)
NEXT_READING = {
    "owner": [
        "اندپوینت‌های قلمرو خودت در همین پاکت: endpoints (دقت کن auth هر ردیف)",
        "قرارداد کامل همین پل: AGENT_PROTOCOL.fa.md (§۴ exec، §۵ توکن گیت‌هاب)",
        "نقش اکوسیستمی خودت را از ROLES.fa.md انتخاب کن (معمولاً A1؛ کلاه I1..I5)",
    ],
    "user": [
        "قلمرو تو در همین پاکت کافی است: /healthz و /api/status (فیلترشده)",
        "پایان مکالمه: POST /api/agent/session/end",
    ],
    "agent": [
        "اندپوینت‌های قلمرو خودت در همین پاکت: endpoints (دقت کن auth هر ردیف)",
        "قرارداد کامل همین پل: AGENT_PROTOCOL.fa.md",
        "نقش اکوسیستمی خودت را از ROLES.fa.md انتخاب کن",
    ],
}


def family_payload() -> dict:
    """v0.11 — بخش خانواده برای پاکت /api/docs؛ فقط داده و اشاره‌گر."""
    services: list[dict] = []
    for svc in FAMILY_SERVICES:
        entry = dict(svc)
        if svc["name"] == "access-agent":  # خودارجاعی: URL زندهٔ خودمان
            entry["docs_url"] = docs_url() or "/api/docs"
        services.append(entry)
    return {
        "name": FAMILY_NAME,
        "principle": FAMILY_PRINCIPLE,
        "registry": INDEX_URL,          # مبدأ رجیستر خانواده (INDEX §۱)
        "ecosystem": ECOSYSTEM_URL,     # متن بیداری یکتا
        "roles": ROLES_URL,             # انتخاب نقش عامل سرد
        "contract": CONTRACT_URL,       # متن کامل قرارداد پاکت هم‌شکل
        "services": services,
    }


def cold_start_payload() -> dict:
    """v0.11 — زنجیرهٔ خواندن عامل سرد؛ داده است، نه دستور رفتاری."""
    return {"steps": list(COLD_START_STEPS)}
