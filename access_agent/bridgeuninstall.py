"""حذف خود پل — access_agent.bridgeuninstall (v0.5.7، فرمان مالک 2026-11-09).

آخرین گام سفر «نقطهٔ صفر»: پس از این که پرستو کامل حذف شد و موبایل آن را دید،
مالک از پرستو موبایل دستور «پاک کردن پل» می‌دهد. پل باید خودش را — کد، راز‌ها،
توکن‌ها (ادمین + عامل)، گواهی TLS، vault گیت‌هاب و کل audit — برای همیشه پاک
کند. پس از این فرمان **هیچ‌کس** از راه دور نمی‌تواند وارد سرور شود: نه اپ،
نه عامل هوش مصنوعی، نه پنل. تنها راه بازگشت، جریان «افزودن سرور» اپ با رمز
root است (قرارداد «رمز روت = مالکیت») — مثل اولین روز.

قراردادهای غیرقابل‌مذاکره:
- فقط قلمرو ادمین (گارد در server.py)؛ قلمرو عامل هرگز حق حذف پل را ندارد.
- بدنهٔ تخریبی باید {"confirm": "uninstall"} دقیق باشد (همان قرارداد جفت
  تخریبی lifecycle؛ دفاع در عمق، گاهِ اصلی خود توکن ادمین است).
- هم‌زمانی با lifecycle پرستو: تا یک عملیات پرستو در جریان است، 409 lifecycle_busy
  (بازیگرِ متغیرِ واحد).
- قرارداد بقا (contract of survival): uninstall.sh --purge خودش
  `systemctl stop access-agent` را اجرا می‌کند و همین پروسهٔ سرور را می‌کُشد —
  پس حذف نمی‌تواند thread فرزندِ همین پروسه باشد (KillMode پیش‌فرض systemd کل
  cgroup سرویس را می‌کُشد). راه درست: `systemd-run --on-active` یک واحد oneshot
  گذرا با cgroup مستقل می‌سازد که چند ثانیه پس از ارسال پاسخ HTTP شعله‌ور
  می‌شود و از مرگ سرویس جان سالم به‌در می‌برد. ترتیب: پاسخ → جانِ ۶ ثانیه‌ای →
  پاک‌سازی.
- هیچ فایلی از خروجی پاک‌سازی روی دیسک نمی‌ماند — فقط journaldِ سیستم. نقطهٔ
  صفر یعنی صفرِ اثر؛ پس از پاک‌سازی حتی audit پل هم دیگر موجود نیست. قطع شدن
  اتصالِ اپِ بلافاصله بعد، خودش «اطلاع‌رسانی» است: اپ باید «پاسخ نگرفتن» را
  نتیجهٔ مورد انتظار بداند، نه خطا.
- حذف فقط از مسیر رسمی uninstall.sh --purge می‌رود؛ هیچ منطق حذفی این‌جا
  بازنویسی نمی‌شود.

قلاب‌های تست (آفلاین): ACCESS_AGENT_BRIDGE_UNINSTALL_CMD (کل فرمانِ زمان‌بندی‌شده
را جایگزین می‌کند — بدون systemd)، ACCESS_AGENT_BRIDGE_OPT (ریشهٔ نصب)،
ACCESS_AGENT_BRIDGE_SUDO.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from . import parastoolifecycle
from .security import audit, now_iso

CONFIRM_WORD = "uninstall"
GRACE_SECONDS = 6          # پاسخ HTTP باید حتماً پیش از این رسیده باشد
UNIT_NAME = "access-agent-self-purge"
RAW_URL = (
    "https://raw.githubusercontent.com/SelfEvolvingNetwork/access-agent/main/uninstall.sh"
)
RAW_PROXY = f"https://gh-proxy.com/{RAW_URL}"


def _sudo() -> str:
    override = os.environ.get("ACCESS_AGENT_BRIDGE_SUDO")
    if override is not None:
        return override
    return "" if os.geteuid() == 0 else "sudo "


def _opt() -> Path:
    """ریشهٔ نصب پل روی همین هاست — پیش‌فرض: والدِ بستهٔ پایتونِ در حال اجرا."""
    override = os.environ.get("ACCESS_AGENT_BRIDGE_OPT")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent


def _local_uninstall_script() -> Path | None:
    p = _opt() / "uninstall.sh"
    return p if p.is_file() else None


def _fetch_uninstall_script() -> Path | None:
    """فالبک برای نصب‌های قدیمی که uninstall.sh را محلی ندارند (v0.5.4 و قبل‌تر
    فقط access_agent/ را کپی می‌کردند). فایل موقت است — فرمانِ زمان‌بندی‌شده
    خودش بعد از اجرا پاکش می‌کند؛ اثری روی دیسک نمی‌ماند."""
    tmp = Path("/tmp/access-agent-uninstall.sh")
    for url in (RAW_URL, RAW_PROXY):
        try:
            subprocess.run(
                ["curl", "-fsSL", "--retry", "2", "--max-time", "120",
                 "-o", str(tmp), url],
                check=True, timeout=150,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if tmp.is_file() and tmp.stat().st_size > 0:
                return tmp
        except Exception:
            continue
    return None


def _scheduled_command(script: Path) -> str:
    """فرمانِ واحدِ گذرا: جانِ ۶ ثانیه‌ای، بعد uninstall.sh رسمی با --purge.
    بعد از اجرا، فایل اسکریپت هم پاک می‌شود (اگر فالبکِ دانلودی باشد)."""
    s = _sudo()
    return (
        f"{s}systemd-run --unit={UNIT_NAME} --on-active={GRACE_SECONDS}s "
        f"--description='access-agent self-purge (owner command)' "
        f"{s}bash {script} --purge && {s}rm -f {script}"
    )


def schedule(confirm: str) -> dict:
    """اعتبارسنجی و زمان‌بندی حذف خود پل. خروجی HTTP-مپ است (server.py)."""
    if confirm != CONFIRM_WORD:
        return {"ok": False, "error": "confirm_required",
                "detail": f'body must contain {{"confirm": "{CONFIRM_WORD}"}}',
                "status": 400}
    if parastoolifecycle.is_busy():
        return {"ok": False, "error": "lifecycle_busy",
                "detail": "a parastoo lifecycle operation is running — the bridge "
                          "refuses to delete itself mid-operation; poll "
                          "/api/admin/parastoo/lifecycle-status",
                "status": 409}

    script = _local_uninstall_script() or _fetch_uninstall_script()
    cmd_override = os.environ.get("ACCESS_AGENT_BRIDGE_UNINSTALL_CMD")
    if cmd_override:
        cmd = cmd_override          # تست آفلاین: کل فرمان جایگزین می‌شود
    else:
        if script is None:
            return {"ok": False, "error": "uninstall_script_missing",
                    "detail": "uninstall.sh neither local nor fetchable — update "
                              "the bridge first (v0.5.7 copies it into the install tree)",
                    "status": 503}
        if not shutil.which("systemd-run"):
            return {"ok": False, "error": "systemd_missing",
                    "detail": "the bridge self-purge requires systemd-run (the "
                              "purge must survive the service stop; a child "
                              "process of the server would die with its cgroup)",
                    "status": 503}
        cmd = _scheduled_command(script)

    try:
        proc = subprocess.run(
            ["bash", "-c", cmd], capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL,
        )
    except Exception as e:
        audit("admin", "admin_bridge_uninstall_fail",
              {"error": type(e).__name__}, "internal")
        return {"ok": False, "error": "schedule_failed",
                "detail": str(e)[:200], "status": 500}
    if proc.returncode != 0:
        audit("admin", "admin_bridge_uninstall_fail",
              {"exit_code": proc.returncode,
               "stderr_preview": (proc.stderr or "")[:200]}, "internal")
        return {"ok": False, "error": "schedule_failed",
                "detail": (proc.stderr or proc.stdout or "")[:200],
                "status": 500}

    audit("admin", "admin_bridge_uninstall_start",
          {"grace_s": GRACE_SECONDS, "unit": UNIT_NAME}, "internal")
    return {
        "ok": True,
        "accepted": True,
        "unit": UNIT_NAME,
        "grace_s": GRACE_SECONDS,
        "scheduled_at": now_iso(),
        "detail": "the bridge will remove itself — code, secrets, tokens, TLS, "
                  "audit. Every remote access dies with it (intended zero "
                  "point). Re-entry only via the app-first bootstrap (root "
                  "password). The connection WILL drop mid-purge; that is the "
                  "success path, not an error.",
    }
