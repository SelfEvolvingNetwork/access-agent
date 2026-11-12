#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی هستهٔ داده‌محور اپ موبایل — v0.5.8، سرور واقعی روی پورت آزاد.

پوشش: GET /api/admin/app/core-config (گارد ادمین/عامل/ناشناس)، پاکت پیش‌فرض
(schema/revision/sha256/config_json)، فایل اورراید معتبر، اورراید نامعتبر
(فالبک امن به پیش‌فرض) و صحت هش روی متن config_json.

اجرا:  python tests/smoke_coreconfig.py
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

GREEN, RED, YELLOW, NC = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
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
        timeout: float = 15) -> tuple[int, dict | bytes]:
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


# ---------- start server ----------
PORT = free_port()
TMP = tempfile.mkdtemp(prefix="access-agent-coreconfig.")
os.environ["ACCESS_AGENT_HOME"] = TMP
os.environ["ACCESS_AGENT_PORT"] = str(PORT)
os.environ["ACCESS_AGENT_NO_TLS"] = "1"

ADMIN = "adm_" + os.urandom(24).hex()
AGENT = "aa_" + os.urandom(24).hex()

(Path(TMP) / "tokens.json").write_text(json.dumps({
    "admin_sha": hashlib.sha256(ADMIN.encode()).hexdigest(),
    "agent_sha": hashlib.sha256(AGENT.encode()).hexdigest(),
}), encoding="utf-8")

env = dict(os.environ)
env["PYTHONUNBUFFERED"] = "1"
server_log = open(Path(TMP) / "server.log", "w", encoding="utf-8")
proc = subprocess.Popen(
    [sys.executable, "-m", "access_agent.server"],
    cwd=str(REPO), env=env,
    stdout=server_log, stderr=server_log,
    stdin=subprocess.DEVNULL,
)

up = False
for _ in range(50):
    try:
        code, body = req("GET", "/healthz", timeout=2)
        if code == 200:
            up = True
            break
    except Exception:
        pass
    time.sleep(0.2)


def main() -> int:
    global n_pass, n_fail
    try:
        run()
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        server_log.close()
    print(f"\n{'=' * 60}")
    print(f"core-config smoke: {n_pass} pass, {n_fail} fail")
    if failures:
        print("FAILED:", *failures, sep="\n  - ")
    return 1 if n_fail else 0


def run() -> None:
    ch("سرور بالا آمد", up)
    if not up:
        return

    from access_agent import appcore  # noqa: E402 — پس از ست‌شدن env

    # ---------- module-level: پیش‌فرض جاسازی‌شده ----------
    snap = appcore.snapshot()
    DEF_REV = appcore.DEFAULT_PAYLOAD["revision"]  # از قرارداد بخوان، هاردکد نکن
    ch("پاکت پیش‌فرض ok=True", snap.get("ok") is True)
    ch("schema درست", snap.get("schema") == appcore.SCHEMA)
    ch("revision پیش‌فرض از DEFAULT_PAYLOAD", snap.get("revision") == DEF_REV)
    ch("min_version_code = 17 (اپ 0.4.12)", snap.get("min_version_code") == 17)
    ch("منبع = default", snap.get("source") == "default")
    cfg = json.loads(snap.get("config_json", "{}"))
    ch("config_json endpointها را دارد",
       cfg.get("endpoints", {}).get("core_config") == "/api/admin/app/core-config")
    ch("sha256 روی متن config_json درست است",
       snap.get("sha256") == hashlib.sha256(snap.get("config_json", "").encode()).hexdigest())
    ch("متن تأییدیِ هات در allowlist سمت پل است",
       "bridge_uninstall_card_subtitle" in appcore.STRING_ALLOWLIST)

    # ---------- HTTP: گاردها ----------
    code, b = req("GET", "/api/admin/app/core-config")
    ch("بدون توکن → 401", code == 401)
    code, b = req("GET", "/api/admin/app/core-config", token=AGENT)
    ch("توکن عامل → 403 (فقط ادمین)", code == 403)
    code, b = req("GET", "/api/admin/app/core-config", token=ADMIN)
    ch("توکن ادمین → 200", code == 200 and b.get("ok") is True)
    ch("پاکت HTTP همان امضای ماژول را دارد",
       b.get("sha256") == snap.get("sha256") and b.get("revision") == snap.get("revision"))

    # ---------- override معتبر ----------
    odir = Path(TMP) / "app-core"
    odir.mkdir(parents=True, exist_ok=True)
    ov = {
        "schema": appcore.SCHEMA,
        "revision": DEF_REV + 1,  # همیشه یک قدم جلوتر از پیش‌فرض — اثباتِ واقعی اورراید
        "min_version_code": 17,
        "config": {
            "endpoints": {"core_config": "/api/admin/app/core-config"},
            "strings": {"bridge_uninstall_card_subtitle": "متن آزمایشی از اورراید"},
            "flags": {"bridge_self_destruct_visible": False},
        },
    }
    (odir / "core.json").write_text(json.dumps(ov, ensure_ascii=False), encoding="utf-8")
    snap2 = appcore.snapshot()
    ch("اورراید معتبر → revision جلوتر از پیش‌فرض", snap2.get("revision") == DEF_REV + 1)
    ch("اورراید معتبر → source=override", snap2.get("source") == "override")
    cfg2 = json.loads(snap2.get("config_json", "{}"))
    ch("متن سفارشی از اورراید می‌آید",
       cfg2.get("strings", {}).get("bridge_uninstall_card_subtitle") == "متن آزمایشی از اورراید")
    ch("فلگ مخفی‌سازی از اورراید می‌آید",
       cfg2.get("flags", {}).get("bridge_self_destruct_visible") is False)
    code, b = req("GET", "/api/admin/app/core-config", token=ADMIN)
    ch("HTTP اورراید را می‌بیند (revision جلوتر)",
       code == 200 and b.get("revision") == DEF_REV + 1 and b.get("source") == "override")

    # ---------- v0.8.2: اورراید کهنه‌تر از کد → هرگز سرو نمی‌شود ----------
    # میدان ۲۰۲۶-۱۱-۱۲: فایل rev2 روی سرور زنده پس از هر آپدیت پل سایه می‌انداخت.
    stale = json.loads(json.dumps(ov))
    stale["revision"] = DEF_REV - 1          # معتبر اما کهنه‌تر از کدِ در حال اجرا
    (odir / "core.json").write_text(json.dumps(stale, ensure_ascii=False), encoding="utf-8")
    s3 = appcore.snapshot()
    ch("اورراید کهنه‌تر از کد → پیش‌فرض سرو می‌شود",
       s3.get("revision") == DEF_REV and s3.get("source") == "default")
    ch("اورراید کهنه → note صادقانه دارد", bool(s3.get("note")))
    code, b = req("GET", "/api/admin/app/core-config", token=ADMIN)
    ch("HTTP هم اورراید کهنه را رد می‌کند",
       code == 200 and b.get("revision") == DEF_REV and b.get("source") == "default")

    # ---------- v0.8.2: هش گواهی در healthz (پیوستگی هویت، بدون توکن) ----------
    from access_agent import handoff as _handoff
    code, hb = req("GET", "/healthz")
    ch("healthz فیلد cert_sha256 دارد و با handoff.cert_fingerprint() یکی است",
       code == 200 and hb.get("cert_sha256") == _handoff.cert_fingerprint()
       and isinstance(hb.get("cert_sha256"), str))

    # ---------- override نامعتبر → فالبک امن ----------
    bad_cases = {
        "revision صفر": {**ov, "revision": 0},
        "schema غلط": {**ov, "schema": "parastoo-core/9"},
        "endpoint خطرناک": {**ov, "config": {"endpoints": {"status": "/x/../y"}}},
        "کلید متن بیرون از allowlist": {**ov, "config": {"strings": {"bridge_uninstall_confirm_word": "تأیید"}}},
        "فلگ غیر بولی": {**ov, "config": {"flags": {"bridge_self_destruct_visible": "yes"}}},
    }
    for name, payload in bad_cases.items():
        (odir / "core.json").write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        s = appcore.snapshot()
        ch(f"اورراید نامعتبر ({name}) → فالبک به پیش‌فرض",
           s.get("revision") == DEF_REV and s.get("source") == "default" and bool(s.get("note")))
    (odir / "core.json").write_text("{این جیسون نیست", encoding="utf-8")
    s = appcore.snapshot()
    ch("اورراید JSON خراب → فالبک امن", s.get("revision") == DEF_REV and s.get("source") == "default")

    # ---------- دستکاری متن config_json در راه (شبیه‌سازی در اپ) ----------
    tampered = json.loads(json.dumps(snap2))
    tampered["config_json"] = tampered["config_json"].replace("/api/admin/", "/api/hacked/")
    ch("دستکاری متن config با هش کشف می‌شود",
       tampered["sha256"] != hashlib.sha256(tampered["config_json"].encode()).hexdigest())


if __name__ == "__main__":
    raise SystemExit(main())
