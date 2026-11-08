#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی قابلیت‌های v0.3 برای parastoo-mobile — سرور واقعی روی پورت آزاد.

پوشش: کلید توقف قلمرو عامل (pause/resume + ماندگاری)، متادیتای توکن عامل،
endpoint بلوک تحویل، جریان SSE زندهٔ audit، غنی‌سازی رکورد exec برای مانیتور زنده.

اجرا:  python tests/smoke_mobile.py
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
GREEN, RED, YELLOW, NC = "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0m"
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
TMP = tempfile.mkdtemp(prefix="access-agent-mobile.")
os.environ["ACCESS_AGENT_HOME"] = TMP
os.environ["ACCESS_AGENT_PORT"] = str(PORT)
os.environ["ACCESS_AGENT_NO_TLS"] = "1"

ADMIN = "adm_" + os.urandom(24).hex()
AGENT = "aa_" + os.urandom(24).hex()

(Path(TMP) / "tokens.json").write_text(json.dumps({
    "admin_sha": hashlib.sha256(ADMIN.encode()).hexdigest(),
    "agent_sha": hashlib.sha256(AGENT.encode()).hexdigest(),
    "agent_meta": {"label": "first-agent", "rotated_at": "2026-11-08T00:00:00+0000"},
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


def sse_read(path: str, token: str, seconds: float) -> tuple[str, bool]:
    """Read the SSE stream for a while; return (raw text, is_event_stream).

    Socket timeout is short (2s) so readline never blocks past the window;
    non-200 responses (e.g. 403) return their body in the text."""
    out: list[bytes] = []
    ctype = ""
    req_ = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}")
    req_.add_header("Authorization", f"Bearer {token}")
    deadline = time.monotonic() + seconds
    try:
        resp = urllib.request.urlopen(req_, timeout=2.0)
        ctype = resp.headers.get("Content-Type", "")
        while time.monotonic() < deadline:
            try:
                line = resp.fp.readline()
            except (TimeoutError, OSError):
                # تایم‌اوت سوکت = هیچ داده‌ای نبود؛ تا پایان پنجره ادامه بده
                if time.monotonic() < deadline:
                    continue
                break
            if not line:
                break
            out.append(line)
        resp.close()
    except urllib.error.HTTPError as e:
        try:
            out.append(e.read())
        except Exception:
            pass
    except Exception:
        pass
    return b"".join(out).decode("utf-8", "replace"), ctype.startswith("text/event-stream")


def main() -> int:
    try:
        run_all()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        server_log.close()
    print(f"\n# جمع‌بندی: {GREEN}{n_pass} سبز{NC}، {RED}{n_fail} قرمز{NC}")
    if failures:
        print("# شکست‌ها:")
        for f in failures:
            print(f"  - {f}")
    return 1 if n_fail else 0


def run_all() -> None:
    ch("healthz: سرور بالا آمد", up)

    # ---------- agent-token metadata (بدون افشای خود توکن) ----------
    code, b = req("GET", "/api/admin/agent-token", token=ADMIN)
    ch("agent-token متادیتا 200", code == 200 and b.get("ok") is True)
    ch("متادیتا set=true", b.get("set") is True)
    ch("متادیتا label دارد", (b.get("meta") or {}).get("label") == "first-agent")
    ch("متادیتا هرگز خود توکن را نمی‌دهد",
       AGENT not in json.dumps(b))
    code, b = req("GET", "/api/admin/agent-token", token=AGENT)
    ch("agent-token با توکن عامل → 403", code == 403)

    # ---------- status فیلد pause دارد ----------
    code, b = req("GET", "/api/status", token=ADMIN)
    ch("status فیلد agent_realm_paused دارد", code == 200 and b.get("agent_realm_paused") is False)

    # ---------- exec audit enrichment ----------
    code, b = req("POST", "/api/exec", token=AGENT,
                  body={"cmd": "echo hello-mobile", "timeout_s": 10})
    ch("exec عامل کار می‌کند", code == 200 and b.get("ok") and "hello-mobile" in b.get("stdout", ""))
    time.sleep(0.3)
    code, b = req("GET", "/api/admin/audit?tail=5", token=ADMIN)
    recs = [json.loads(l) for l in b.get("lines", []) if l.strip().startswith("{")]
    execrecs = [r for r in recs if r.get("action") == "exec"]
    ch("audit رکورد exec غنی‌شده دارد", bool(execrecs))
    if execrecs:
        r = execrecs[-1]
        ch("cmd_preview دارد", "echo hello-mobile" in str(r.get("cmd_preview", "")))
        ch("stdout_preview دارد", "hello-mobile" in str(r.get("stdout_preview", "")))
        ch("duration_ms عددی", isinstance(r.get("duration_ms"), int))

    # ---------- kill switch ----------
    code, b = req("POST", "/api/admin/agent-realm/pause", token=AGENT,
                  body={"paused": True})
    ch("pause با توکن عامل → 403", code == 403)
    code, b = req("POST", "/api/admin/agent-realm/pause", token=ADMIN,
                  body={"paused": True, "reason": "توقف از موبایل"})
    ch("pause توسط ادمین 200", code == 200 and b.get("agent_paused") is True)
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "echo blocked", "timeout_s": 5})
    ch("exec عامل در توقف → 403 agent_realm_paused",
       code == 403 and b.get("error") == "agent_realm_paused")
    ch("دلیل توقف در پاسخ است", "موبایل" in str(b.get("detail", "")))
    code, b = req("POST", "/api/exec", token=ADMIN, body={"cmd": "echo admin-ok", "timeout_s": 5})
    ch("exec ادمین در توقف هم آزاد", code == 200 and b.get("ok") is True)
    code, b = req("GET", "/api/status", token=AGENT)
    ch("status عامل در توقف → 403", code == 403)
    code, b = req("GET", "/api/status", token=ADMIN)
    ch("status ادمین pause=true را می‌بیند", code == 200 and b.get("agent_realm_paused") is True)
    code, b = req("GET", "/healthz")
    ch("healthz در توقف سالم", code == 200 and b.get("ok") is True)
    # ماندگاری: state.json نوشته شده؟
    st = json.loads((Path(TMP) / "state.json").read_text(encoding="utf-8"))
    ch("state.json ماندگار شد", st.get("agent_paused") is True)
    code, b = req("POST", "/api/admin/agent-realm/pause", token=ADMIN, body={"paused": False})
    ch("resume توسط ادمین", code == 200 and b.get("agent_paused") is False)
    code, b = req("POST", "/api/exec", token=AGENT, body={"cmd": "echo back", "timeout_s": 5})
    ch("exec عامل پس از resume آزاد", code == 200 and b.get("ok") is True)

    # ---------- handoff endpoint ----------
    code, b = req("GET", "/api/admin/handoff", token=AGENT)
    ch("handoff با توکن عامل → 403", code == 403)
    code, b = req("GET", "/api/admin/handoff", token=ADMIN)
    ch("handoff بدون data کامل → 409 شفاف",
       code in (200, 409))  # 200 اگر config/tls/توکن در TMP ست باشد، وگرنه 409
    if code == 200:
        ch("بلوک تحویل سه مقدار دارد",
           all(k in b.get("block", "") for k in ("ACCESS_URL:", "CERT_SHA256:", "AGENT_TOKEN:")))
        ch("توکن ادمین در بلوک نیست", ADMIN not in b.get("block", ""))
        ch("توکن عامل خودش همان فعال است", AGENT in b.get("block", ""))

    # ---------- SSE live audit stream ----------
    import threading
    got: dict = {}

    def reader():
        got["text"], got["ctype"] = sse_read("/api/admin/audit/stream?backfill=10", ADMIN, 4.0)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    time.sleep(1.5)  # اتصال زنده برقرار شود
    req("POST", "/api/exec", token=AGENT, body={"cmd": "echo sse-live-1", "timeout_s": 5})
    t.join(timeout=12)
    text = got.get("text", "")
    ch("SSE با content-type درست", got.get("ctype") is True)
    ch("SSE بک‌فیل تاریخچه دارد", "data: " in text and '"exec"' in text)
    ch("SSE رخداد زندهٔ بعد از اتصال را می‌گیرد", "sse-live-1" in text)
    ch("SSE پس از بچ، id: offset می‌دهد", "id: " in text)
    ch("SSE با توکن عامل → 403",
       "unauthorized" in sse_read("/api/admin/audit/stream", AGENT, 1.5)[0]
       or "forbidden" in sse_read("/api/admin/audit/stream", AGENT, 1.5)[0])

    # ---------- resume با cursor ----------
    # cursor بزرگ‌تر از حجم فایل → فالبک به بک‌فیل (بدون کرش)
    text_fb, ct_fb = sse_read("/api/admin/audit/stream?cursor=999999999&backfill=3", ADMIN, 3.0)
    ch("cursor نامعتبر فالبک امن دارد", ct_fb and "data: " in text_fb)


if __name__ == "__main__":
    raise SystemExit(main())
