#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی چت‌روم (v0.6.0) — سرور واقعی روی پورت آزاد، بدون TLS، آفلاین.

اجرا:  python tests/smoke_chat.py
قرارداد: docs/CHAT_ROOM.fa.md — پیام=داده نه فرمان؛ توکن چت جدا؛ نرخ ۳۰/دقیقه؛
کلید توقف عامل چت را هم بی‌صدا می‌کند؛ متن پیام هرگز در audit نمی‌نشیند.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import hashlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GREEN, RED, YELLOW, NC = "\033", "\033", "\033", "\033"
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
        cookie: str = "", timeout: float = 15):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    if cookie:
        r.add_header("Cookie", cookie)
    if data:
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
TMP = tempfile.mkdtemp(prefix="access-agent-chat-smoke.")
os.environ["ACCESS_AGENT_HOME"] = TMP
os.environ["ACCESS_AGENT_PORT"] = str(PORT)
os.environ["ACCESS_AGENT_NO_TLS"] = "1"

ADMIN = "adm_" + os.urandom(24).hex()
AGENT = "aa_" + os.urandom(24).hex()
(TMP_PATH := Path(TMP)).mkdir(parents=True, exist_ok=True)
(Path(TMP) / "tokens.json").write_text(json.dumps({
    "admin_sha": hashlib.sha256(ADMIN.encode()).hexdigest(),
    "agent_sha": hashlib.sha256(AGENT.encode()).hexdigest(),
    "updated_at": "smoke",
}), encoding="utf-8")

proc = subprocess.Popen(
    [sys.executable, "-m", "access_agent.server"], cwd=str(REPO),
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(50):
    try:
        st, _ = req("GET", "/healthz", timeout=2)
        if st == 200:
            break
    except Exception:
        time.sleep(0.1)
else:
    print("server did not start")
    raise SystemExit(1)

SECRET_TEXT = "راز-چت-۸۸۷۱"

try:
    # --- page + auth surface ---
    st, raw = req("GET", "/chat")
    ch("GET /chat → 200 html", st == 200 and b"<html" in raw)
    import re as _re
    ch("page leaks no real token value", not _re.search(rb"aachat_[0-9a-f]{24}", raw))
    st, d = req("GET", "/api/chat/messages")
    ch("chat endpoint without token → 401", st == 401)
    st, d = req("POST", "/api/chat/send", token=AGENT, body={"text": "forge"})
    ch("agent token CANNOT forge host message", st in (401, 403))

    # --- chat token lifecycle ---
    st, d = req("GET", "/api/admin/chat/token", token=ADMIN)
    ch("token meta: not set yet", st == 200 and d.get("set") is False)
    st, d = req("POST", "/api/admin/chat/token/rotate", token=ADMIN,
                body={"label": "smoke"})
    CHAT = d.get("chat_token", "")
    ch("rotate → raw aachat_ once", st == 200 and CHAT.startswith("aachat_"))
    st, d = req("GET", "/api/admin/chat/token", token=ADMIN)
    ch("token meta now set", st == 200 and d.get("set") is True)
    st, d = req("GET", "/api/admin/chat/token/show", token=ADMIN)
    ch("show returns same token (admin-only, audited)",
       st == 200 and d.get("chat_token") == CHAT)
    st, d = req("GET", "/api/admin/chat/token/show", token=AGENT)
    ch("agent token cannot read chat token", st == 403)

    # --- cookie auth ---
    st, d = req("POST", "/api/chat/auth", body={"token": "wrong"})
    ch("auth with bad token → 401", st == 401)
    url = f"http://127.0.0.1:{PORT}/api/chat/auth"
    r = urllib.request.Request(url, data=json.dumps({"token": CHAT}).encode(),
                               method="POST")
    r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, timeout=10) as resp:
        setc = resp.headers.get("Set-Cookie", "")
    ch("auth ok → HttpOnly cookie", resp.status == 200 and "HttpOnly" in setc)
    cookie = setc.split(";")[0]
    st, d = req("GET", "/api/chat/messages", cookie=cookie)
    ch("cookie grants chat realm", st == 200 and d.get("ok") is True)

    # --- send/validate ---
    st, d = req("POST", "/api/chat/send", token=CHAT, body={"text": "<script>x</script>" + SECRET_TEXT})
    mid1 = d.get("message", {}).get("id", 0)
    ch("host send ok (html text stored as data)", st == 200 and mid1 == 1)
    st, d = req("POST", "/api/chat/send", token=CHAT, body={"text": " " * 5})
    ch("empty text → 400", st == 400)
    st, d = req("POST", "/api/chat/send", token=CHAT, body={"text": "x" * 4001})
    ch("4001 chars → 400", st == 400)
    st, d = req("POST", "/api/admin/chat/send", token=ADMIN, body={"text": "از ادمین"})
    ch("admin send ok", st == 200 and d.get("message", {}).get("sender") == "host")
    st, d = req("POST", "/api/chat/send", token=CHAT, body={"text": "پاسخ بده", "reply_to": mid1})
    ch("reply_to accepted", st == 200 and d.get("message", {}).get("reply_to") == mid1)

    # --- agent side ---
    st, d = req("GET", "/api/agent/chat/poll?since_id=0", token=AGENT)
    host_msgs = d.get("messages", [])
    last_host = host_msgs[-1]["id"] if host_msgs else 0
    ch("poll returns host msgs only",
       st == 200 and len(host_msgs) == 3 and all(m["sender"] == "host" for m in host_msgs))
    ch("poll marked host messages read", all(m["read_at"] for m in host_msgs))
    st, d = req("GET", f"/api/agent/chat/poll?since_id={last_host}", token=AGENT)
    ch("re-poll after cursor → empty", st == 200 and d.get("messages") == [])
    st, d = req("POST", "/api/agent/chat/reply", token=AGENT,
                body={"text": "پاسخ عامل", "reply_to": mid1})
    ch("agent reply ok (sender=agent)",
       st == 200 and d.get("message", {}).get("sender") == "agent")
    st, d = req("GET", "/api/chat/messages?since_id=0", token=CHAT)
    ch("owner sees agent reply", st == 200 and
       any(m["sender"] == "agent" for m in d.get("messages", [])))

    # --- forging & realm isolation ---
    st, d = req("POST", "/api/chat/send", token=CHAT, body={"text": "ok"})
    ch("chat token on agent endpoint → refused",
       req("POST", "/api/agent/chat/reply", token=CHAT, body={"text": "x"})[0] in (401, 403))

    # --- export + jsonl + audit hygiene ---
    st, d = req("GET", "/api/admin/chat/export", token=ADMIN)
    ch("export lines == inserted", st == 200 and d.get("n", 0) >= 5)
    jl = Path(TMP) / "chat" / "chat.jsonl"
    ch("jsonl mirror exists", jl.exists())
    aud = (Path(TMP) / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    ch("message text NEVER in audit", SECRET_TEXT not in aud and "<script>" not in aud)

    # --- backup ---
    time.sleep(0.05)
    st, d = req("POST", "/api/chat/send", token=CHAT, body={"text": "backup trigger"})
    bk = list((Path(TMP) / "backups").glob("chat-*.db"))
    ch("daily backup file created", st == 200 and len(bk) == 1)

    # --- pause silences agent side ---
    st, d = req("POST", "/api/admin/agent-realm/pause", token=ADMIN,
                body={"paused": True, "reason": "smoke"})
    ch("pause accepted", st == 200 and d.get("agent_paused") is True)
    st, d = req("GET", "/api/agent/chat/poll?since_id=0", token=AGENT)
    ch("paused agent poll → 403", st == 403)
    st, d = req("POST", "/api/agent/chat/reply", token=AGENT, body={"text": "x"})
    ch("paused agent reply → 403", st == 403)
    st, d = req("POST", "/api/chat/send", token=CHAT, body={"text": "مالک آزاد است"})
    ch("owner can still write while paused", st == 200)
    st, d = req("POST", "/api/admin/agent-realm/pause", token=ADMIN,
                body={"paused": False})
    ch("unpause accepted", st == 200 and d.get("agent_paused") is False)
    st, d = req("POST", "/api/agent/chat/reply", token=AGENT,
                body={"text": "بعد از رفع توقف"})
    ch("agent reply works after unpause", st == 200)

    # --- SSE smoke ---
    # --- rate limit (last: fills the window) ---
    last = 0
    for i in range(35):
        st, d = req("POST", "/api/chat/send", token=CHAT, body={"text": f"n{i}"})
        last = st
    ch("31st+ message in a minute → 429", last == 429)
    time.sleep(0.1)


    url = f"http://127.0.0.1:{PORT}/api/admin/chat/stream?backfill=3"
    sreq = urllib.request.Request(url)
    sreq.add_header("Authorization", "Bearer " + ADMIN)
    with urllib.request.urlopen(sreq, timeout=8) as resp:
        ct = resp.headers.get("Content-Type", "")
        chunk = resp.read(64)
    ch("SSE 200 + event-stream + backfill data",
       resp.status == 200 and "text/event-stream" in ct and b"data:" in chunk)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

print(f"\nجمع‌بندی چت: {n_pass} موفق، {n_fail} ناموفق")
if failures:
    print("شکست‌ها:", failures)
    raise SystemExit(1)
print("SMOKE_CHAT=PASS")
