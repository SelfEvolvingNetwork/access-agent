"""Owner↔agent chat room — access_agent.chatroom (v0.6.0).

Contract: docs/CHAT_ROOM.fa.md §4 + owner decisions (2026-11-10):
  - message = data, never command; plain text ≤4000 chars; rendered escaped
  - two sides only: host (chat token / admin token) and agent (agent token)
  - sender label derives from AUTH, never from the request body (no forging)
  - SQLite next to bridge data (ACCESS_AGENT_HOME/chat/chat.db) + a JSONL
    mirror updated on every insert (anti-lock-in; also the SSE source)
  - rate limit 30 msg/min per side; agent-realm pause silences agent side
  - daily db backup into ACCESS_AGENT_HOME/backups (keep 30)
  - audit records ids/lengths/counts only — never message text, never tokens
Pure stdlib. All handlers receive the bridge request handler instance and
reuse its _guard/_send/_agent_paused_guard plumbing.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import time
import urllib.parse
from pathlib import Path

from .security import audit, check_token, home, load_tokens, now_iso, save_tokens, sha256_hex

TEXT_MAX = 4000
RATE_LIMIT = 30          # messages per minute per side
RATE_WINDOW_S = 60
BACKUPS_KEEP = 30
COOKIE_NAME = "chat_token"
COOKIE_MAX_AGE = 30 * 24 * 3600

GET_PATHS = {
    "/chat", "/chat/",
    "/api/admin/chat/messages", "/api/admin/chat/stream",
    "/api/admin/chat/token", "/api/admin/chat/token/show",
    "/api/admin/chat/export",
    "/api/chat/messages", "/api/chat/stream",
    "/api/agent/chat/poll",
}
POST_PATHS = {
    "/api/admin/chat/send", "/api/admin/chat/read",
    "/api/admin/chat/token/rotate",
    "/api/chat/send", "/api/chat/read", "/api/chat/auth",
    "/api/agent/chat/reply",
}

_rl: dict[str, list[float]] = {"host": [], "agent": []}
_last_backup_day = ""


# ---------- storage ----------

def _dir() -> Path:
    d = home() / "chat"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _db() -> Path:
    return _dir() / "chat.db"


def _jsonl() -> Path:
    return _dir() / "chat.jsonl"


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(str(_db()), timeout=5)
    con.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        sender TEXT NOT NULL CHECK (sender IN ('host','agent')),
        text TEXT NOT NULL,
        reply_to INTEGER,
        read_at TEXT
    )""")
    return con


def _append_jsonl(rec: dict) -> None:
    with _jsonl().open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _daily_backup() -> None:
    global _last_backup_day
    day = time.strftime("%Y%m%d")
    if day == _last_backup_day:
        return
    _last_backup_day = day
    try:
        bdir = home() / "backups"
        bdir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_db(), bdir / f"chat-{day}.db")
        olds = sorted(bdir.glob("chat-*.db"))
        for old in olds[:-BACKUPS_KEEP]:
            old.unlink(missing_ok=True)
    except Exception:
        pass  # backup must never break chat


def _insert(sender: str, text: str, reply_to: int | None) -> dict:
    ts = now_iso()
    con = _conn()
    try:
        cur = con.execute(
            "INSERT INTO messages(ts,sender,text,reply_to) VALUES(?,?,?,?)",
            (ts, sender, text, reply_to))
        mid = int(cur.lastrowid)
        con.commit()
    finally:
        con.close()
    rec = {"id": mid, "ts": ts, "sender": sender, "text": text,
           "reply_to": reply_to, "read_at": None}
    _append_jsonl(rec)
    _daily_backup()
    return rec


def _fetch(since_id: int, limit: int, sender: str | None = None) -> list[dict]:
    con = _conn()
    try:
        q = "SELECT id,ts,sender,text,reply_to,read_at FROM messages WHERE id>?"
        args: list = [since_id]
        if sender:
            q += " AND sender=?"
            args.append(sender)
        q += " ORDER BY id ASC LIMIT ?"
        args.append(limit)
        rows = con.execute(q, args).fetchall()
    finally:
        con.close()
    return [{"id": r[0], "ts": r[1], "sender": r[2], "text": r[3],
             "reply_to": r[4], "read_at": r[5]} for r in rows]


def _mark_read(sender_side: str) -> int:
    """Messages written by sender_side get read_at=now (the other side read them)."""
    con = _conn()
    try:
        cur = con.execute(
            "UPDATE messages SET read_at=? WHERE sender=? AND read_at IS NULL",
            (now_iso(), sender_side))
        con.commit()
        return cur.rowcount
    finally:
        con.close()


# ---------- rate limit ----------

def _rate_ok(side: str) -> bool:
    now = time.monotonic()
    bucket = [t for t in _rl[side] if now - t < RATE_WINDOW_S]
    if len(bucket) >= RATE_LIMIT:
        _rl[side] = bucket
        return False
    bucket.append(now)
    _rl[side] = bucket
    return True


# ---------- chat token (third realm: "chat") ----------

def _write_secret(name: str, value: str) -> None:
    d = home() / "secrets"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(value + "\n", encoding="utf-8")
    p.chmod(0o600)


def mint_chat_token(label: str = "") -> str:
    import secrets as pysecrets
    raw = "aachat_" + pysecrets.token_hex(24)
    toks = load_tokens()
    toks["chat_sha"] = sha256_hex(raw)
    toks["chat_meta"] = {"label": str(label)[:80], "rotated_at": now_iso()}
    save_tokens(toks)
    _write_secret("chat-token", raw)
    return raw


def ensure_chat_token() -> str:
    if not load_tokens().get("chat_sha", ""):
        return mint_chat_token("auto-provisioned")
    p = home() / "secrets" / "chat-token"
    if p.exists():
        return p.read_text(encoding="utf-8").strip()
    return mint_chat_token("re-provisioned (secret file missing)")


def _principal_is_host(h) -> bool:
    """host = valid chat token (Bearer or cookie) or the admin token.
    The agent token is deliberately NOT accepted here (no forging)."""
    tok = h._bearer()
    if tok and (check_token(tok, "chat") or check_token(tok, "admin")):
        return True
    for part in (h.headers.get("Cookie") or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE_NAME and check_token(urllib.parse.unquote(v), "chat"):
            return True
    return False


# ---------- validation ----------

def _clean_text(data: dict):
    t = str(data.get("text") or "").strip()
    if not t or len(t) > TEXT_MAX:
        return None
    return t


def _clean_reply_to(data: dict):
    r = data.get("reply_to")
    if r in (None, "", 0):
        return None
    try:
        r = int(r)
    except (TypeError, ValueError):
        return None
    return r if 0 < r < 10**9 else None


# ---------- responses ----------

def _fail(h, code: int, error: str, detail: str = ""):
    h._send(code, {"ok": False, "error": error, "detail": detail})


def _send_cookie(h, obj: dict, raw_token: str) -> None:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    h.send_response(200)
    h.send_header("Content-Type", "application/json; charset=utf-8")
    h.send_header("Content-Length", str(len(body)))
    h.send_header("Cache-Control", "no-store")
    h.send_header("Set-Cookie",
                  f"{COOKIE_NAME}={urllib.parse.quote(raw_token)}; Path=/; HttpOnly; "
                  f"Secure; SameSite=Strict; Max-Age={COOKIE_MAX_AGE}")
    h.end_headers()
    try:
        h.wfile.write(body)
    except BrokenPipeError:
        pass


# ---------- GET dispatcher ----------

def handle_get(h, path: str) -> None:
    if path in ("/chat", "/chat/"):
        return _serve_page(h)
    if path == "/api/admin/chat/messages":
        if not h._guard("admin"):
            return
        msgs = _fetch(_since(h), _limit(h))
        audit("admin", "chat_messages", {"n": len(msgs)}, h._peer_ip())
        return h._send(200, {"ok": True, "messages": msgs,
                             "last_id": _last_id()})
    if path == "/api/admin/chat/export":
        if not h._guard("admin"):
            return
        lines = []
        p = _jsonl()
        if p.exists():
            lines = p.read_text(encoding="utf-8").splitlines()[-5000:]
        audit("admin", "chat_export", {"n": len(lines)}, h._peer_ip())
        return h._send(200, {"ok": True, "n": len(lines), "lines": lines,
                             "note": "full anti-lock-in export (last 5000 lines)"})
    if path == "/api/admin/chat/token":
        if not h._guard("admin"):
            return
        toks = load_tokens()
        audit("admin", "chat_token_meta", {}, h._peer_ip())
        return h._send(200, {"ok": True, "set": bool(toks.get("chat_sha", "")),
                             "meta": toks.get("chat_meta") or {}})
    if path == "/api/admin/chat/token/show":
        if not h._guard("admin"):
            return
        raw = ensure_chat_token()
        audit("admin", "chat_token_show", {}, h._peer_ip())
        return h._send(200, {"ok": True, "chat_token": raw,
                             "note": "chat realm only — revoke by rotating; "
                                     "never equal to the admin token"})
    if path == "/api/admin/chat/stream":
        if not h._guard("admin"):
            return
        audit("admin", "chat_stream_open", {"realm": "admin"}, h._peer_ip())
        return _stream(h)
    if path == "/api/chat/messages":
        if not _guard_chat(h, path):
            return
        msgs = _fetch(_since(h), _limit(h))
        audit("host", "chat_messages", {"n": len(msgs)}, h._peer_ip())
        return h._send(200, {"ok": True, "messages": msgs,
                             "last_id": _last_id()})
    if path == "/api/chat/stream":
        if not _guard_chat(h, path):
            return
        audit("host", "chat_stream_open", {"realm": "chat"}, h._peer_ip())
        return _stream(h)
    if path == "/api/agent/chat/poll":
        role = h._guard("agent")
        if not role:
            return
        if h._agent_paused_guard(role, path):
            return
        since = _since(h)
        msgs = _fetch(since, _limit(h), sender="host")
        if msgs:
            _mark_read("host")
            ts_read = now_iso()
            for m in msgs:
                if m["read_at"] is None:
                    m["read_at"] = ts_read
        audit("agent", "chat_poll", {"since_id": since, "n": len(msgs)}, h._peer_ip())
        return h._send(200, {"ok": True, "messages": msgs,
                             "last_id": _last_id(),
                             "paused": False})
    _fail(h, 404, "not_found", path)


# ---------- POST dispatcher ----------

def handle_post(h, path: str, data: dict) -> None:
    if path == "/api/chat/auth":
        tok = str(data.get("token") or "").strip()
        if not check_token(tok, "chat"):
            audit("anon", "chat_auth_fail", {}, h._peer_ip())
            return _fail(h, 401, "unauthorized", "invalid chat token")
        audit("host", "chat_auth_ok", {}, h._peer_ip())
        return _send_cookie(h, {"ok": True, "detail": "cookie set; the raw token "
                                                   "never lands in JS storage"}, tok)
    if path == "/api/admin/chat/send":
        if not h._guard("admin"):
            return
        return _send_host(h, data, "admin")
    if path == "/api/chat/send":
        if not _guard_chat(h, path):
            return
        return _send_host(h, data, "chat")
    if path == "/api/admin/chat/read":
        if not h._guard("admin"):
            return
        n = _mark_read("agent")
        return h._send(200, {"ok": True, "marked": n})
    if path == "/api/chat/read":
        if not _guard_chat(h, path):
            return
        n = _mark_read("agent")
        return h._send(200, {"ok": True, "marked": n})
    if path == "/api/admin/chat/token/rotate":
        if not h._guard("admin"):
            return
        raw = mint_chat_token(str(data.get("label") or "")[:80])
        audit("admin", "chat_token_rotate", {}, h._peer_ip())
        return h._send(200, {"ok": True, "chat_token": raw,
                             "note": "old chat token is dead now"})
    if path == "/api/agent/chat/reply":
        role = h._guard("agent")
        if not role:
            return
        if h._agent_paused_guard(role, path):
            return
        if not _rate_ok("agent"):
            audit("agent", "chat_rate_limited", {}, h._peer_ip())
            return _fail(h, 429, "rate_limited", f"max {RATE_LIMIT} msgs/min")
        text = _clean_text(data)
        if text is None:
            return _fail(h, 400, "bad_text", f"1..{TEXT_MAX} chars")
        rec = _insert("agent", text, _clean_reply_to(data))
        audit("agent", "chat_reply", {"id": rec["id"], "len": len(text)}, h._peer_ip())
        return h._send(200, {"ok": True, "message": rec})
    _fail(h, 404, "not_found", path)


def _send_host(h, data: dict, realm: str) -> None:
    if not _rate_ok("host"):
        audit("host", "chat_rate_limited", {"realm": realm}, h._peer_ip())
        return _fail(h, 429, "rate_limited", f"max {RATE_LIMIT} msgs/min")
    text = _clean_text(data)
    if text is None:
        return _fail(h, 400, "bad_text", f"1..{TEXT_MAX} chars")
    rec = _insert("host", text, _clean_reply_to(data))
    audit("host", "chat_send", {"id": rec["id"], "len": len(text), "realm": realm},
          h._peer_ip())
    h._send(200, {"ok": True, "message": rec})


def _guard_chat(h, path: str) -> bool:
    if _principal_is_host(h):
        return True
    audit("anon", "chat_auth_fail", {"path": path}, h._peer_ip())
    _fail(h, 401, "unauthorized", "chat token required (admin token also accepted)")
    return False


def _since(h) -> int:
    try:
        return max(0, min(int(_q(h, "since_id", "0")), 10**9))
    except ValueError:
        return 0


def _limit(h) -> int:
    try:
        return max(1, min(int(_q(h, "limit", "200")), 500))
    except ValueError:
        return 200


def _q(h, key: str, default: str) -> str:
    if "?" not in h.path:
        return default
    for part in h.path.split("?", 1)[1].split("&"):
        k, _, v = part.partition("=")
        if k == key:
            return urllib.parse.unquote(v)
    return default


def _last_id() -> int:
    con = _conn()
    try:
        row = con.execute("SELECT COALESCE(MAX(id),0) FROM messages").fetchone()
        return int(row[0])
    finally:
        con.close()


# ---------- web page ----------

def _serve_page(h) -> None:
    p = Path(__file__).with_name("chatpage.html")
    try:
        html = p.read_text(encoding="utf-8")
    except Exception:
        return _fail(h, 500, "page_missing", "chatpage.html not found")
    body = html.encode("utf-8")
    h.send_response(200)
    h.send_header("Content-Type", "text/html; charset=utf-8")
    h.send_header("Content-Length", str(len(body)))
    h.send_header("Cache-Control", "no-store")
    h.send_header("X-Content-Type-Options", "nosniff")
    h.send_header("Content-Security-Policy",
                  "default-src 'none'; connect-src 'self'; img-src 'self' data:; "
                  "style-src 'unsafe-inline'; script-src 'unsafe-inline'")
    h.end_headers()
    try:
        h.wfile.write(body)
    except BrokenPipeError:
        pass


# ---------- SSE (same pattern as the audit stream) ----------

def _stream(h) -> None:
    p = _jsonl()
    try:
        cursor = int(_q(h, "cursor", ""))
    except ValueError:
        cursor = -1
    try:
        backfill = max(0, min(int(_q(h, "backfill", "0")), 200))
    except ValueError:
        backfill = 0
    h.send_response(200)
    h.send_header("Content-Type", "text/event-stream; charset=utf-8")
    h.send_header("Cache-Control", "no-store")
    h.end_headers()
    try:
        if p.exists():
            size = p.stat().st_size
            if cursor > size:
                cursor = -1
            if cursor < 0:
                cursor = size
                if backfill:
                    window = min(size, 262_144)
                    with p.open("rb") as f:
                        f.seek(size - window)
                        chunk = f.read().splitlines()
                    for line in chunk[-backfill:]:
                        h.wfile.write(b"data: " + line + b"\n\n")
                    h.wfile.flush()
            else:
                with p.open("rb") as f:
                    f.seek(cursor)
                    pending = f.read()
                nl = pending.rfind(b"\n")
                if nl >= 0:
                    for line in pending[:nl].splitlines():
                        h.wfile.write(b"data: " + line + b"\n\n")
                    cursor += nl + 1
                    h.wfile.flush()
        h.wfile.write(f"id: {cursor}\n\n".encode("ascii"))
        h.wfile.flush()
        last_ping = time.monotonic()
        while True:
            time.sleep(0.5)
            if p.exists():
                size = p.stat().st_size
                if size > cursor:
                    with p.open("rb") as f:
                        f.seek(cursor)
                        pending = f.read()
                    nl = pending.rfind(b"\n")
                    if nl >= 0:
                        for line in pending[:nl].splitlines():
                            h.wfile.write(b"data: " + line + b"\n\n")
                        cursor += nl + 1
                        h.wfile.write(f"id: {cursor}\n\n".encode("ascii"))
                        h.wfile.flush()
                        last_ping = time.monotonic()
            if time.monotonic() - last_ping > 15:
                h.wfile.write(b": ping\n\n")
                h.wfile.flush()
                last_ping = time.monotonic()
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass  # client went away — normal SSE lifecycle
    finally:
        h.close_connection = True
