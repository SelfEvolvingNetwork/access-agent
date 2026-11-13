"""HTTPS bridge server — access_agent.server (pure Python stdlib).

Endpoints (v0.5):
  GET  /                          public service info
  GET  /healthz                   public lightweight health
  GET  /api/agent/onboarding      public read-only onboarding doc; with
                                  ?iid=<invite-id> (v0.9) the invite itself
                                  is the credential: the server DIRECTLY
                                  issues the temporary agent session token
                                  (aagx_) in the same response — no pairing
                                  code, no polling (owner decree 2026-11-13)
  GET  /api/admin/invite          admin one-line invite (v0.9): mints a
                                  user-bound one-time invite (?for=<label>,
                                  ?ttl_h=1..168 default 24) whose URL carries
                                  the invite id — leak-safe
  POST /api/admin/revoke-agent-sessions  admin kill-all temporary sessions
  POST /api/agent/session/end     agent|admin  end-of-conversation: revoke
                                  the caller's temporary session (v0.7)
  GET  /api/status                agent|admin  host status snapshot
  POST /api/exec                  agent|admin  run a command on the host;
                                  v0.5.1: refused 409 lifecycle_busy while a
                                  parastoo lifecycle op runs and the cmd
                                  mutates the platform (read-only passes)
  POST /api/github/token          agent|admin  purpose-gated token disclosure:
                                               GitHub App mode (v0.2): REAL
                                               <=1h installation tokens; master
                                               PAT never served. PAT mode (v0.1
                                               fallback while no app is set).
  GET  /api/admin/audit           admin        audit tail (?tail=N)
  GET  /api/admin/audit/stream    admin        SSE live audit tail (v0.3;
                                               ?cursor=byte-offset, ?backfill=N)
  GET  /api/admin/sessions        admin        github grant tail (?tail=N)
  GET  /api/admin/agent-token     admin        agent token metadata — never the
                                               token itself (v0.3)
  GET  /api/admin/handoff         admin        ready-to-paste handoff block for
                                               the AI agent (v0.3, parastoo-mobile)
  POST /api/admin/agent-realm/pause   admin   kill switch: block/unblock the
                                               whole agent realm (v0.3, persists)
  POST /api/admin/rotate-agent-token  admin   new agent token (printed once;
                                               optional {label} stored as meta)
  POST /api/admin/revoke-agent-token  admin   disable agent realm
  POST /api/admin/set-github-token    admin   store the owner's GitHub PAT
  GET  /api/admin/parastoo/lifecycle-status  admin  parastoo install state + progress
  GET  /api/admin/parastoo/setup-token       admin  setup-wizard token + domain
                                               facts for the phone UI (v0.5.3);
                                               value never logged or audited
  POST /api/admin/parastoo/install     admin  official bootstrap install (v0.5,
                                               owner directive: phone-only admin)
  POST /api/admin/parastoo/uninstall   admin  FULL removal incl. /var/lib/parastoo
                                               (requires {"confirm": "uninstall"})
  POST /api/admin/parastoo/reinstall   admin  uninstall+install in one lock
                                               (requires {"confirm": "reinstall"})
  POST /api/admin/parastoo/update      admin  run auto-update.sh --force now
                                               (v0.5: one operation at a time;
                                               background thread + log file)
  POST /api/admin/bridge/uninstall     admin  v0.5.7 — the bridge removes ITSELF
                                               (code+secrets+tokens+TLS+audit;
                                               requires {"confirm": "uninstall"};
                                               survives its own stop via a
                                               systemd-run transient unit; every
                                               remote access dies — intended)
  GET  /api/admin/app/core-config      admin  v0.5.8 — the mobile app's HOT DATA
                                               CORE: versioned {endpoints, allowed
                                               strings, flags} envelope; data only
                                               (never code), sha256-covered,
                                               optional override file at
                                               ACCESS_AGENT_HOME/app-core/core.json;
                                               lets the app evolve without
                                               reinstalling the APK

Auth: Authorization: Bearer <token> — two realms (admin, agent); admin is a
superset. Tokens stored as SHA-256 hashes in ACCESS_AGENT_HOME/tokens.json.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import VERSION
from . import appcore, bridgeuninstall, githubapp, parastoolifecycle
from .execbridge import run_exec
from .githubbroker import disclose, grants_tail, save_token, stored_token
from .handoff import (ONBOARDING_RULES, build_block, build_invite,
                      cert_fingerprint, onboarding_doc)
from .security import (audit, audit_tail, agent_paused, check_agent_session,
                       check_token, claim_invite_session,
                       clear_agent_sessions, home, load_state, load_tokens,
                       mint_invite, now_iso, sanitize_invite_label,
                       save_tokens, revoke_agent_session, set_agent_paused,
                       sha256_hex)

MAX_BODY = 100_000
MAX_BODY_HARD = 1_000_000
STARTED_AT = time.monotonic()

POST_ONLY = {
    "/api/exec",
    "/api/github/token",
    "/api/admin/rotate-agent-token",
    "/api/admin/revoke-agent-token",
    "/api/admin/agent-realm/pause",
    "/api/admin/set-github-token",
    "/api/admin/parastoo/install",
    "/api/admin/parastoo/uninstall",
    "/api/admin/parastoo/reinstall",
    "/api/admin/parastoo/update",
    "/api/admin/bridge/uninstall",
    "/api/agent/session/end",
    "/api/admin/revoke-agent-sessions",
}
GET_ONLY = {"/", "/healthz", "/api/agent/onboarding", "/api/status", "/api/admin/audit",
            "/api/admin/audit/stream", "/api/admin/sessions",
            "/api/admin/agent-token", "/api/admin/handoff",
            "/api/admin/invite",
            "/api/admin/parastoo/lifecycle-status",
            "/api/admin/parastoo/setup-token",
            "/api/admin/app/core-config"}


# ---------- helpers ----------

def _json_body(raw: bytes):
    try:
        data = json.loads(raw.decode("utf-8") or "{}")
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def host_status() -> dict:
    uptime_s = 0
    try:
        uptime_s = int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        pass
    disk = shutil.disk_usage("/")
    mem_total = mem_avail = 0
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                mem_total = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                mem_avail = int(line.split()[1])
    except Exception:
        pass
    parastoo_path = ""
    p = Path("/etc/parastoo-install-path")
    if p.exists():
        try:
            parastoo_path = p.read_text(encoding="utf-8").strip().splitlines()[0]
        except Exception:
            parastoo_path = ""
    self_update = None  # v0.8.3 — tail of the server-side self-update history
    try:
        rows = (home() / "updates.jsonl").read_text(encoding="utf-8").strip().splitlines()
        if rows:
            self_update = json.loads(rows[-1])
    except Exception:
        self_update = None
    return {
        "ok": True,
        "service": "access-agent",
        "version": VERSION,
        "uptime_s": uptime_s,
        "hostname": socket.gethostname(),
        "kernel": os.uname().release,
        "python": ".".join(map(str, sys.version_info[:3])),
        "disk_percent": round(disk.used / disk.total * 100, 1) if disk.total else None,
        "disk_free_gb": round(disk.free / 1024**3, 1),
        "mem_total_mb": mem_total // 1024 if mem_total else None,
        "mem_avail_mb": mem_avail // 1024 if mem_avail else None,
        "docker_path": shutil.which("docker") or "",
        "parastoo_install_path": parastoo_path,
        "github_token_stored": bool(stored_token()),
        "agent_realm_enabled": bool(load_tokens().get("agent_sha", "")),
        "agent_realm_paused": bool(load_state().get("agent_paused")),
        "self_update": self_update,
    }


def validate_github_token(token: str) -> dict:
    """Best-effort online validation (never blocks saving)."""
    result = {"validated": False, "login": "", "note": ""}
    try:
        req = urllib.request.Request(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "User-Agent": "access-agent"},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            result.update(validated=resp.status == 200,
                          login=data.get("login", ""),
                          note="validated against api.github.com/user")
    except Exception as e:  # offline-safe: Iran networks etc.
        result["note"] = f"validation skipped ({type(e).__name__}) — token saved anyway"
    return result


# ---------- request handler ----------

class Handler(BaseHTTPRequestHandler):
    server_version = f"access-agent/{VERSION}"
    sys_version = ""

    # ---- plumbing ----
    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def log_message(self, fmt, *args):  # minimal, token-free (headers never logged)
        print(f"[{self.log_date_time_string()}] {fmt % args}", flush=True)

    def _peer_ip(self) -> str:
        return self.client_address[0] if self.client_address else ""

    def _bearer(self) -> str:
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            return h[7:].strip()
        return ""

    def _role(self) -> str:
        """Return "admin" | "agent" | "" (unauthenticated).

        v0.7: توکن موقت نشست عامل (aagx_) هم نقش agent می‌گیرد —
        همان قلمرو، همان audit؛ فقط عمرش کوتاه و ابطالش مستقل است."""
        tok = self._bearer()
        if tok and check_token(tok, "admin"):
            return "admin"
        if tok and (check_token(tok, "agent") or check_agent_session(tok)):
            return "agent"
        return ""

    def _read_body(self) -> bytes | None:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n > MAX_BODY_HARD:
            self.close_connection = True
            return None
        if n <= 0:
            return b""
        return self.rfile.read(n)

    def _guard(self, need: str) -> str:
        """need: "public" | "agent" (agent or admin) | "admin".
        Returns the role; on failure sends the error response and returns ""."""
        if need == "public":
            return "public"
        role = self._role()
        if not role:
            audit("anon", "auth_fail", {"path": self.path.split("?")[0]}, self._peer_ip())
            self._send(401, {"ok": False, "error": "unauthorized",
                             "detail": "missing or invalid bearer token"})
            return ""
        if need == "admin" and role != "admin":
            audit(role, "auth_forbidden", {"path": self.path.split("?")[0]}, self._peer_ip())
            self._send(403, {"ok": False, "error": "forbidden",
                             "detail": "this endpoint requires the admin token"})
            return ""
        return role

    def _query_int(self, key: str, default: int, lo: int = 1,
                   hi: int = 2000) -> int:
        q = self.path.split("?", 1)
        if len(q) != 2:
            return default
        for part in q[1].split("&"):
            k, _, v = part.partition("=")
            if k == key:
                try:
                    return max(lo, min(int(v), hi))
                except ValueError:
                    return default
        return default

    def _query_param(self, key: str, max_len: int = 120) -> str:
        """اولین مقدار پارامتر رشته‌ای query — URL-decode با tolerate خطا."""
        q = self.path.split("?", 1)
        if len(q) != 2:
            return ""
        for part in q[1].split("&"):
            k, _, v = part.partition("=")
            if k == key:
                try:
                    from urllib.parse import unquote_plus
                    v = unquote_plus(v)
                except Exception:
                    pass
                return v[:max_len]
        return ""

    # ---- GET ----
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in POST_ONLY:
            return self._send(405, {"ok": False, "error": "method_not_allowed",
                                    "detail": "use POST"})
        if path == "/healthz":
            # v0.8.2 — هش گواهی عمومی است (همان که دعوت‌نامه‌ها هم می‌برند؛ رازی
            # نیست). فرمان مالک ۲۰۲۶-۱۱-۱۲ («الگوی مخرب آپدیت»): کلاینت باید بتواند
            # پیوستگی هویت سرور را بی‌هزینه بپرسد — «آیا اثرانگشت عوض شده؟»
            # جوابش از خود سرور، بدون SSH و بدون توکن.
            return self._send(200, {"ok": True, "service": "access-agent", "version": VERSION,
                                    "uptime_s": int(time.monotonic() - STARTED_AT),
                                    "cert_sha256": cert_fingerprint()})
        if path == "/":
            return self._send(200, {"ok": True, "service": "access-agent", "version": VERSION,
                                    "detail": "independent AI-agent bridge; see /healthz and /api/status",
                                    "agent_connected": bool(self._role())})
        # v0.9.1 — اتصال مستقیم: خودِ iid اعتبار است؛ نه رمز، نه poll (فرمان
        # مالک ۲۰۲۶-۱۱-۱۳). بدون iid فقط سند کوتاه؛ با iid توکن در همان پاسخ.
        # فرمان مالک (چت دوم ۲۰۲۶-۱۱-۱۳): توضیحِ بیشتر ولی مختصر، پس از فراخوانی —
        # پاسخ با «connected: true» و یک خط هدف شروع می‌شود تا عامل بداند چه
        # رخ داده و بعد چه کند (اعتمادسازی از خود سرور، نه از متن دعوت).
        if path == "/api/agent/onboarding":
            iid = self._query_param("iid", max_len=80)
            if not iid:
                audit("anon", "agent_onboarding_read", {}, self._peer_ip())
                return self._send(200, onboarding_doc())
            res = claim_invite_session(iid, self._peer_ip())
            if not res.get("ok"):
                audit("anon", "agent_onboarding_refused",
                      {"error": res.get("error")}, self._peer_ip())
                return self._send(res.get("status", 404), res)
            audit("anon", "agent_onboarding_granted",
                  {"invited_by": res.get("invited_by", "")}, self._peer_ip())
            return self._send(200, {
                "ok": True,
                "connected": True,
                "service": "access-agent",
                "version": VERSION,
                "protocol": "onboarding/0.9.1",
                "invited_by": res.get("invited_by", ""),
                "token": res.get("token", ""),
                "agent_token": res.get("token", ""),
                "expires": res.get("expires", ""),
                "cert_sha256": cert_fingerprint(),
                "connection": (
                    "اتصال همین مکالمه با سرور مالک برقرار شد؛ "
                    "دعوت مالک معتبر بود و این توکن فقط برای همین مکالمه است."
                ),
                "next": ("GET /healthz، سپس GET /api/status با همین توکن "
                         "(Authorization: Bearer)؛ بعد به مالک گزارش بده "
                         "و منتظر فرمانش بمان."),
                "end": {"method": "POST", "path": "/api/agent/session/end",
                        "note": "در آخرین پیام مکالمه، به درخواست مالک."},
                "rules": ONBOARDING_RULES,
            })
        role = self._guard("agent")
        if not role:
            return
        if path == "/api/status":
            if self._agent_paused_guard(role, path):
                return
            audit(role, "status", {}, self._peer_ip())
            return self._send(200, host_status())
        if path == "/api/admin/audit":
            role = self._guard("admin")
            if not role:
                return
            tail = self._query_int("tail", 200)
            audit(role, "admin_audit_tail", {"tail": tail}, self._peer_ip())
            return self._send(200, {"ok": True, "lines": audit_tail(tail), "n": tail})
        if path == "/api/admin/sessions":
            role = self._guard("admin")
            if not role:
                return
            tail = self._query_int("tail", 50)
            audit(role, "admin_sessions_tail", {"tail": tail}, self._peer_ip())
            return self._send(200, {"ok": True, "grants": grants_tail(tail)})
        if path == "/api/admin/audit/stream":
            role = self._guard("admin")
            if not role:
                return
            audit(role, "admin_audit_stream", {"q": self.path.split("?", 1)[1] if "?" in self.path else ""},
                  self._peer_ip())
            return self._stream_audit()
        if path == "/api/admin/agent-token":
            role = self._guard("admin")
            if not role:
                return
            toks = load_tokens()
            audit(role, "admin_agent_token_meta", {}, self._peer_ip())
            return self._send(200, {"ok": True, "set": bool(toks.get("agent_sha", "")),
                                    "meta": toks.get("agent_meta") or {}})
        if path == "/api/admin/handoff":
            role = self._guard("admin")
            if not role:
                return
            try:
                block = build_block()
            except Exception as e:
                return self._send(409, {"ok": False, "error": "handoff_unavailable",
                                        "detail": str(e)})
            audit(role, "admin_handoff_served", {}, self._peer_ip())
            return self._send(200, {"ok": True, "block": block})
        # v0.7.2 → v0.8 — دعوت‌نامهٔ کاربر-مند برای اپ موبایل: مالک با ?for=<نام
        # کاربر> دعوت را به نام او صادر می‌کند؛ متن بی‌رمز است (URL با شناسهٔ
        # دعوت + هش گواهی) و لورفتنش بی‌خطر است. شناسهٔ دعوت فقط یک بار در همین
        # پاسخ چاپ می‌شود؛ با نخستین تأیید مالک مصرف می‌شود (یک دعوت = یک عامل).
        if path == "/api/admin/invite":
            role = self._guard("admin")
            if not role:
                return
            label = sanitize_invite_label(self._query_param("for", max_len=60))
            ttl_h = self._query_int("ttl_h", 24, lo=1, hi=168)
            try:
                from .security import INVITE_TTL_S_DEFAULT
                iid, rec = mint_invite(label, ttl_s=ttl_h * 3600)
                invite = build_invite(iid)
            except Exception as e:
                return self._send(409, {"ok": False, "error": "invite_unavailable",
                                        "detail": str(e)})
            audit(role, "admin_invite_served",
                  {"invited_by": label, "ttl_h": ttl_h}, self._peer_ip())
            return self._send(200, {"ok": True, "invite": invite,
                                    "invited_by": label, "expires": rec.get("expires", "")})
        if path == "/api/admin/parastoo/lifecycle-status":
            role = self._guard("admin")
            if not role:
                return
            audit(role, "admin_parastoo_status", {}, self._peer_ip())
            return self._send(200, parastoolifecycle.status_snapshot())
        if path == "/api/admin/parastoo/setup-token":
            role = self._guard("admin")
            if not role:
                return
            # v0.5.3 — the owner finishes the panel wizard from the phone:
            # token + domain facts ride the pinned TLS channel; the audit
            # records booleans only (token value never in log/audit).
            info = parastoolifecycle.setup_token_info()
            audit(role, "admin_parastoo_setup_token",
                  {"installed": bool(info.get("installed")),
                   "has_token": bool(info.get("has_token"))},
                  self._peer_ip())
            return self._send(200, info)
        # v0.5.8 — هستهٔ داده‌محور اپ موبایل: فقط ادمین؛ در audit فقط revision و
        # منبع ثبت می‌شود، نه محتوای پاکت. داده است، نه کد — اپ با اعتبارسنجی
        # سخت‌گیرانه و allowlist خودش می‌خواند؛ endpoint آدرس سرور را هرگز عوض
        # نمی‌کند — این کانال است که آدرس را می‌آورد.
        if path == "/api/admin/app/core-config":
            role = self._guard("admin")
            if not role:
                return
            snap = appcore.snapshot()
            audit(role, "admin_app_core_config",
                  {"revision": snap.get("revision"), "source": snap.get("source")},
                  self._peer_ip())
            return self._send(200, snap)
        self._send(404, {"ok": False, "error": "not_found", "path": path})

    # ---- POST ----
    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path in GET_ONLY:
            return self._send(405, {"ok": False, "error": "method_not_allowed",
                                    "detail": "use GET"})
        raw = self._read_body()
        if raw is None:
            return self._send(413, {"ok": False, "error": "body_too_large",
                                    "limit": MAX_BODY_HARD})
        if len(raw) > MAX_BODY:
            return self._send(413, {"ok": False, "error": "body_too_large", "limit": MAX_BODY})
        data = _json_body(raw) if raw else {}
        if data is None:
            return self._send(400, {"ok": False, "error": "bad_json"})

        if path == "/api/agent/session/end":
            role = self._guard("agent")
            if not role:
                return
            tok = self._bearer()
            removed = revoke_agent_session(tok) if check_agent_session(tok) else False
            audit(role, "agent_session_end", {"session_removed": removed}, self._peer_ip())
            return self._send(200, {"ok": True, "session_removed": removed,
                                    "detail": "temporary session revoked; no agent "
                                              "credential of this conversation remains"})

        # v0.7.1 — کلید اضطراری مالک: ابطال همهٔ نشست‌های موقت جفت‌سازی.
        if path == "/api/admin/revoke-agent-sessions":
            role = self._guard("admin")
            if not role:
                return
            n = clear_agent_sessions()
            audit(role, "admin_revoke_agent_sessions", {"removed": n}, self._peer_ip())
            return self._send(200, {"ok": True, "removed": n,
                                    "detail": "all temporary agent sessions revoked"})

        if path == "/api/exec":
            role = self._guard("agent")
            if not role:
                return
            if self._agent_paused_guard(role, path):
                return
            # v0.5.1 — one platform-mutating actor at a time (owner decree
            # «one transparent pipeline»): while a parastoo lifecycle op runs,
            # conflicting exec is refused; read-only supervision passes.
            blocked = parastoolifecycle.exec_block_reason(str(data.get("cmd") or ""))
            if blocked:
                audit(role, "exec_blocked_lifecycle",
                      {"cmd_len": len(str(data.get("cmd") or "")),
                       "cmd_preview": str(data.get("cmd") or "")[:200]},
                      self._peer_ip())
                return self._send(409, {"ok": False, "error": "lifecycle_busy",
                                        "detail": blocked})
            res = run_exec(data.get("cmd"), data.get("timeout_s", 60), data.get("cwd"))
            if not res.get("ok"):
                audit(role, "exec_rejected",
                      {"error": res.get("error"), "cmd_len": len(str(data.get("cmd") or ""))},
                      self._peer_ip())
                return self._send(res.get("status", 400), res)
            # v0.3: richer live-monitoring record for parastoo-mobile — bounded
            # previews so audit.jsonl stays lean; the agent produces no reports,
            # the bridge captures everything software-side.
            audit(role, "exec",
                  {"exit_code": res.get("exit_code"), "timed_out": res.get("timed_out"),
                   "duration_ms": res.get("duration_ms"),
                   "cmd_len": len(str(data.get("cmd") or "")),
                   "cmd_preview": str(data.get("cmd") or "")[:400],
                   "stdout_preview": str(res.get("stdout") or "")[:600],
                   "stderr_preview": str(res.get("stderr") or "")[:300]},
                  self._peer_ip())
            return self._send(200, res)

        if path == "/api/github/token":
            role = self._guard("agent")
            if not role:
                return
            if self._agent_paused_guard(role, path):
                return
            # v0.2: GitHub App mode serves REAL <=1h installation tokens and
            # never touches the master PAT; PAT mode stays only as the
            # fallback while the owner has not configured an app yet.
            if githubapp.configured():
                res = githubapp.disclose(data.get("purpose"), self._peer_ip())
            else:
                res = disclose(data.get("purpose"), data.get("ttl_min", 60), self._peer_ip())
            if not res.get("ok"):
                return self._send(res.get("status", 400), res)
            return self._send(200, res)

        if path == "/api/admin/rotate-agent-token":
            role = self._guard("admin")
            if not role:
                return
            import secrets as pysecrets
            new_token = "aa_" + pysecrets.token_hex(24)
            toks = load_tokens()
            toks["agent_sha"] = sha256_hex(new_token)
            toks["agent_meta"] = {"label": str(data.get("label") or "")[:80],
                                  "rotated_at": now_iso()}
            save_tokens(toks)
            self._write_secret_file("agent-token", new_token)
            audit(role, "admin_rotate_agent_token",
                  {"label": str(data.get("label") or "")[:80]}, self._peer_ip())
            return self._send(200, {"ok": True, "agent_token": new_token,
                                    "note": "give it to the AI agent; the old one is dead now"})

        if path == "/api/admin/revoke-agent-token":
            role = self._guard("admin")
            if not role:
                return
            toks = load_tokens()
            toks["agent_sha"] = ""
            save_tokens(toks)
            audit(role, "admin_revoke_agent_token", {}, self._peer_ip())
            return self._send(200, {"ok": True, "detail": "agent realm disabled; rotate to re-enable"})

        if path == "/api/admin/agent-realm/pause":
            # v0.3 mobile kill switch — persists in state.json, survives restarts
            role = self._guard("admin")
            if not role:
                return
            paused = bool(data.get("paused"))
            reason = str(data.get("reason") or "")[:300]
            st = set_agent_paused(paused, reason)
            audit(role, "admin_pause_agent_realm" if paused else "admin_resume_agent_realm",
                  {"reason": st.get("reason", "")}, self._peer_ip())
            return self._send(200, {"ok": True, "agent_paused": st["agent_paused"],
                                    "reason": st.get("reason", "")})

        if path == "/api/admin/set-github-token":
            role = self._guard("admin")
            if not role:
                return
            token = str(data.get("token") or "").strip()
            if not token:
                return self._send(400, {"ok": False, "error": "token_required"})
            if not save_token(token):
                return self._send(400, {"ok": False, "error": "bad_token_format"})
            validation = validate_github_token(token)
            audit(role, "admin_set_github_token", validation, self._peer_ip())
            return self._send(200, {"ok": True, "stored": True, "validation": validation})

        if path.startswith("/api/admin/parastoo/"):
            role = self._guard("admin")
            if not role:
                return
            action = path.rsplit("/", 1)[1]
            res = parastoolifecycle.start(action, str(data.get("confirm") or ""))
            if not res.get("ok"):
                audit(role, "admin_parastoo_rejected",
                      {"action": action, "error": res.get("error")}, self._peer_ip())
                return self._send(res.get("status", 400), res)
            return self._send(202, res)

        # v0.5.7 — آخرین فرمان: پل خودش را حذف می‌کند (نقطهٔ صفر مطلق؛ فرمان مالک).
        # فقط ادمین؛ قلمرو عامل هرگز حق حذف پل را ندارد.
        if path == "/api/admin/bridge/uninstall":
            role = self._guard("admin")
            if not role:
                return
            res = bridgeuninstall.schedule(str(data.get("confirm") or ""))
            if not res.get("ok"):
                audit(role, "admin_bridge_uninstall_refused",
                      {"error": res.get("error")}, self._peer_ip())
                return self._send(res.get("status", 400), res)
            return self._send(202, res)

        self._send(404, {"ok": False, "error": "not_found", "path": path})

    # ---- methods unsupported ----
    def do_PUT(self):
        self._send(405, {"ok": False, "error": "method_not_allowed"})

    do_DELETE = do_PUT

    def _write_secret_file(self, name: str, value: str) -> None:
        d = home() / "secrets"
        d.mkdir(parents=True, exist_ok=True)
        p = d / name
        p.write_text(value + "\n", encoding="utf-8")
        p.chmod(0o600)

    def _agent_paused_guard(self, role: str, path: str) -> bool:
        """v0.3 kill switch: while the agent realm is paused, agent-role calls to
        work endpoints get 403. Admin passes always; returns True if blocked."""
        if role != "agent":
            return False
        paused, reason = agent_paused()
        if not paused:
            return False
        audit("agent", "agent_blocked_paused", {"path": path}, self._peer_ip())
        self._send(403, {"ok": False, "error": "agent_realm_paused",
                         "detail": reason or "agent realm paused by owner"})
        return True

    def _stream_audit(self) -> None:
        """v0.3 — SSE live tail of audit/audit.jsonl (admin only).

        Query: ?cursor=<byte offset> resume after disconnect;
               ?backfill=N replay last N lines on fresh connect (default 50,
               cap 500). Heartbeat comment every ~15s. The stream itself never
               writes to audit (no feedback loop). Byte-offset id after every
               batch lets the client resume exactly where it left off."""
        import urllib.parse
        q: dict[str, str] = {}
        if "?" in self.path:
            for part in self.path.split("?", 1)[1].split("&"):
                k, _, v = part.partition("=")
                q[k] = urllib.parse.unquote(v)
        p = home() / "audit" / "audit.jsonl"
        try:
            offset = int(q.get("cursor", ""))
        except ValueError:
            offset = -1
        try:
            backfill = max(1, min(int(q.get("backfill", "50")), 500))
        except ValueError:
            backfill = 50
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            if p.exists():
                size = p.stat().st_size
                if offset > size:
                    offset = -1  # file shrank/rotated — fall back to backfill
                if offset < 0:
                    window = min(size, 262_144)
                    with p.open("rb") as f:
                        f.seek(size - window)
                        chunk = f.read().splitlines()
                    for line in chunk[-backfill:]:
                        self.wfile.write(b"data: " + line + b"\n\n")
                    self.wfile.flush()
                    offset = size
                else:
                    with p.open("rb") as f:
                        f.seek(offset)
                        pending = f.read()
                    nl = pending.rfind(b"\n")
                    if nl >= 0:
                        for line in pending[:nl].splitlines():
                            self.wfile.write(b"data: " + line + b"\n\n")
                        offset += nl + 1
                    self.wfile.flush()
            self.wfile.write(f"id: {offset}\n\n".encode("ascii"))
            self.wfile.flush()
            last_ping = time.monotonic()
            while True:
                time.sleep(0.5)
                if p.exists():
                    size = p.stat().st_size
                    if size > offset:
                        with p.open("rb") as f:
                            f.seek(offset)
                            pending = f.read()
                        nl = pending.rfind(b"\n")
                        if nl >= 0:
                            for line in pending[:nl].splitlines():
                                self.wfile.write(b"data: " + line + b"\n\n")
                            offset += nl + 1
                            self.wfile.write(f"id: {offset}\n\n".encode("ascii"))
                            self.wfile.flush()
                            last_ping = time.monotonic()
                if time.monotonic() - last_ping > 15:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    last_ping = time.monotonic()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # client went away — normal SSE lifecycle
        finally:
            self.close_connection = True


# ---------- main ----------

def main() -> int:
    bind = os.environ.get("ACCESS_AGENT_BIND", "0.0.0.0")
    try:
        port = int(os.environ.get("ACCESS_AGENT_PORT", "0") or 0)
    except ValueError:
        port = 0
    if port <= 0:
        # v0.1.2: honor the installer's chosen port (config.json) when the env
        # is absent — the systemd unit is exactly this case; 0 = OS random.
        try:
            port = int(json.loads((home() / "config.json").read_text(encoding="utf-8")).get("port") or 0)
        except Exception:
            port = 0
    no_tls = os.environ.get("ACCESS_AGENT_NO_TLS", "") == "1"

    httpd = ThreadingHTTPServer((bind, port), Handler)
    tls_on = False
    if not no_tls:
        tls_dir = home() / "tls"
        cert = tls_dir / "cert.pem"
        key = tls_dir / "key.pem"
        if cert.exists() and key.exists():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert), str(key))
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            tls_on = True
        else:
            print("WARN: TLS certs missing under", tls_dir, "— running PLAIN HTTP "
                  "(test/dev only)", flush=True)
    real_port = httpd.socket.getsockname()[1]
    print(f"access-agent v{VERSION} listening on {bind}:{real_port} "
          f"(tls={'on' if tls_on else 'OFF'}, home={home()})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
