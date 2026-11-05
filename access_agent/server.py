"""HTTPS bridge server — access_agent.server (pure Python stdlib).

Endpoints (v0.1):
  GET  /                          public service info
  GET  /healthz                   public lightweight health
  GET  /api/status                agent|admin  host status snapshot
  POST /api/exec                  agent|admin  run a command on the host
  POST /api/github/token          agent|admin  session-scoped PAT disclosure
  GET  /api/admin/audit           admin        audit tail (?tail=N)
  GET  /api/admin/sessions        admin        github grant tail (?tail=N)
  POST /api/admin/rotate-agent-token  admin   new agent token (printed once)
  POST /api/admin/revoke-agent-token  admin   disable agent realm
  POST /api/admin/set-github-token    admin   store the owner's GitHub PAT

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
from .execbridge import run_exec
from .githubbroker import disclose, grants_tail, save_token, stored_token
from .security import audit, audit_tail, check_token, home, load_tokens, save_tokens, sha256_hex

MAX_BODY = 100_000
MAX_BODY_HARD = 1_000_000
STARTED_AT = time.monotonic()

POST_ONLY = {
    "/api/exec",
    "/api/github/token",
    "/api/admin/rotate-agent-token",
    "/api/admin/revoke-agent-token",
    "/api/admin/set-github-token",
}
GET_ONLY = {"/", "/healthz", "/api/status", "/api/admin/audit", "/api/admin/sessions"}


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
        """Return "admin" | "agent" | "" (unauthenticated)."""
        tok = self._bearer()
        if tok and check_token(tok, "admin"):
            return "admin"
        if tok and check_token(tok, "agent"):
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

    def _query_int(self, key: str, default: int) -> int:
        q = self.path.split("?", 1)
        if len(q) != 2:
            return default
        for part in q[1].split("&"):
            k, _, v = part.partition("=")
            if k == key:
                try:
                    return max(1, min(int(v), 2000))
                except ValueError:
                    return default
        return default

    # ---- GET ----
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in POST_ONLY:
            return self._send(405, {"ok": False, "error": "method_not_allowed",
                                    "detail": "use POST"})
        if path == "/healthz":
            return self._send(200, {"ok": True, "service": "access-agent", "version": VERSION,
                                    "uptime_s": int(time.monotonic() - STARTED_AT)})
        if path == "/":
            return self._send(200, {"ok": True, "service": "access-agent", "version": VERSION,
                                    "detail": "independent AI-agent bridge; see /healthz and /api/status",
                                    "agent_connected": bool(self._role())})
        role = self._guard("agent")
        if not role:
            return
        if path == "/api/status":
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

        if path == "/api/exec":
            role = self._guard("agent")
            if not role:
                return
            res = run_exec(data.get("cmd"), data.get("timeout_s", 60), data.get("cwd"))
            if not res.get("ok"):
                audit(role, "exec_rejected",
                      {"error": res.get("error"), "cmd_len": len(str(data.get("cmd") or ""))},
                      self._peer_ip())
                return self._send(res.get("status", 400), res)
            audit(role, "exec",
                  {"exit_code": res.get("exit_code"), "timed_out": res.get("timed_out"),
                   "cmd_len": len(str(data.get("cmd") or "")),
                   "cmd_preview": str(data.get("cmd") or "")[:160]},
                  self._peer_ip())
            return self._send(200, res)

        if path == "/api/github/token":
            role = self._guard("agent")
            if not role:
                return
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
            save_tokens(toks)
            self._write_secret_file("agent-token", new_token)
            audit(role, "admin_rotate_agent_token", {}, self._peer_ip())
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


# ---------- main ----------

def main() -> int:
    bind = os.environ.get("ACCESS_AGENT_BIND", "0.0.0.0")
    try:
        port = int(os.environ.get("ACCESS_AGENT_PORT", "0") or 0)
    except ValueError:
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
