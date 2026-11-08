"""Host command execution with hard caps — access_agent.execbridge.

Equivalent of SSH for the AI agent, over HTTPS + token. Hard limits mirror the
Parastoo agent bridge conventions (cmd 8000 chars, timeout 600s, output tail
200k chars per stream, max 2 concurrent). stdin is always /dev/null — the
`curl | bash` stdin-hunger lesson from Parastoo docs/LESSONS.md.
"""
from __future__ import annotations

import os
import signal
import subprocess
import threading
import time

MAX_CMD_CHARS = 8000
MAX_TIMEOUT_S = 600
MAX_OUTPUT_CHARS = 200_000
MAX_CONCURRENT = 2

_sem = threading.BoundedSemaphore(MAX_CONCURRENT)

# --- v0.5.1: mutual exclusivity with parastoo lifecycle ops (owner decree
# 2026-11-09, «one transparent pipeline»): while a lifecycle operation runs,
# exec commands that mutate the platform are refused; while a conflicting exec
# runs, lifecycle start() refuses. The mid-install deploy race (parastoo
# docs/LESSONS.md, field 2026-11-08) must stay structurally impossible.
LIFECYCLE_CONFLICT_TOKENS = (
    "bootstrap.sh", "setup.sh", "install.sh", "uninstall.sh",
    "auto-update.sh", "factory-reset.sh", "tls-store.sh",
    "parastoo update", "parastoo reset", "parastoo autoupdate",
    "docker compose",
)

_active_lock = threading.Lock()
_active_cmds: dict[int, str] = {}
_active_seq = 0


def lifecycle_conflict(cmd: str) -> str:
    """First conflict token found in cmd ("" if none)."""
    low = (cmd or "").lower()
    for tok in LIFECYCLE_CONFLICT_TOKENS:
        if tok in low:
            return tok
    return ""


def mutation_running() -> str:
    """Conflict token of a currently running exec that would collide with a
    lifecycle operation ("" if none)."""
    with _active_lock:
        snapshot = list(_active_cmds.values())
    for c in snapshot:
        tok = lifecycle_conflict(c)
        if tok:
            return tok
    return ""


def run_exec(cmd, timeout_s=60, cwd=None) -> dict:
    """Run a command on the host via bash -c. Returns a structured result.

    On input/validation errors returns {"ok": False, "error": ..., "status": 400}
    (status 429 when the concurrency cap is hit) — the HTTP layer maps it.
    """
    global _active_seq
    if not isinstance(cmd, str) or not cmd.strip():
        return {"ok": False, "error": "cmd_required", "status": 400}
    if len(cmd) > MAX_CMD_CHARS:
        return {"ok": False, "error": "cmd_too_long", "limit": MAX_CMD_CHARS, "status": 400}
    try:
        timeout_s = int(timeout_s)
    except (TypeError, ValueError):
        return {"ok": False, "error": "bad_timeout", "status": 400}
    if timeout_s < 1 or timeout_s > MAX_TIMEOUT_S:
        return {"ok": False, "error": "timeout_out_of_range", "limit": MAX_TIMEOUT_S, "status": 400}
    if cwd is not None:
        if not isinstance(cwd, str) or not os.path.isdir(cwd):
            return {"ok": False, "error": "cwd_not_found", "status": 400}
    if not _sem.acquire(blocking=False):
        return {"ok": False, "error": "busy",
                "detail": f"max {MAX_CONCURRENT} concurrent execs", "status": 429}
    with _active_lock:  # v0.5.1: track running cmds for the lifecycle guard
        _active_seq += 1
        seq = _active_seq
        _active_cmds[seq] = cmd

    started = time.monotonic()
    timed_out = False
    try:
        env = {
            "PATH": os.environ.get(
                "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            "HOME": os.environ.get("HOME", "/root"),
            "TERM": os.environ.get("TERM", "dumb"),
            "LANG": "C.UTF-8",
        }
        proc = subprocess.Popen(
            ["bash", "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,       # never inherit the caller's stdin
            cwd=cwd,
            env=env,
            start_new_session=True,
        )
        try:
            out_b, err_b = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                proc.kill()
            out_b, err_b = proc.communicate()

        def cap(b) -> str:
            s = (b or b"").decode("utf-8", "replace")
            if len(s) > MAX_OUTPUT_CHARS:
                s = s[:MAX_OUTPUT_CHARS] + f"\n...[truncated at {MAX_OUTPUT_CHARS} chars]"
            return s

        return {
            "ok": True,
            "exit_code": proc.returncode,
            "stdout": cap(out_b),
            "stderr": cap(err_b),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "timed_out": timed_out,
        }
    finally:
        with _active_lock:
            _active_cmds.pop(seq, None)
        _sem.release()
