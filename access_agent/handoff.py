"""Owner→AI handoff block — access_agent.handoff (v0.1.3).

Field decision 2026-11-05: after install the owner should have ONE thing to
copy into the chat with the AI agent — not three values to retype. This module
composes that ready-to-paste block from files under ACCESS_AGENT_HOME
(config.json, tls/cert.pem, secrets/agent-token). It never contacts the
network and never returns the admin token.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

PROTOCOL_URL = ("https://raw.githubusercontent.com/SelfEvolvingNetwork/"
                "access-agent/main/docs/AGENT_PROTOCOL.fa.md")
PARASTOO_LOOP_URL = ("https://raw.githubusercontent.com/SelfEvolvingNetwork/"
                     "parastoo/main/docs/AI_AGENT_LOOP.md")


def _home() -> Path:
    return Path(os.environ.get("ACCESS_AGENT_HOME", "/etc/access-agent"))


def _cfg() -> dict:
    try:
        return json.loads((_home() / "config.json").read_text(encoding="utf-8"))
    except Exception:
        return {}


def cert_fingerprint() -> str:
    """SHA-256 of the TLS cert, colon-less hex (same form install.sh reports)."""
    p = _home() / "tls" / "cert.pem"
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(p), "-noout", "-fingerprint", "-sha256"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout
        return out.split("=", 1)[1].strip().replace(":", "")
    except Exception:
        return ""


def agent_token() -> str:
    try:
        return (_home() / "secrets" / "agent-token").read_text(
            encoding="utf-8").strip()
    except Exception:
        return ""


def missing_inputs() -> list[str]:
    cfg = _cfg()
    miss: list[str] = []
    if not (cfg.get("ip") and cfg.get("port")):
        miss.append("config.json(ip/port)")
    if not agent_token():
        miss.append("secrets/agent-token")
    if not cert_fingerprint():
        miss.append("tls/cert.pem")
    return miss


def build_block() -> str:
    miss = missing_inputs()
    if miss:
        raise RuntimeError("handoff data missing: " + ", ".join(miss))
    cfg = _cfg()
    return (
        "---- HANDOFF BLOCK — copy everything between the lines to your AI agent ----\n"
        "You are the Parastoo dev-test agent on a server you know nothing about.\n"
        "Connect first, act later:\n"
        "\n"
        f"ACCESS_URL:  https://{cfg['ip']}:{cfg['port']}\n"
        f"CERT_SHA256: {cert_fingerprint()}   <- pin the TLS cert (self-signed on purpose)\n"
        f"AGENT_TOKEN: {agent_token()}   <- agent realm; NEVER ask for the admin token\n"
        "\n"
        f"Protocol (read first, it is short):\n{PROTOCOL_URL}\n"
        "Then follow the Parastoo dev-test loop — start at section 0 (cold start):\n"
        f"{PARASTOO_LOOP_URL}\n"
        "First calls: GET /healthz -> GET /api/status -> report to the owner "
        "and await orders.\n"
        "---- END HANDOFF BLOCK ----"
    )


if __name__ == "__main__":
    print(build_block())
