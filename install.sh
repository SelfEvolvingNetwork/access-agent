#!/usr/bin/env bash
# =============================================================
#  Access Agent — installer (invoked by bootstrap.sh or from a local folder)
#    Usage: sudo bash install.sh [SRC_DIR]
#  Idempotent: re-running UPGRADES the code and KEEPS all secrets
#  (tokens, TLS certs, GitHub PAT, audit log) — nothing is printed twice.
# =============================================================
set -euo pipefail

SRC_DIR="${1:-$(pwd)}"
ETC="${ACCESS_AGENT_ETC:-/etc/access-agent}"
OPT="${ACCESS_AGENT_OPT:-/opt/access-agent}"
UNIT_DIR="${ACCESS_AGENT_UNIT_DIR:-/etc/systemd/system}"
CLI_BIN="${ACCESS_AGENT_CLI_BIN:-/usr/local/bin/access-agent}"
SERVICE=access-agent

# v0.1.2: run a command in the HOST network namespace when possible. Under a
# privileged chroot container (AI-agent exec bridge) the container netns differs
# from the host — the UDP probe and 127.0.0.1 self-check would report/see the
# container's network, not the host's. On a normal host (root) nsenter -t 1 -n
# is identity; as non-root (sandbox e2e) it fails and we fall back to direct.
hostns() {
  if command -v nsenter >/dev/null 2>&1 && nsenter -t 1 -n true 2>/dev/null; then
    nsenter -t 1 -n "$@"
  else
    "$@"
  fi
}

# v0.5.2 — single token-writer used by BOTH the fresh path and the re-provision
# reset path (contract: Parastoo Mobile «رمز روت = مالکیت»). Never prints tokens.
write_tokens() {  # $1=ETC  $2=admin_token  $3=agent_token
  local etc="$1" admin="$2" agent="$3"
  "$PYBIN" - "$etc" \
    "$("$PYBIN" -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$admin")" \
    "$("$PYBIN" -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$agent")" <<'PY'
import json, os, sys
etc, a, g = sys.argv[1], sys.argv[2], sys.argv[3]
with open(os.path.join(etc, "tokens.json"), "w", encoding="utf-8") as f:
    json.dump({"admin_sha": a, "agent_sha": g, "updated_at": ""}, f, indent=2)
PY
  mkdir -p "$etc/secrets"
  printf '%s\n' "$admin" > "$etc/secrets/admin-token"
  printf '%s\n' "$agent" > "$etc/secrets/agent-token"
  chmod 600 "$etc/tokens.json" "$etc/secrets/admin-token" "$etc/secrets/agent-token"
}

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
say()  { echo -e "${BLUE}==>${NC} $*"; }
ok()   { echo -e "${GREEN} [ok]${NC} $*"; }
warn() { echo -e "${YELLOW} [warn]${NC} $*"; }
die()  { echo -e "${RED} error:${NC} $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root:  sudo bash install.sh $SRC_DIR"
[ -f "$SRC_DIR/access_agent/server.py" ] || die "invalid SRC_DIR: $SRC_DIR"

# ---------- 0) detect runtime facts ----------
PYBIN="$(command -v python3)"
HOSTNAME_BIN="$(hostname 2>/dev/null || echo server)"
VERSION="$("$PYBIN" - "$SRC_DIR" <<'PY'
import re, sys
src = open(sys.argv[1] + "/access_agent/__init__.py", encoding="utf-8").read()
m = re.search(r'VERSION\s*=\s*"([^"]+)"', src)
print(m.group(1) if m else "0.0.0")
PY
)"

is_private_ip() {  # 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10 CGNAT, 0/8, reserved 224+/8
  printf '%s' "${1:-}" | grep -qE '^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|0\.|22[4-9]\.|2[3-5][0-9]\.)'
}

# v0.6.4 — IP detection rewrite. The v0.1.2 hotfix (c4ade68) switched detect_ip
# to "first IPv4 of hostname -I"; on Docker-heavy hosts that grabs a bridge
# gateway (e.g. 172.22.0.1) and records an unreachable ACCESS_URL in
# config.json, the report card and the handoff block. New priority (every
# probe runs in the host netns via hostns — the v0.1.2 container-netns intent
# is preserved):
#   1) source IP of the default route — `ip route get`, then the 8.8.8.8 UDP
#      probe; the address egress traffic actually leaves from, immune to
#      Docker bridges;
#   2) first PUBLIC IPv4 from hostname -I (private/reserved ranges skipped);
#   3) first IPv4 from hostname -I (private-only / NAT hosts — v0.1.2 behavior);
#   4) 127.0.0.1 last resort.
detect_ip() {
  local ip pub
  ip="$(hostns ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}\).*/\1/p' | head -n1 || true)"
  if [ -n "$ip" ] && ! is_private_ip "$ip"; then
    echo "$ip"; return
  fi
  ip="$("$PYBIN" - <<'PY' 2>/dev/null || true
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(("8.8.8.8", 80))
    print(s.getsockname()[0])
except Exception:
    pass
finally:
    s.close()
PY
)"
  if [ -n "$ip" ] && ! is_private_ip "$ip"; then
    echo "$ip"; return
  fi
  pub="$(hostns hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | { grep -vE '^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|0\.|22[4-9]\.|2[3-5][0-9]\.)' || true; } | head -n1 || true)"
  if [ -n "$pub" ]; then
    echo "$pub"; return
  fi
  ip="$(hostns hostname -I 2>/dev/null | awk '{print $1}')"
  if [ -n "$ip" ]; then
    echo "$ip"
  else
    echo "127.0.0.1"
  fi
}
pick_free_port() {
  "$PYBIN" - <<'PY'
import random, socket
for _ in range(50):
    p = random.randint(20000, 39999)
    s = socket.socket()
    try:
        s.bind(("0.0.0.0", p)); s.close(); print(p); break
    except OSError:
        s.close()
PY
}

# ---------- 1) fresh install vs upgrade ----------
FRESH=1
[ -f "$ETC/tokens.json" ] && FRESH=0
if [ "$FRESH" = "1" ]; then
  say "Fresh install detected (no $ETC/tokens.json)."
else
  say "Existing installation found — upgrading code, KEEPING all secrets."
fi

mkdir -p "$ETC" "$OPT"
chmod 700 "$ETC"

if [ "$FRESH" = "1" ]; then
  PORT="${ACCESS_AGENT_PORT:-$(pick_free_port)}"
  case "$PORT" in ''|*[!0-9]*) die "ACCESS_AGENT_PORT must be numeric";; esac
  IP="$(detect_ip)"
  # v0.2.1: a provisioning client (e.g. Parastoo Mobile) may generate the tokens
  # on-device and pass them via env — such tokens are NEVER printed back.
  ADMIN_TOKEN="${ACCESS_AGENT_ADMIN_TOKEN:-}"
  AGENT_TOKEN="${ACCESS_AGENT_AGENT_TOKEN:-}"
  TOKENS_SELF_GENERATED=1
  if [ -z "$ADMIN_TOKEN" ]; then ADMIN_TOKEN="adm_$(openssl rand -hex 24)"; else TOKENS_SELF_GENERATED=0; fi
  if [ -z "$AGENT_TOKEN" ]; then AGENT_TOKEN="aa_$(openssl rand -hex 24)"; else TOKENS_SELF_GENERATED=0; fi

  # tokens.json (hashes only) + plaintext copies under secrets/ (root-only)
  write_tokens "$ETC" "$ADMIN_TOKEN" "$AGENT_TOKEN"

  # TLS: self-signed cert (10 years) with SAN for IP + hostname
  mkdir -p "$ETC/tls"
  CERT_OK=0
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/CN=access-agent" \
      -addext "subjectAltName=IP:${IP},DNS:${HOSTNAME_BIN}" \
      -keyout "$ETC/tls/key.pem" -out "$ETC/tls/cert.pem" </dev/null >/dev/null 2>&1 || CERT_OK=1
  if [ "$CERT_OK" = "1" ]; then
    warn "openssl -addext unsupported; generating without SAN"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=access-agent" \
        -keyout "$ETC/tls/key.pem" -out "$ETC/tls/cert.pem" </dev/null >/dev/null 2>&1
  fi
  chmod 600 "$ETC/tls/key.pem"; chmod 644 "$ETC/tls/cert.pem"

  # optional: store the owner's GitHub PAT right at install time
  if [ -n "${ACCESS_AGENT_GITHUB_TOKEN:-}" ]; then
    printf '# managed by access-agent — root-only, never commit\nGITHUB_TOKEN=%s\n' \
      "$ACCESS_AGENT_GITHUB_TOKEN" > "$ETC/github.env"
    chmod 600 "$ETC/github.env"
    ok "GitHub token stored (ACCESS_AGENT_GITHUB_TOKEN)."
  fi
else
  PORT="$("$PYBIN" -c "import json;print(json.load(open('$ETC/config.json'))['port'])" 2>/dev/null || echo "")"
  if [ -z "$PORT" ]; then warn "config.json missing — cannot resolve port"; exit 1; fi
  IP="$(detect_ip)"
  # regenerate TLS only if missing
  if [ ! -f "$ETC/tls/cert.pem" ] || [ ! -f "$ETC/tls/key.pem" ]; then
    mkdir -p "$ETC/tls"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=access-agent" \
        -keyout "$ETC/tls/key.pem" -out "$ETC/tls/cert.pem" </dev/null >/dev/null 2>&1
    chmod 600 "$ETC/tls/key.pem"; chmod 644 "$ETC/tls/cert.pem"
    warn "TLS certs were missing — regenerated."
  fi

  # v0.5.2 — ownership transfer on re-provision (documented contract of
  # Parastoo Mobile: «رمز روت = مالکیت»). With ACCESS_AGENT_RESET_TOKENS=1 the
  # provisioning client REPLACES both tokens with the ones it generated
  # on-device; previous tokens die, nothing is ever printed. Refused without
  # env tokens so a half-sent env can never lock the owner out.
  TOKENS_RESET=0
  if [ "${ACCESS_AGENT_RESET_TOKENS:-}" = "1" ]; then
    RT_ADMIN="${ACCESS_AGENT_ADMIN_TOKEN:-}"
    RT_AGENT="${ACCESS_AGENT_AGENT_TOKEN:-}"
    if [ -n "$RT_ADMIN" ] && [ -n "$RT_AGENT" ]; then
      write_tokens "$ETC" "$RT_ADMIN" "$RT_AGENT"
      TOKENS_RESET=1
      ok "Tokens REPLACED by provisioning client (ownership transfer) — never printed."
    else
      warn "RESET_TOKENS=1 but env tokens missing — keeping existing tokens (lockout avoided)."
    fi
  fi
fi

# ---------- 2) code ----------
say "Installing code to $OPT ..."
rm -rf "$OPT/access_agent"
cp -r "$SRC_DIR/access_agent" "$OPT/access_agent"
rm -rf "$OPT/access_agent/__pycache__"
find "$OPT/access_agent" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
# v0.5.7 (owner decree 2026-11-09: «پرستو موبایل دستور پاک کردن پل را می‌دهد»):
# the bridge must be able to remove ITSELF offline — keep the official
# uninstaller inside the install tree so the self-purge never depends on
# GitHub reachability at the moment of destruction.
if [ -f "$SRC_DIR/uninstall.sh" ]; then
  cp -f "$SRC_DIR/uninstall.sh" "$OPT/uninstall.sh"
else
  warn "uninstall.sh missing from source — bridge self-purge will fall back to fetching it"
fi
if [ -f "$SRC_DIR/deploy/access-agent-cli.sh" ]; then
  mkdir -p "$(dirname "$CLI_BIN")"   # v0.2.1: destination dir may not exist yet
  cp "$SRC_DIR/deploy/access-agent-cli.sh" "$CLI_BIN"
  chmod 755 "$CLI_BIN"
fi

# v0.8.2 — in-system data rotation (owner decree 2026-11-12, «harmful update
# pattern»): an app-core override left by an OLDER code generation must not
# outlive the code it came with. If the override on disk is older than the
# payload embedded in the code we just installed, remove it — the bridge then
# serves the newer embedded payload (appcore.snapshot() also refuses to serve
# an older override at runtime; this is belt-and-braces hygiene, best-effort).
if [ -f "$ETC/app-core/core.json" ]; then
  STALE_MSG="$(mktemp)"
  "$PYBIN" - "$ETC" "$OPT" >"$STALE_MSG" 2>/dev/null <<'STALE_PY' || true
import json, os, re, sys
etc, opt = sys.argv[1], sys.argv[2]
try:
    src_txt = open(os.path.join(opt, "access_agent", "appcore.py"), encoding="utf-8").read()
    m = re.search(r'"revision":\s*(\d+)', src_txt)
    embedded_rev = int(m.group(1)) if m else 0
    ov = json.loads(open(os.path.join(etc, "app-core", "core.json"), encoding="utf-8").read())
    if int(ov.get("revision", 0)) < embedded_rev:
        os.remove(os.path.join(etc, "app-core", "core.json"))
        print(f"removed: override rev {ov.get('revision')} < embedded rev {embedded_rev}")
except Exception:
    pass  # unreadable override: leave it; the runtime guard still protects serving
STALE_PY
  if grep -q "^removed:" "$STALE_MSG" 2>/dev/null; then
    ok "app-core: stale override cleared — $(cat "$STALE_MSG")"
  fi
  rm -f "$STALE_MSG"
fi

# record config (never contains secrets)
COMMIT="${ACCESS_AGENT_DEPLOYED_COMMIT:-}"
"$PYBIN" - "$ETC" "$PORT" "$IP" "$VERSION" "$COMMIT" <<'PY'
import json, os, sys, time
etc, port, ip, ver, commit = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
cfg = {"port": int(port), "ip": ip, "version": ver, "commit": commit,
       "installed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
with open(os.path.join(etc, "config.json"), "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
PY
chmod 600 "$ETC/config.json"

# ---------- 3) systemd ----------
say "Writing systemd unit ($SERVICE.service)..."
mkdir -p "$UNIT_DIR"   # v0.2.1: override dirs (tests/containers) may not exist
cat > "${UNIT_DIR}/${SERVICE}.service" <<UNIT
[Unit]
Description=Access Agent — independent AI-agent bridge (survives Parastoo crashes)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$OPT
ExecStart=$PYBIN -m access_agent.server
Environment=ACCESS_AGENT_HOME=$ETC
Environment=ACCESS_AGENT_PORT=$PORT
User=root
Restart=always
RestartSec=3
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
UNIT
# v0.2.1: systemd guard — containers and exotic hosts may lack systemd.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1 || true
  if systemctl is-active --quiet "$SERVICE"; then
    systemctl restart "$SERVICE"
  else
    systemctl start "$SERVICE"
  fi
  ok "Service started (Restart=always, independent of Docker)."
else
  warn "systemd not available — starting via nohup (survives logout, not reboot)."
  pkill -f "access_agent.server" 2>/dev/null || true
  ( cd "$OPT" && ACCESS_AGENT_HOME="$ETC" ACCESS_AGENT_PORT="$PORT" \
      nohup "$PYBIN" -m access_agent.server >>"$ETC/agent.nohup.log" 2>&1 & )
  sleep 1
fi

# best-effort firewall opening
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$PORT"/tcp </dev/null >/dev/null 2>&1 && ok "ufw: port $PORT/tcp allowed." || warn "ufw allow failed — open port $PORT/tcp manually."
fi

# ---------- 4) self-check ----------
say "Self-check: https://127.0.0.1:${PORT}/healthz ..."
HEALTH=""
for i in $(seq 1 20); do
  HEALTH="$(hostns curl -sk --max-time 3 "https://127.0.0.1:${PORT}/healthz" 2>/dev/null || true)"
  echo "$HEALTH" | grep -q '"ok": *true\|"ok":true' && break
  sleep 1
done
if echo "$HEALTH" | grep -q '"ok": *true\|"ok":true'; then
  ok "Health check passed: $HEALTH"
else
  warn "Health check FAILED — inspect:  systemctl status $SERVICE --no-pager && journalctl -u $SERVICE -n 30"
fi

# ---------- 5) report ----------
CERT_SHA="$(openssl x509 -in "$ETC/tls/cert.pem" -noout -fingerprint -sha256 2>/dev/null \
  | sed 's/^.*Fingerprint=//' | tr -d ':' || true)"
URL="https://${IP}:${PORT}"

ORG_REPO_URL="https://raw.githubusercontent.com/SelfEvolvingNetwork/access-agent/main"
REPORT="$ETC/install-report.txt"
{
  echo "============================================================"
  echo " Access Agent v$VERSION — installed $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "============================================================"
  echo "ACCESS_URL:      $URL"
  echo "CERT_SHA256:     $CERT_SHA"
  if [ "$FRESH" = "1" ]; then
    if [ "$TOKENS_SELF_GENERATED" = "1" ]; then
      echo "AGENT_TOKEN:     $AGENT_TOKEN"
      echo "ADMIN_TOKEN:     (stored on server — view it with:  sudo access-agent show-admin-token)"
      echo "  -> give ACCESS_URL + CERT_SHA256 + AGENT_TOKEN to your AI agent."
      echo "  -> ADMIN_TOKEN stays with you (never sent to the agent; never in the handoff block)."
    else
      echo "AGENT_TOKEN:     (provided by provisioning client — not printed)"
      echo "ADMIN_TOKEN:     (provided by provisioning client — not printed)"
      echo "  -> the client already holds its token; nothing to hand over."
    fi
    echo "  -> v0.2: real <=1h GitHub tokens via GitHub App — see:  sudo access-agent set-github-app"
  else
    if [ "${TOKENS_RESET:-0}" = "1" ]; then
      echo "  -> upgrade: certs/PAT kept unchanged; TOKENS REPLACED (ownership transfer)."
    else
      echo "  -> upgrade: tokens/certs/PAT kept unchanged."
    fi
    echo "  -> tokens live in $ETC/secrets/ (root-only)."
  fi
  echo "COMMIT:          ${COMMIT:-unknown}"
  echo "SECRETS_DIR:     $ETC/secrets (chmod 600)"
  echo "AUDIT_LOG:       $ETC/audit/audit.jsonl (append-only)"
  echo "OWNER CLI:       access-agent status | url | invite | approve <code> | handoff | rotate-agent-token | revoke-agent-token | revoke-agent-sessions | set-github-token <token> | set-github-app <id> <pem> | test-github-app"
  echo "INVITE:          sudo access-agent invite   # URL + cert hash only — agent makes its own 5-digit code; confirm it with:  sudo access-agent approve <code>"
  echo "SERVICE:         systemctl status $SERVICE --no-pager"
  echo "UNINSTALL:       curl -fsSL $ORG_REPO_URL/uninstall.sh | sudo bash"
  echo "============================================================"
} | tee "$ETC/install-report.tmp" >/dev/null
mv "$ETC/install-report.tmp" "$REPORT"
chmod 600 "$REPORT"

echo ""
cat "$ETC/install-report.txt"

# v0.1.3: the owner's single copy-paste step — hand the AI agent its mission.
# Fresh install prints the block right here (tokens are already in hand);
# upgrades point to the canonical reprint command.
if [ "$FRESH" = "1" ] && [ -x "$CLI_BIN" ]; then
  if [ "$TOKENS_SELF_GENERATED" = "1" ]; then
    say "Handoff block — copy everything between the lines to your AI agent:"
    ACCESS_AGENT_HOME="$ETC" "$CLI_BIN" handoff || warn "handoff block failed — reprint anytime:  sudo access-agent handoff"
  else
    # v0.2.1: client-provisioned tokens must never reappear on the terminal.
    say "Tokens were provided by the provisioning client — handoff block skipped (it would print the agent token)."
    say "Reprint the AI-agent handoff block anytime:  sudo access-agent handoff"
  fi
else
  say "Reprint the AI-agent handoff block anytime:  sudo access-agent handoff"
fi

if [ "$FRESH" = "1" ]; then
  warn "This report is printed ONCE and saved to $ETC/install-report.txt (chmod 600)."
fi
