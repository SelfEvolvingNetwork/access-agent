#!/usr/bin/env bash
# =============================================================
#  Access Agent — server-side self-updater (v0.8.3)
#
#  Owner decree 2026-11-11: «پل باید اتوماتیک خودش را آپدیت کند؛ اگر
#  نتوانست پرستو موبایل آپدیت می‌کند» — restored 2026-11-12 after the
#  0.6.3 code fell out of main (audit finding: the live timer kept running
#  a fossil engine from bridge-r24 while the repo had moved on).
#
#  Contract: docs/AGENT_PROTOCOL.fa.md §۸ (headless) + §۸.۱۰
#   - armed by default via access-agent-update.timer (~10 min) — off:
#       sudo access-agent autoupdate off
#   - the SAME two-channel integrity as Parastoo Mobile:
#       RELEASE_MANIFEST.json (main)  +  release asset (bridge-r<N>)
#   - sha256 strict / no downgrade / secrets & TLS certs untouched / no RESET_TOKENS
#   - deferred while a parastoo lifecycle op is in-flight (one changing actor)
#   - IDENTITY-CONTINUITY GUARD (v0.8.3, the field bug behind the owner's
#     warning «آی‌پی لوکال به‌جای آی‌پی اصلی سرور — هیچ اتصالی ممکن نبود»):
#     the recorded address (ip/port) and the TLS cert are SERVER IDENTITY,
#     not version. Before updating we snapshot them; after install we
#     hard-verify version + cert_sha256 + ip + port. ANY drift = automatic
#     rollback (code + config + TLS from the one-generation backup).
#   - history: $ETC/updates.jsonl — mirrored into /api/status as "self_update"
#   - output English on purpose (SSH/RTL lesson). Run as root (systemd oneshot).
#
#  Env overrides (tests + bootstrap deploy):
#   ACCESS_AGENT_ETC, ACCESS_AGENT_OPT,
#   ACCESS_AGENT_MANIFEST_URL, ACCESS_AGENT_BUNDLE_URL,
#   ACCESS_AGENT_MANIFEST_FILE, ACCESS_AGENT_BUNDLE_FILE,
#   ACCESS_AGENT_SKIP_INSTALL=1  (test hook: stop right after extract)
#   ACCESS_AGENT_HEALTHZ_FILE=   (test hook: canned healthz JSON instead of curl)
#   ACCESS_AGENT_ALLOW_NONROOT=1 (test hook: relax the root check ONLY here —
#                                  install.sh still enforces root itself)
# =============================================================
set -euo pipefail

ETC="${ACCESS_AGENT_ETC:-/etc/access-agent}"
OPT="${ACCESS_AGENT_OPT:-/opt/access-agent}"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

MANIFEST_URL="${ACCESS_AGENT_MANIFEST_URL:-https://raw.githubusercontent.com/SelfEvolvingNetwork/access-agent/main/RELEASE_MANIFEST.json}"
BUNDLE_BASE="${ACCESS_AGENT_BUNDLE_URL:-https://github.com/SelfEvolvingNetwork/access-agent/releases/latest/download}"
MANIFEST_FILE="${ACCESS_AGENT_MANIFEST_FILE:-}"
BUNDLE_FILE="${ACCESS_AGENT_BUNDLE_FILE:-}"
SKIP_INSTALL="${ACCESS_AGENT_SKIP_INSTALL:-0}"
HEALTHZ_FILE="${ACCESS_AGENT_HEALTHZ_FILE:-}"
ALLOW_NONROOT="${ACCESS_AGENT_ALLOW_NONROOT:-0}"
# Iran networks lesson (Vazirmatn CDN): direct GitHub is intermittent — try proxies as fallback.
PROXIES=("" "https://gh-proxy.com/")

say()  { echo "  self-update: $*"; }
ok()   { echo "  self-update [ok] $*"; }
warn() { echo "  self-update [warn] $*"; }
die()  { echo "  self-update error: $*" >&2; exit 1; }

# ---------- history: one JSON line per attempt (mirrored in /api/status) ----------
log_row() { # $1=result  $2=detail
  python3 - "$ETC" "${1:-}" "${2:-}" "${INSTALLED:-}" "${MAN_V:-}" <<'PY'
import json, os, sys, time
etc, result, detail, frm, to = sys.argv[1:6]
row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
       "action": "self_update", "result": result,
       "from": frm or None, "to": to or None, "detail": detail}
os.makedirs(etc, exist_ok=True)
p = os.path.join(etc, "updates.jsonl")
with open(p, "a", encoding="utf-8") as f:
    f.write(json.dumps(row, ensure_ascii=False) + "\n")
os.chmod(p, 0o600)
PY
}

# ---------- network: direct first, proxy fallback (fails closed) ----------
fetch() { # $1=url  $2=out
  local p u
  for p in "${PROXIES[@]}"; do
    u="${p}${1}"
    if curl -fsSL --max-time 90 "$u" -o "$2" 2>/dev/null && [ -s "$2" ]; then
      [ -n "$p" ] && say "fetched via proxy: $p"
      return 0
    fi
  done
  return 1
}

# ---------- semver-ish compare: returns 0 when $1 >= $2 ----------
ver_ge() {
  python3 - "$1" "$2" <<'PY'
import sys
def key(v):
    out = []
    for part in str(v).strip().lstrip("v").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    while len(out) < 3:
        out.append(0)
    return out
sys.exit(0 if key(sys.argv[1]) >= key(sys.argv[2]) else 1)
PY
}

# ---------- config access (ACCESS_AGENT_ETC-aware) ----------
cfg_get() { # $1=key
  python3 -c "import json;print(json.load(open('$ETC/config.json')).get('$1',''))" 2>/dev/null || true
}

# ---------- healthz field reader (test hook: canned JSON file) ----------
health_field() { # $1=port  $2=field
  if [ -n "$HEALTHZ_FILE" ]; then
    python3 -c "import json;print(json.load(open('$HEALTHZ_FILE')).get('$2',''))" 2>/dev/null || true
  else
    curl -sk --max-time 4 "https://127.0.0.1:${1}/healthz" 2>/dev/null \
      | python3 -c "import json,sys
try:
    print(json.load(sys.stdin).get('$2',''))
except Exception:
    print('')" 2>/dev/null || true
  fi
}

cert_sha_of_file() { # DER SHA-256 fingerprint of a PEM cert (same form healthz reports)
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
    | sed 's/^.*Fingerprint=//' | tr -d ':' || true
}

# ---------- one changing actor: defer while parastoo lifecycle is in-flight ----------
lifecycle_busy() {
  local port tok snap
  port="$(cfg_get port)"
  [ -n "$port" ] || return 1
  tok=""
  [ -f "$ETC/secrets/admin-token" ] && tok="$(head -1 "$ETC/secrets/admin-token")"
  [ -n "$tok" ] || return 1
  snap="$(curl -sk --max-time 5 -H "Authorization: Bearer $tok" \
        "https://127.0.0.1:${port}/api/admin/parastoo/lifecycle-status" 2>/dev/null || true)"
  echo "$snap" | grep -q '"busy": *true\|"busy":true'
}

# ---------- rollback: code + config + TLS from the one-generation backup ----------
# v0.8.3: TLS is restored too — install.sh only regenerates the cert when the
# files are MISSING, but if that ever happens mid-update the pinned clients
# (mobile app + AI agent) are severed; restoring the backup cert/key closes it.
rollback() {
  if [ -d "$OPT/.prev-access_agent" ]; then
    say "restoring previous code from $OPT/.prev-access_agent"
    rm -rf "$OPT/access_agent"
    cp -a "$OPT/.prev-access_agent" "$OPT/access_agent"
    [ -f "$OPT/.prev-config.json" ] && cp -f "$OPT/.prev-config.json" "$ETC/config.json" || true
    if [ -d "$OPT/.prev-tls" ]; then
      mkdir -p "$ETC/tls"
      cp -f "$OPT/.prev-tls/cert.pem" "$ETC/tls/cert.pem" 2>/dev/null || true
      cp -f "$OPT/.prev-tls/key.pem" "$ETC/tls/key.pem" 2>/dev/null || true
      chmod 600 "$ETC/tls/key.pem" 2>/dev/null || true
    fi
    systemctl restart access-agent 2>/dev/null || true
    sleep 2
    local v; v="$(health_field "$(cfg_get port)" version || true)"
    if [ -n "$v" ]; then warn "rolled back — bridge healthy again at v$v"; else warn "rolled back — bridge still unhealthy, manual attention needed"; fi
  else
    warn "no backup found — cannot roll back (install.sh v0.8.3+ maintains it)"
  fi
}

# ---------- 0) preconditions ----------
# Root is required only for the real install/restart path; --check and the
# SKIP_INSTALL / ALLOW_NONROOT test hooks are read-only plumbing (download/
# verify/log) and must stay testable as non-root (CI + sandbox). install.sh
# enforces root itself — the defense lives there, not here.
NEED_ROOT=1
[ "$CHECK_ONLY" = "1" ] && NEED_ROOT=0
[ "$SKIP_INSTALL" = "1" ] && NEED_ROOT=0
[ "$ALLOW_NONROOT" = "1" ] && NEED_ROOT=0
if [ "$NEED_ROOT" = "1" ] && [ "$(id -u)" -ne 0 ]; then
  die "run as root (systemd oneshot does this)"
fi
[ -f "$ETC/config.json" ] || { say "no installation found ($ETC/config.json) — nothing to do"; exit 0; }
INSTALLED="$(cfg_get version)"
PORT="$(cfg_get port)"

# ---- IDENTITY SNAPSHOT (before anything is touched) ----
# v0.8.3: address + cert are server identity (AGENT_PROTOCOL §۲.۱ mirror).
# Field bug 2026-11-10: upgrade-time re-detection recorded a Docker-bridge
# IP (172.22.0.1) as the ACCESS_URL — no client could connect. The guard
# below makes that class of corruption impossible to land silently.
PRE_CERT="$(cert_sha_of_file "$ETC/tls/cert.pem")"
PRE_IP="$(cfg_get ip)"
PRE_PORT="$PORT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------- 1) manifest (independent integrity channel) ----------
if [ -n "$MANIFEST_FILE" ]; then
  cp -f "$MANIFEST_FILE" "$TMP/manifest.json"
else
  fetch "$MANIFEST_URL" "$TMP/manifest.json" || { log_row "network_fail" "manifest unreachable"; die "cannot fetch RELEASE_MANIFEST.json (direct+proxy)"; }
fi
read -r MAN_V MAN_F MAN_SHA <<EOF
$(python3 - "$TMP/manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
print(m.get("version", ""), m.get("filename", ""), m.get("sha256", ""))
PY
)
EOF
[ -n "$MAN_V" ] && [ -n "$MAN_SHA" ] || { log_row "bad_manifest" "missing version/sha256"; die "manifest malformed"; }

# ---------- 2) decision: downgrade guard + check-only ----------
if ver_ge "$INSTALLED" "$MAN_V"; then
  if [ "$INSTALLED" = "$MAN_V" ]; then
    say "already up to date (v$INSTALLED)"
    log_row "noop" "installed==manifest==v$MAN_V"
  else
    warn "downgrade refused: installed v$INSTALLED > manifest v$MAN_V"
    log_row "downgrade_refused" "installed v$INSTALLED > manifest v$MAN_V"
  fi
  exit 0
fi
if [ "$CHECK_ONLY" = "1" ]; then
  ok "update available: v$INSTALLED -> v$MAN_V ($MAN_F)"
  exit 0
fi

# ---------- 3) one changing actor: defer during parastoo lifecycle ----------
if lifecycle_busy; then
  say "parastoo lifecycle op in-flight — deferring (next tick retries)"
  log_row "deferred_busy" "lifecycle busy; retry next tick"
  exit 0
fi

# ---------- 4) bundle download + strict sha256 (tainted mirror = hard reject) ----------
if [ -n "$BUNDLE_FILE" ]; then
  cp -f "$BUNDLE_FILE" "$TMP/bundle.tar.gz"
else
  fetch "$BUNDLE_BASE/$MAN_F" "$TMP/bundle.tar.gz" || { log_row "network_fail" "bundle unreachable"; die "cannot fetch $MAN_F (direct+proxy)"; }
fi
if ! echo "$MAN_SHA  $TMP/bundle.tar.gz" | sha256sum -c --status >/dev/null 2>&1; then
  log_row "sha_mismatch" "bundle sha256 != manifest sha256"
  die "sha256 mismatch — bundle rejected (two-channel integrity contract §8)"
fi
ok "bundle verified: $MAN_F (sha256 ok)"

# ---------- 5) extract ----------
mkdir -p "$TMP/src"
tar -xzf "$TMP/bundle.tar.gz" -C "$TMP/src"
[ -f "$TMP/src/install.sh" ] && [ -f "$TMP/src/access_agent/server.py" ] || { log_row "bad_bundle" "install.sh/server.py missing"; die "bundle layout invalid"; }
[ "$SKIP_INSTALL" = "1" ] && { log_row "skip_install" "test hook (ACCESS_AGENT_SKIP_INSTALL=1)"; ok "extract-only done (test hook)"; exit 0; }

# ---------- 6) install — the same script the app runs; it locks, backs up, keeps secrets ----------
# install.sh v0.8.3 keeps the recorded address on upgrade (IP continuity) and
# refreshes /opt/deploy/self-update.sh (new inode) + the timer units itself.
say "upgrading v$INSTALLED -> v$MAN_V ..."
if bash "$TMP/src/install.sh" "$TMP/src" >"$ETC/last-update-install.log" 2>&1; then
  chmod 600 "$ETC/last-update-install.log" 2>/dev/null || true
  say "install.sh finished (log: $ETC/last-update-install.log)"
else
  log_row "install_failed" "install.sh rc=$? — see $ETC/last-update-install.log"
  warn "install.sh FAILED — rolling back"
  rollback
  exit 1
fi

# ---------- 7) strict verify: version + IDENTITY (cert/address); fail = rollback ----------
# Probe the port the (possibly rewritten) config names — but the guard below
# compares against the PRE-update snapshot, so any drift still rolls back.
PROBE_PORT="$(cfg_get port)"
[ -n "$PROBE_PORT" ] || PROBE_PORT="$PORT"
GOT=""; GOT_CERT=""
for _ in $(seq 1 25); do
  GOT="$(health_field "$PROBE_PORT" version)"
  GOT_CERT="$(health_field "$PROBE_PORT" cert_sha256)"
  [ "$GOT" = "$MAN_V" ] && [ -n "$GOT_CERT" ] && break
  sleep 1
done
IDENTITY_BAD=""
if [ "$GOT" != "$MAN_V" ]; then
  IDENTITY_BAD="version: healthz reports '${GOT:-none}', want v$MAN_V"
elif [ -n "$PRE_CERT" ] && [ "$GOT_CERT" != "$PRE_CERT" ]; then
  IDENTITY_BAD="TLS cert changed ($PRE_CERT -> ${GOT_CERT:-none}) — pinned clients would break"
elif [ -n "$PRE_IP" ] && [ "$(cfg_get ip)" != "$PRE_IP" ]; then
  IDENTITY_BAD="recorded address changed ($PRE_IP -> $(cfg_get ip)) — clients would be severed"
elif [ -n "$PRE_PORT" ] && [ "$(cfg_get port)" != "$PRE_PORT" ]; then
  IDENTITY_BAD="port changed ($PRE_PORT -> $(cfg_get port))"
fi
if [ -z "$IDENTITY_BAD" ] && [ "$GOT" = "$MAN_V" ]; then
  ok "bridge healthy at v$GOT — identity intact (cert + address unchanged)"
  log_row "success" "v$INSTALLED -> v$MAN_V; identity: cert+addr unchanged"
  exit 0
fi
# version mismatch with no identity note = plain unhealthy
[ -z "$IDENTITY_BAD" ] && IDENTITY_BAD="healthz unreachable or wrong version (got '${GOT:-none}', want v$MAN_V)"
log_row "rolled_back" "$IDENTITY_BAD"
warn "post-install check FAILED — $IDENTITY_BAD — rolling back"
rollback
exit 1
