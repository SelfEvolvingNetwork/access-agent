#!/usr/bin/env bash
# =============================================================
#  Access Agent — server-side self-updater (v0.6.3 — فرمان مالک 2026-11-11:
#  «پل باید اتوماتیک خودش را آپدیت کند؛ اگر نتوانست، پرستو موبایل با اتصال
#  به اینترنت آن را آپدیت می‌کند»)
#
#  Contract: docs/AGENT_PROTOCOL.fa.md §۸.۱۰
#   - armed by default via access-agent-update.timer (~10 min) — off:
#       sudo access-agent autoupdate off
#   - the SAME two-channel integrity as Parastoo Mobile:
#       RELEASE_MANIFEST.json (main)  +  release asset (bridge-r<N>)
#   - sha256 strict / no downgrade / secrets & TLS certs untouched / no RESET_TOKENS
#   - deferred while a parastoo lifecycle op is in-flight (one changing actor)
#   - strict post-install health+version check → auto-rollback (one-generation backup)
#   - history: $ETC/updates.jsonl — mirrored into /api/status as "self_update"
#   - output English on purpose (SSH/RTL lesson). Run as root (systemd oneshot).
#
#  Env overrides (tests + bootstrap deploy):
#   ACCESS_AGENT_ETC, ACCESS_AGENT_OPT,
#   ACCESS_AGENT_MANIFEST_URL, ACCESS_AGENT_BUNDLE_URL,
#   ACCESS_AGENT_MANIFEST_FILE, ACCESS_AGENT_BUNDLE_FILE,
#   ACCESS_AGENT_SKIP_INSTALL=1  (test hook: stop right after extract)
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
# Iran networks lesson (Vazirmatn CDN): direct GitHub is intermittent — try proxies as fallback.
PROXIES=("" "https://gh-proxy.com/")

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
say()  { echo "  self-update: $*"; }
ok()   { echo -e "  ${GREEN}self-update [ok]${NC} $*"; }
warn() { echo -e "  ${YELLOW}self-update [warn]${NC} $*"; }
die()  { echo -e "  ${RED}self-update error:${NC} $*" >&2; exit 1; }

# ---------- history: one JSON line per attempt (mirrored in /api/status) ----------
log_row() { # $1=result  $2=detail
  python3 - "$ETC" "${1:-}" "${2:-}" "${INSTALLED:-}" "${MAN_V:-}" <<'PY'
import json, os, sys, time
etc, result, detail, frm, to = sys.argv[1:6]
row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
       "action": "self_update", "result": result,
       "from": frm or None, "to": to or None, "detail": detail}
os.makedirs(etc, exist_ok=True)
with open(os.path.join(etc, "updates.jsonl"), "a", encoding="utf-8") as f:
    f.write(json.dumps(row, ensure_ascii=False) + "\n")
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

# ---------- one changing actor: defer while parastoo lifecycle is in-flight ----------
lifecycle_busy() {
  local port tok snap
  port="$(python3 -c "import json;print(json.load(open('$ETC/config.json')).get('port',''))" 2>/dev/null || true)"
  [ -n "$port" ] || return 1
  tok=""
  [ -f "$ETC/secrets/admin-token" ] && tok="$(head -1 "$ETC/secrets/admin-token")"
  [ -n "$tok" ] || return 1
  snap="$(curl -sk --max-time 5 -H "Authorization: Bearer $tok" \
        "https://127.0.0.1:${port}/api/admin/parastoo/lifecycle-status" 2>/dev/null || true)"
  echo "$snap" | grep -q '"busy": *true\|"busy":true'
}

health_version() { # $1=port → prints running version ("" when unreachable)
  curl -sk --max-time 4 "https://127.0.0.1:${1}/healthz" 2>/dev/null \
    | python3 -c "import json,sys
try:
    print(json.load(sys.stdin).get('version', ''))
except Exception:
    print('')" 2>/dev/null || true
}

rollback() { # one-generation restore (secrets never touched — they live in $ETC)
  if [ -d "$OPT/.prev-access_agent" ]; then
    say "restoring previous code from $OPT/.prev-access_agent"
    rm -rf "$OPT/access_agent"
    cp -a "$OPT/.prev-access_agent" "$OPT/access_agent"
    [ -f "$OPT/.prev-config.json" ] && cp -f "$OPT/.prev-config.json" "$ETC/config.json" || true
    systemctl restart access-agent 2>/dev/null || true
    sleep 2
    local v; v="$(health_version "$PORT" || true)"
    if [ -n "$v" ]; then warn "rolled back — bridge healthy again at v$v"; else warn "rolled back — bridge still unhealthy, manual attention needed"; fi
  else
    warn "no backup found — cannot roll back"
  fi
}

# ---------- 0) preconditions ----------
# Root is required only for the real install/restart path; --check and the
# SKIP_INSTALL test hook are read-only plumbing (download/verify/log) and must
# stay testable as non-root (CI + sandbox). install.sh enforces root itself.
NEED_ROOT=1
[ "$CHECK_ONLY" = "1" ] && NEED_ROOT=0
[ "$SKIP_INSTALL" = "1" ] && NEED_ROOT=0
if [ "$NEED_ROOT" = "1" ] && [ "$(id -u)" -ne 0 ]; then
  die "run as root (systemd oneshot does this)"
fi
[ -f "$ETC/config.json" ] || { say "no installation found ($ETC/config.json) — nothing to do"; exit 0; }
INSTALLED="$(python3 -c "import json;print(json.load(open('$ETC/config.json')).get('version','0.0.0'))")"
PORT="$(python3 -c "import json;print(json.load(open('$ETC/config.json')).get('port',''))")"

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
say "upgrading v$INSTALLED -> v$MAN_V ..."
if bash "$TMP/src/install.sh" "$TMP/src" >"$ETC/last-update-install.log" 2>&1; then
  say "install.sh finished (log: $ETC/last-update-install.log)"
else
  log_row "install_failed" "install.sh rc=$? — see $ETC/last-update-install.log"
  warn "install.sh FAILED — rolling back"
  rollback
  exit 1
fi

# ---------- 7) strict verify: healthz + exact manifest version; fail = rollback ----------
GOT=""
for _ in $(seq 1 25); do
  GOT="$(health_version "$PORT" || true)"
  [ "$GOT" = "$MAN_V" ] && break
  sleep 1
done
if [ "$GOT" = "$MAN_V" ]; then
  ok "bridge healthy at v$GOT — self-update complete"
  log_row "success" "v$INSTALLED -> v$MAN_V"
  exit 0
fi
log_row "rolled_back" "health/version check failed (got '${GOT:-none}', want v$MAN_V)"
warn "post-install check FAILED (got '${GOT:-none}', want v$MAN_V) — rolling back"
rollback
exit 1
