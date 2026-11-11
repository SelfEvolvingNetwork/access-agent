#!/usr/bin/env bash
# =============================================================
#  access-agent — owner-side helper CLI (installed to /usr/local/bin)
#  Root-only. Runs locally on the server; talks to the same files the
#  service uses. Output is English on purpose (SSH/RTL lesson).
#
#  Commands:
#    status                  service state + URL + healthz
#    url                     print ACCESS_URL only
#    show-agent-token        print the agent token (to hand to the AI agent)
#    rotate-agent-token      new agent token, printed once; old one dies
#    revoke-agent-token      disable the agent realm until next rotation
#    show-admin-token        print the admin token (owner-only)
#    rotate-admin-token      new admin token, printed once; old one dies
#    set-github-token <tok>  store/replace the owner's GitHub PAT (best-effort validation)
#    set-github-app <id> <pem>  configure a GitHub App (v0.2): REAL <=1h installation tokens
#    test-github-app         mint a fresh installation token; print metadata only (never the token)
#    show-github-app         app config summary (no secrets)
#    clear-github-app        remove app config; broker falls back to PAT mode
#    handoff                 ready-to-paste handoff block (legacy, <=0.6.x agents)
#    invite [ttl_min]        short invite block: URL + cert hash + one-time
#                            onboarding code (v0.7) — no permanent token in chat
#    audit [N]               tail of the audit log (default 30)
# =============================================================
set -euo pipefail

ETC="${ACCESS_AGENT_ETC:-/etc/access-agent}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
die() { echo -e "${RED} error:${NC} $*" >&2; exit 1; }
ok()  { echo -e "${GREEN} [ok]${NC} $*"; }
warn() { echo -e "${YELLOW} [warn]${NC} $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root:  sudo access-agent <command>"
[ -d "$ETC" ] || die "no $ETC — install first: bootstrap.sh"

CMD="${1:-help}"

cfg_port() { python3 -c "import json;print(json.load(open('$ETC/config.json'))['port'])" 2>/dev/null || echo ""; }
cfg_ip()   { python3 -c "import json;print(json.load(open('$ETC/config.json')).get('ip',''))" 2>/dev/null || echo ""; }
url()      { echo "https://$(cfg_ip):$(cfg_port)"; }

set_agent_hash() { # $1 = sha256 hex or ""
  python3 - "$ETC" "$1" <<'PY'
import json, os, sys
etc, val = sys.argv[1], sys.argv[2]
p = os.path.join(etc, "tokens.json")
d = json.load(open(p, encoding="utf-8"))
d["agent_sha"] = val
json.dump(d, open(p, "w", encoding="utf-8"), indent=2)
os.chmod(p, 0o600)
PY
}

set_admin_hash() { # $1 = sha256 hex (v0.1.1)
  python3 - "$ETC" "$1" <<'PY'
import json, os, sys
etc, val = sys.argv[1], sys.argv[2]
p = os.path.join(etc, "tokens.json")
d = json.load(open(p, encoding="utf-8"))
d["admin_sha"] = val
json.dump(d, open(p, "w", encoding="utf-8"), indent=2)
os.chmod(p, 0o600)
PY
}

OPT_DIR="${ACCESS_AGENT_OPT:-/opt/access-agent}"
py_with_agent() { ACCESS_AGENT_HOME="$ETC" python3 - "$OPT_DIR" "$@" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from access_agent import githubapp
fn = getattr(githubapp, sys.argv[2])
import json
args = sys.argv[3:]
try:
    out = fn(*args)
except Exception as e:
    print(f"error: {e}", file=sys.stderr); raise SystemExit(1)
print(out if isinstance(out, str) else json.dumps(out, ensure_ascii=False, indent=2))
PY
}

case "$CMD" in
  status)
    echo "service : $(systemctl is-active access-agent 2>/dev/null || echo unknown) ($(systemctl is-enabled access-agent 2>/dev/null || echo disabled))"
    echo "url     : $(url)"
    echo "version : $(python3 -c "import json;print(json.load(open('$ETC/config.json')).get('version','?'))" 2>/dev/null || echo '?')"
    H="$(curl -sk --max-time 4 "$(url)/healthz" 2>/dev/null || true)"
    echo "healthz : ${H:-unreachable}"
    echo "agent   : $(python3 -c "import json;print('enabled' if json.load(open('$ETC/tokens.json')).get('agent_sha') else 'disabled')" 2>/dev/null || echo '?')"
    echo "github  : $([ -s "$ETC/github.env" ] && echo stored || echo not-stored)"
    echo "gh-app  : $([ -s "$ETC/github-app.json" ] && echo "configured (app_id $(python3 -c "import json;print(json.load(open('$ETC/github-app.json')).get('app_id','?'))" 2>/dev/null || echo '?'))" || echo not-configured)"
    ;;
  url) url ;;
  show-agent-token)
    [ -f "$ETC/secrets/agent-token" ] || die "$ETC/secrets/agent-token missing"
    cat "$ETC/secrets/agent-token"
    ;;
  rotate-agent-token)
    NEW="aa_$(openssl rand -hex 24)"
    set_agent_hash "$(python3 -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$NEW")"
    mkdir -p "$ETC/secrets"
    printf '%s\n' "$NEW" > "$ETC/secrets/agent-token"
    chmod 600 "$ETC/secrets/agent-token"
    ok "agent token rotated — give the NEW token to your AI agent:"
    echo "$NEW"
    ;;
  revoke-agent-token)
    set_agent_hash ""
    ok "agent realm disabled until the next rotation."
    ;;
  show-admin-token)
    [ -f "$ETC/secrets/admin-token" ] || die "$ETC/secrets/admin-token missing"
    cat "$ETC/secrets/admin-token"
    ;;
  rotate-admin-token)
    NEW="adm_$(openssl rand -hex 24)"
    set_admin_hash "$(python3 -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$NEW")"
    mkdir -p "$ETC/secrets"
    printf '%s\n' "$NEW" > "$ETC/secrets/admin-token"
    chmod 600 "$ETC/secrets/admin-token"
    ok "admin token rotated — view it anytime with:  sudo access-agent show-admin-token"
    echo "$NEW"
    ;;
  set-github-token)
    TOK="${2:-}"
    [ -n "$TOK" ] || die "usage: access-agent set-github-token <token>"
    printf '# managed by access-agent — root-only, never commit\nGITHUB_TOKEN=%s\n' "$TOK" > "$ETC/github.env"
    chmod 600 "$ETC/github.env"
    V="$(curl -s --max-time 8 -H "Authorization: Bearer $TOK" https://api.github.com/user 2>/dev/null \
        | python3 -c "import sys,json
try:
    d=json.load(sys.stdin); print('validated as @'+d.get('login','?'))
except Exception:
    print('could NOT validate (saved anyway — check network/scope)')" || echo "could NOT validate (saved anyway)")"
    ok "GitHub token stored ($V)."
    ;;
  set-github-app)
    APP_ID="${2:-}"; PEM="${3:-}"
    [ -n "$APP_ID" ] && [ -n "$PEM" ] || die "usage: access-agent set-github-app <app_id> <pem_path>  (PEM must arrive via SSH/scp, never through the AI channel)"
    py_with_agent save_config "$APP_ID" "$PEM" && ok "GitHub App configured."
    echo "  -> minting a test token (best-effort; needs api.github.com reachability)..."
    py_with_agent test_github_app >/dev/null 2>&1 \
      && ok "validated: a real installation token was minted." \
      || warn "saved but NOT validated now (network?) — run later:  sudo access-agent test-github-app"
    ;;
  test-github-app)
    py_with_agent test_github_app || die "mint failed — see the error above"
    ;;
  show-github-app)
    py_with_agent status
    ;;
  clear-github-app)
    py_with_agent clear_config && ok "GitHub App config removed — broker is back in PAT mode."
    ;;
  handoff)
    OPT_DIR="${ACCESS_AGENT_OPT:-/opt/access-agent}"
    if [ ! -f "$OPT_DIR/access_agent/handoff.py" ]; then
      die "handoff module missing — upgrade first: re-run bootstrap.sh"
    fi
    ACCESS_AGENT_HOME="$ETC" python3 - "$OPT_DIR" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from access_agent.handoff import build_block
print(build_block())
PY
    ;;
  invite)
    # v0.7 — دعوت‌نامهٔ کوتاه: توکن بلندمدت دیگر از چت عبور نمی‌کند.
    # کد یک‌بارمصرف (TTL پیش‌فرض ۶۰ دقیقه) تولید و در خروجی جای‌گذاری می‌شود؛
    # فقط هشش روی دیسک می‌ماند. برای مکالمهٔ تازه، دوباره همین فرمان را بزنید.
    TTL="${2:-60}"
    OPT_DIR="${ACCESS_AGENT_OPT:-/opt/access-agent}"
    if [ ! -f "$OPT_DIR/access_agent/handoff.py" ]; then
      die "handoff module missing — upgrade first: re-run bootstrap.sh"
    fi
    ACCESS_AGENT_HOME="$ETC" python3 - "$OPT_DIR" "$TTL" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from access_agent.handoff import build_invite_block, invite_missing_inputs
from access_agent.security import mint_onboard_code
miss = invite_missing_inputs()
if miss:
    raise SystemExit(f"invite data missing: {', '.join(miss)}")
code, rec = mint_onboard_code(ttl_s=int(sys.argv[2]) * 60)
print(build_invite_block(code, ttl_min=int(sys.argv[2])))
PY
    ;;
  audit)
    N="${2:-30}"
    tail -n "$N" "$ETC/audit/audit.jsonl" 2>/dev/null || echo "(empty audit log)"
    ;;
  help|*)
    sed -n '3,20p' "$0" | sed 's/^# \{0,2\}//'
    ;;
esac
