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
#    set-github-token <tok>  store/replace the owner's GitHub PAT (best-effort validation)
#    audit [N]               tail of the audit log (default 30)
# =============================================================
set -euo pipefail

ETC="${ACCESS_AGENT_ETC:-/etc/access-agent}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
die() { echo -e "${RED} error:${NC} $*" >&2; exit 1; }
ok()  { echo -e "${GREEN} [ok]${NC} $*"; }

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

case "$CMD" in
  status)
    echo "service : $(systemctl is-active access-agent 2>/dev/null || echo unknown) ($(systemctl is-enabled access-agent 2>/dev/null || echo disabled))"
    echo "url     : $(url)"
    echo "version : $(python3 -c "import json;print(json.load(open('$ETC/config.json')).get('version','?'))" 2>/dev/null || echo '?')"
    H="$(curl -sk --max-time 4 "$(url)/healthz" 2>/dev/null || true)"
    echo "healthz : ${H:-unreachable}"
    echo "agent   : $(python3 -c "import json;print('enabled' if json.load(open('$ETC/tokens.json')).get('agent_sha') else 'disabled')" 2>/dev/null || echo '?')"
    echo "github  : $([ -s "$ETC/github.env" ] && echo stored || echo not-stored)"
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
  audit)
    N="${2:-30}"
    tail -n "$N" "$ETC/audit/audit.jsonl" 2>/dev/null || echo "(empty audit log)"
    ;;
  help|*)
    sed -n '3,20p' "$0" | sed 's/^# \{0,2\}//'
    ;;
esac
