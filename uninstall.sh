#!/usr/bin/env bash
# =============================================================
#  Access Agent — uninstaller
#    curl -fsSL https://raw.githubusercontent.com/SelfEvolvingNetwork/access-agent/main/uninstall.sh | sudo bash
#  By default KEEPS /etc/access-agent (secrets + audit) so a reinstall
#  keeps the same tokens. Use --purge to remove everything.
# =============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
say()  { echo -e "${GREEN}==>${NC} $*"; }
ok()   { echo -e "${GREEN} [ok]${NC} $*"; }
warn() { echo -e "${YELLOW} [warn]${NC} $*"; }
die()  { echo -e "${RED} error:${NC} $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root:  sudo bash uninstall.sh"

SERVICE=access-agent
ETC="${ACCESS_AGENT_ETC:-/etc/access-agent}"
OPT="${ACCESS_AGENT_OPT:-/opt/access-agent}"
UNIT_DIR="${ACCESS_AGENT_UNIT_DIR:-/etc/systemd/system}"
CLI_BIN="${ACCESS_AGENT_CLI_BIN:-/usr/local/bin/access-agent}"

say "Stopping and disabling $SERVICE ..."
systemctl stop "$SERVICE" 2>/dev/null || true
systemctl disable "$SERVICE" 2>/dev/null || true
rm -f "${UNIT_DIR}/${SERVICE}.service"
systemctl daemon-reload 2>/dev/null || true

say "Removing code and CLI ..."
rm -rf "$OPT"
rm -f "$CLI_BIN"

if [ "${1:-}" = "--purge" ]; then
  say "Purging $ETC (secrets, TLS, audit) ..."
  rm -rf "$ETC"
  ok "Fully purged."
else
  warn "$ETC kept (secrets + audit). Remove it too:  sudo bash uninstall.sh --purge"
fi
say "Access Agent removed. Parastoo was not touched."
