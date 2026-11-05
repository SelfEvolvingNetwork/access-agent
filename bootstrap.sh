#!/usr/bin/env bash
# =============================================================
#  Access Agent — one-command bootstrap from GitHub (SSH-safe)
#
#    curl -fsSL https://raw.githubusercontent.com/SelfEvolvingNetwork/access-agent/main/bootstrap.sh | sudo bash
#
#  Independent of Parastoo and of Docker: pure-Python + systemd.
#  Survives Parastoo crashes; used to test, repair and reinstall Parastoo.
#
#  Fetch routes: repo tarball (codeload) → git clone → local folder.
#
#  Optional variables (set before the command):
#    ACCESS_AGENT_REF=main              branch or tag (default: main)
#    ACCESS_AGENT_GH_PROXY=URL          GitHub proxy prefix for Iran,
#                                       e.g. https://gh-proxy.com/
#    ACCESS_AGENT_GITHUB_TOKEN=ghp_...  store the owner's GitHub PAT at install
#    ACCESS_AGENT_PORT=25123            fixed port (default: random free port)
#
#  Installer output is English on purpose — Persian/RTL text breaks
#  rendering over SSH (same lesson as Parastoo bootstrap).
# =============================================================
set -euo pipefail

ORG="${ACCESS_AGENT_GH_ORG:-SelfEvolvingNetwork}"
REPO="${ACCESS_AGENT_GH_REPO:-access-agent}"
REF="${ACCESS_AGENT_REF:-main}"
PROXY="${ACCESS_AGENT_GH_PROXY:-}"
RAW_URL="${PROXY}https://raw.githubusercontent.com/${ORG}/${REPO}/${REF}/bootstrap.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
say()  { echo -e "${BLUE}==>${NC} $*"; }
ok()   { echo -e "${GREEN} [ok]${NC} $*"; }
warn() { echo -e "${YELLOW} [warn]${NC} $*"; }
die()  { echo -e "${RED} error:${NC} $*" >&2; exit 1; }

# ---------- 1) root (compatible with curl | bash) ----------
is_file_self() {
  local s="${BASH_SOURCE[0]:-}"
  [ -n "$s" ] && [ -f "$s" ] && [ "$s" != "bash" ] && [ "$s" != "sh" ] && [ "$s" != "/dev/stdin" ]
}
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    if is_file_self; then
      exec sudo -E bash "$(readlink -f "${BASH_SOURCE[0]}")" "$@"
    fi
    say "Re-fetching the script with root privileges..."
    exec sudo -E bash -c "curl -fsSL '$RAW_URL' | bash"
  fi
  die "Run as root:  curl -fsSL $RAW_URL | sudo bash"
fi

# ---------- 2) local package already here? ----------
if [ -f ./install.sh ] && [ -f ./access_agent/server.py ]; then
  say "Access-agent package found in current directory; installing directly..."
  exec bash ./install.sh "$(pwd)"
fi

# ---------- 3) dependencies ----------
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  say "Installing curl..."
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates </dev/null >/dev/null
fi
for c in python3 openssl tar systemctl; do
  command -v "$c" >/dev/null 2>&1 || die "missing dependency: $c (apt install $c)"
done

fetch() { # fetch <url> <out>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 2 --max-time 300 -o "$2" "$1"
  else
    wget -q -O "$2" "$1"
  fi
}

WORK="$(mktemp -d /tmp/access-agent-bootstrap.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# ---------- 4) fetch package from GitHub — two routes ----------
say "Fetching access-agent from GitHub: ${ORG}/${REPO} (ref: ${REF})"

got_tar() { fetch "${PROXY}https://codeload.github.com/${ORG}/${REPO}/tar.gz/${REF}" "$WORK/pkg.tar.gz" && [ -s "$WORK/pkg.tar.gz" ]; }
got_clone() {
  command -v git >/dev/null 2>&1 || {
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git </dev/null >/dev/null 2>&1 || return 1
  }
  git clone --depth 1 --branch "$REF" "${PROXY}https://github.com/${ORG}/${REPO}.git" "$WORK/repo" 2>/dev/null
}

MODE=""
if got_tar; then
  MODE="tar"; ok "Repository tarball downloaded (ref: ${REF})."
elif got_clone; then
  MODE="git"; ok "Repository cloned (ref: ${REF})."
else
  die "Could not fetch from GitHub.
Alternative routes:
  1) proxy (Iran):  curl -fsSL ${PROXY}https://gh-proxy.com/https://raw.githubusercontent.com/${ORG}/${REPO}/${REF}/bootstrap.sh | sudo bash
  2) manual:  git clone https://github.com/${ORG}/${REPO}.git && cd ${REPO} && sudo bash install.sh \$(pwd)"
fi

# ---------- 5) extract ----------
if [ "$MODE" = "git" ]; then
  SRC_DIR="$WORK/repo"
else
  say "Extracting package..."
  EXTRACT_DIR="$WORK/src"
  mkdir -p "$EXTRACT_DIR"
  tar -xzf "$WORK/pkg.tar.gz" -C "$EXTRACT_DIR"
  SRC_DIR="$EXTRACT_DIR"
  [ -f "$SRC_DIR/install.sh" ] || SRC_DIR="$(find "$EXTRACT_DIR" -maxdepth 2 -name install.sh -printf '%h\n' 2>/dev/null | head -n1 || true)"
fi
[ -n "${SRC_DIR:-}" ] && [ -f "$SRC_DIR/install.sh" ] && [ -f "$SRC_DIR/access_agent/server.py" ] \
  || die "Invalid package (install.sh / access_agent not found)."
ok "Package verified."

# ---------- 6) resolve exact commit of REF (best effort, non-fatal) ----------
COMMIT=""
if [ "$MODE" = "git" ]; then
  COMMIT="$(git -C "$WORK/repo" rev-parse HEAD 2>/dev/null || true)"
elif command -v git >/dev/null 2>&1; then
  COMMIT="$(timeout 25 git ls-remote "${PROXY}https://github.com/${ORG}/${REPO}.git" \
              "refs/heads/${REF}" "refs/tags/${REF}" 2>/dev/null | awk 'NR==1{print $1}' || true)"
fi
if [ -n "$COMMIT" ]; then
  export ACCESS_AGENT_DEPLOYED_COMMIT="$COMMIT"
  ok "Deployed commit: ${COMMIT:0:12}"
fi

exec bash "$SRC_DIR/install.sh" "$SRC_DIR"
