#!/usr/bin/env bash
# =============================================================
#  Access Agent — release packer (invoked by CI, runnable locally)
#    Usage: bash scripts/pack-release.sh OUT_DIR
#
#  Packs the install bundle with EXACTLY the same member layout as Parastoo
#  Mobile's scripts/pack-agent-bundle.sh (access_agent/ install.sh
#  uninstall.sh bootstrap.sh deploy/ docs/) so the app-side extract+install
#  keeps working, and emits a manifest for the app's two-channel integrity
#  check: the bundle travels via the GitHub Release asset, the sha256 also
#  lands in RELEASE_MANIFEST.json on main (independent channel).
# =============================================================
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:?usage: pack-release.sh OUT_DIR}"
mkdir -p "$OUT"

for f in access_agent install.sh uninstall.sh bootstrap.sh deploy docs; do
  [ -e "$SRC/$f" ] || { echo "missing: $SRC/$f" >&2; exit 1; }
done

VERSION="$(python3 - "$SRC" <<'PY'
import re, sys
src = open(sys.argv[1] + "/access_agent/__init__.py", encoding="utf-8").read()
m = re.search(r'VERSION\s*=\s*"([^"]+)"', src)
print(m.group(1) if m else "0.0.0")
PY
)"

F="access-agent-v${VERSION}.tar.gz"
tar -czf "$OUT/$F" -C "$SRC" \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='.git' \
  access_agent install.sh uninstall.sh bootstrap.sh deploy docs

( cd "$OUT" && sha256sum "$F" | awk '{print $1}' > "$F.sha256" )

MANIFEST="$OUT/manifest.json"
python3 - "$OUT" "$F" "$VERSION" <<'PY'
import json, sys, time
out, fname, ver = sys.argv[1], sys.argv[2], sys.argv[3]
sha = open(f"{out}/{fname}.sha256", encoding="utf-8").read().strip()
manifest = {
    "version": ver,
    "filename": fname,
    "sha256": sha,
    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
with open(f"{out}/manifest.json", "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2)
    fh.write("\n")
print(json.dumps(manifest, indent=2))
PY

echo "packed: $OUT/$F ($(stat -c%s "$OUT/$F") bytes)"
