#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی خودآپدیت سرور-سمت پل (v0.6.3) — کاملاً آفلاین با فایل‌های فیک.

پوشش: گارد downgrade، حالت noop، حالت --check (بدون ردیف تاریخچه)،
رد قطعی sha256 نامطابق (بدون دست‌زدن به نصب)، لوله‌کشی موفق با
ACCESS_AGENT_SKIP_INSTALL، و سلامت قالب JSONL تاریخچه.
اجرا:  python tests/smoke_selfupdate.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "self-update.sh"
GREEN, RED, YELLOW, NC = "\033", "\033", "\033", "\033"
n_pass = n_fail = 0
failures: list[str] = []


def ch(name: str, cond: bool, extra: str = "") -> None:
    global n_pass, n_fail
    if cond:
        n_pass += 1
        print(f"{GREEN}[✓]{NC} {name}")
    else:
        n_fail += 1
        failures.append(name)
        print(f"{RED}[✗]{NC} {name} {YELLOW}{extra}{NC}")


def make_bundle(tmp: Path, version: str) -> Path:
    """یک باندل فیک با چیدمان واقعی (access_agent/ + install.sh) و sha256 آن."""
    src = tmp / "fakesrc"
    (src / "access_agent").mkdir(parents=True, exist_ok=True)
    (src / "access_agent" / "__init__.py").write_text(
        f'VERSION = "{version}"\n', encoding="utf-8")
    (src / "access_agent" / "server.py").write_text("# fake\n", encoding="utf-8")
    (src / "install.sh").write_text("#!/usr/bin/env bash\necho fake-install\n", encoding="utf-8")
    bundle = tmp / f"access-agent-v{version}.tar.gz"
    with tarfile.open(bundle, "w:gz") as tf:
        tf.add(src, arcname=".")
    return bundle


def make_manifest(tmp: Path, version: str, bundle: Path, sha: str | None = None) -> Path:
    import hashlib
    real_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
    m = {"version": version, "filename": bundle.name,
         "sha256": sha or real_sha, "created_at": "2026-11-11T00:00:00Z"}
    p = tmp / "RELEASE_MANIFEST.json"
    p.write_text(json.dumps(m, indent=2), encoding="utf-8")
    return p


def run_selfupdate(env: dict, etc: Path, opt: Path, *args: str) -> tuple[int, str]:
    e = dict(**{k: v for k, v in __import__("os").environ.items()},
             ACCESS_AGENT_ETC=str(etc), ACCESS_AGENT_OPT=str(opt),
             ACCESS_AGENT_SKIP_INSTALL="1")
    e.update(env)
    r = subprocess.run(["bash", str(SCRIPT), *args], env=e,
                       capture_output=True, text=True, timeout=120)
    return r.returncode, (r.stdout + r.stderr)


def last_row(etc: Path) -> dict | None:
    p = etc / "updates.jsonl"
    if not p.exists():
        return None
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    return json.loads(lines[-1]) if lines else None


def main() -> int:
    ch("self-update.sh exists", SCRIPT.exists())
    r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    ch("bash -n self-update.sh", r.returncode == 0, r.stderr[:200])

    base = Path(tempfile.mkdtemp(prefix="aa-smoke-"))

    # --- scenario 1: already up to date → noop, no download needed ---
    etc = base / "etc1"; opt = base / "opt1"
    etc.mkdir(parents=True); opt.mkdir(parents=True)
    (etc / "config.json").write_text('{"version": "1.2.3", "port": 59999}', encoding="utf-8")
    bundle = make_bundle(base, "1.2.3")
    man = make_manifest(base, "1.2.3", bundle)
    rc, out = run_selfupdate({"ACCESS_AGENT_MANIFEST_FILE": str(man),
                              "ACCESS_AGENT_BUNDLE_FILE": str(bundle)}, etc, opt)
    row = last_row(etc)
    ch("noop: exit 0", rc == 0, out[:200])
    ch("noop: row result=noop", bool(row) and row.get("result") == "noop", str(row))
    ch("noop: jsonl shape", bool(row) and row.get("action") == "self_update"
       and isinstance(row.get("ts"), str), str(row))

    # --- scenario 2: downgrade refused ---
    etc = base / "etc2"; opt = base / "opt2"
    etc.mkdir(parents=True); opt.mkdir(parents=True)
    (etc / "config.json").write_text('{"version": "2.0.0", "port": 59999}', encoding="utf-8")
    bundle = make_bundle(base, "1.9.0")
    man = make_manifest(base, "1.9.0", bundle)
    rc, out = run_selfupdate({"ACCESS_AGENT_MANIFEST_FILE": str(man),
                              "ACCESS_AGENT_BUNDLE_FILE": str(bundle)}, etc, opt)
    row = last_row(etc)
    ch("downgrade: exit 0 (refusal, not crash)", rc == 0, out[:200])
    ch("downgrade: row result=downgrade_refused", bool(row) and row.get("result") == "downgrade_refused", str(row))

    # --- scenario 3: --check prints availability, appends NOTHING ---
    etc = base / "etc3"; opt = base / "opt3"
    etc.mkdir(parents=True); opt.mkdir(parents=True)
    (etc / "config.json").write_text('{"version": "1.0.0", "port": 59999}', encoding="utf-8")
    bundle = make_bundle(base, "3.0.0")
    man = make_manifest(base, "3.0.0", bundle)
    rc, out = run_selfupdate({"ACCESS_AGENT_MANIFEST_FILE": str(man),
                              "ACCESS_AGENT_BUNDLE_FILE": str(bundle)}, etc, opt, "--check")
    ch("check: exit 0", rc == 0, out[:200])
    ch("check: says update available", "update available" in out, out[:200])
    ch("check: no history row", last_row(etc) is None)

    # --- scenario 4: sha mismatch → hard reject, install untouched ---
    etc = base / "etc4"; opt = base / "opt4"
    etc.mkdir(parents=True); opt.mkdir(parents=True)
    (etc / "config.json").write_text('{"version": "1.0.0", "port": 59999}', encoding="utf-8")
    (opt / "canary.txt").write_text("untouched", encoding="utf-8")
    bundle = make_bundle(base, "3.0.0")
    man = make_manifest(base, "3.0.0", bundle, sha="0" * 64)
    rc, out = run_selfupdate({"ACCESS_AGENT_MANIFEST_FILE": str(man),
                              "ACCESS_AGENT_BUNDLE_FILE": str(bundle)}, etc, opt)
    row = last_row(etc)
    ch("sha-mismatch: non-zero exit", rc != 0, out[:200])
    ch("sha-mismatch: row result=sha_mismatch", bool(row) and row.get("result") == "sha_mismatch", str(row))
    ch("sha-mismatch: config version untouched",
       json.loads((etc / "config.json").read_text())["version"] == "1.0.0")

    # --- scenario 5: valid newer bundle + SKIP_INSTALL → plumbing to the hook ---
    etc = base / "etc5"; opt = base / "opt5"
    etc.mkdir(parents=True); opt.mkdir(parents=True)
    (etc / "config.json").write_text('{"version": "1.0.0", "port": 59999}', encoding="utf-8")
    bundle = make_bundle(base, "3.0.0")
    man = make_manifest(base, "3.0.0", bundle)
    rc, out = run_selfupdate({"ACCESS_AGENT_MANIFEST_FILE": str(man),
                              "ACCESS_AGENT_BUNDLE_FILE": str(bundle)}, etc, opt)
    row = last_row(etc)
    ch("skip-install: exit 0", rc == 0, out[:200])
    ch("skip-install: row result=skip_install", bool(row) and row.get("result") == "skip_install", str(row))
    ch("skip-install: row to=3.0.0", bool(row) and row.get("to") == "3.0.0", str(row))

    # --- scenario 6: malformed manifest → bad_manifest ---
    etc = base / "etc6"; opt = base / "opt6"
    etc.mkdir(parents=True); opt.mkdir(parents=True)
    (etc / "config.json").write_text('{"version": "1.0.0", "port": 59999}', encoding="utf-8")
    badman = base / "bad_manifest.json"
    badman.write_text('{"version": ""}', encoding="utf-8")
    rc, out = run_selfupdate({"ACCESS_AGENT_MANIFEST_FILE": str(badman)}, etc, opt)
    row = last_row(etc)
    ch("bad-manifest: non-zero exit", rc != 0, out[:200])
    ch("bad-manifest: row result=bad_manifest", bool(row) and row.get("result") == "bad_manifest", str(row))

    shutil.rmtree(base, ignore_errors=True)

    print(f"\n  نتیجه: {n_pass} سبز / {n_fail} قرمز")
    if failures:
        print("  شکست‌ها:", "; ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
