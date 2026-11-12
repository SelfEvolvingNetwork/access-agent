#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست دودی خودآپدیت سرور-سمت پل (v0.8.3) — کاملاً آفلاین با فایل‌های فیک.

بازگردانی از v0.6.3 (bridge-r24) پس از یافتهٔ ممیزی ۲۰۲۶-۱۱-۱۲ (کد خودآپدیت
از main خارج شده بود) + پوشش تازه: گارد پیوستگی هویت.

پوشش:
  - گارد downgrade، حالت noop، حالت --check (بدون ردیف تاریخچه)،
    رد قطعی sha256 نامطابق (بدون دست‌زدن به نصب)، مانیفست معیوب،
    هوک SKIP_INSTALL.
  - سناریوهای نصب کامل با install.sh ساختگی + healthz کنسروی
    (ACCESS_AGENT_HEALTHZ_FILE) که موتور مقایسهٔ واقعی هویت را می‌رانند:
      * موفقیت + هویت سالم (گواهی/آدرس بدون تغییر) → ردیف success؛
      * «باگ میدان ۲۰۲۶-۱۱-۱۰»: نصب‌کننده آی‌پی لوکال (172.22.0.1) را
        به‌جای آی‌پی اصلی سرور در config.json می‌نویسد → گارد آدرس
        → rollback خودکار + بازگردانی config.json از بکاپ یک-نسلی؛
      * تغییر گواهی TLS (قطع کلاینت‌های پین‌شده) → rollback؛
      * نسخهٔ غلط پس از نصب → rollback.
اجرا:  python tests/smoke_selfupdate.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "self-update.sh"
INSTALL = REPO / "install.sh"
GREEN, RED, YELLOW, NC = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
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


STUB_INSTALL = r"""#!/usr/bin/env bash
# test stub — mimics the install.sh v0.8.3 contract bits the engine depends on
set -euo pipefail
SRC="$1"
ETC="${ACCESS_AGENT_ETC:?}"
OPT="${ACCESS_AGENT_OPT:?}"
MODE="${ACCESS_AGENT_STUB_MODE:-ok}"
NEWVER="${ACCESS_AGENT_STUB_NEWVER:-3.0.0}"
mkdir -p "$OPT"
# one-generation backup exactly like install.sh v0.8.3
rm -rf "$OPT/.prev-access_agent" "$OPT/.prev-tls"
cp -a "$OPT/access_agent" "$OPT/.prev-access_agent" 2>/dev/null || true
cp -f "$ETC/config.json" "$OPT/.prev-config.json" 2>/dev/null || true
cp -a "$ETC/tls" "$OPT/.prev-tls" 2>/dev/null || true
chmod 700 "$OPT/.prev-access_agent" "$OPT/.prev-tls" 2>/dev/null || true
# code replacement (new inode — same as install.sh)
rm -rf "$OPT/access_agent"
cp -r "$SRC/access_agent" "$OPT/access_agent"
# config rewrite — upgrade path reads the RECORDED address back (IP continuity);
# MODE=bad_ip simulates the 2026-11-10 field bug: a local/bridge IP lands instead
IP="$(python3 -c "import json;print(json.load(open('$ETC/config.json')).get('ip',''))")"
PORT="$(python3 -c "import json;print(json.load(open('$ETC/config.json')).get('port',''))")"
case "$MODE" in
  bad_ip) IP="172.22.0.1" ;;
  bad_port) PORT="59998" ;;
esac
python3 - "$ETC" "$PORT" "$IP" "$NEWVER" <<'PY'
import json, sys
etc, port, ip, ver = sys.argv[1:5]
cfg = json.load(open(f"{etc}/config.json"))
cfg.update({"port": int(port), "ip": ip, "version": ver})
json.dump(cfg, open(f"{etc}/config.json", "w"), indent=2)
PY
exit 0
"""


def make_bundle(tmp: Path, version: str, stub: str = "") -> Path:
    """یک باندل فیک با چیدمان واقعی (access_agent/ + install.sh) و sha256 آن."""
    src = tmp / "fakesrc"
    (src / "access_agent").mkdir(parents=True, exist_ok=True)
    (src / "access_agent" / "__init__.py").write_text(
        f'VERSION = "{version}"\n', encoding="utf-8")
    (src / "access_agent" / "server.py").write_text("# fake\n", encoding="utf-8")
    if stub:
        (src / "install.sh").write_text(stub, encoding="utf-8")
    else:
        (src / "install.sh").write_text(
            "#!/usr/bin/env bash\necho fake-install\n", encoding="utf-8")
    bundle = tmp / f"access-agent-v{version}.tar.gz"
    with tarfile.open(bundle, "w:gz") as tf:
        tf.add(src, arcname=".")
    return bundle


def make_manifest(tmp: Path, version: str, bundle: Path, sha: str | None = None) -> Path:
    real_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
    m = {"version": version, "filename": bundle.name,
         "sha256": sha or real_sha, "created_at": "2026-11-12T00:00:00Z"}
    p = tmp / "RELEASE_MANIFEST.json"
    p.write_text(json.dumps(m, indent=2), encoding="utf-8")
    return p


def cert_fp(pem: Path) -> str:
    out = subprocess.run(
        ["openssl", "x509", "-in", str(pem), "-noout", "-fingerprint", "-sha256"],
        capture_output=True, text=True, timeout=30).stdout
    return out.split("=", 1)[1].strip().replace(":", "")


def run_selfupdate(env: dict, etc: Path, opt: Path, *args: str,
                   skip_install: bool = True) -> tuple[int, str]:
    e = {k: v for k, v in os.environ.items()}
    e.update({"ACCESS_AGENT_ETC": str(etc), "ACCESS_AGENT_OPT": str(opt),
              "ACCESS_AGENT_SKIP_INSTALL": "1" if skip_install else "0",
              "ACCESS_AGENT_ALLOW_NONROOT": "1"})
    e.update(env)
    r = subprocess.run(["bash", str(SCRIPT), *args], env=e,
                       capture_output=True, text=True, timeout=180)
    return r.returncode, (r.stdout + r.stderr)


def last_row(etc: Path) -> dict | None:
    p = etc / "updates.jsonl"
    if not p.exists():
        return None
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    return json.loads(lines[-1]) if lines else None


def cfg(etc: Path) -> dict:
    return json.loads((etc / "config.json").read_text(encoding="utf-8"))


def make_site(base: Path, name: str, version: str, ip: str,
              port: int = 59999) -> tuple[Path, Path, str]:
    """ETC+OPT زندهٔ ساختگی: config.json + TLS واقعی + کد قبلی."""
    etc = base / f"etc-{name}"
    opt = base / f"opt-{name}"
    (etc / "tls").mkdir(parents=True, exist_ok=True)
    (opt / "access_agent").mkdir(parents=True, exist_ok=True)
    (opt / "access_agent" / "__init__.py").write_text(
        f'VERSION = "{version}"\n', encoding="utf-8")
    (etc / "config.json").write_text(json.dumps(
        {"port": port, "ip": ip, "version": version,
         "commit": "", "installed_at": "2026-11-12T00:00:00+0000"}), encoding="utf-8")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "2", "-subj", "/CN=test-bridge",
         "-keyout", str(etc / "tls" / "key.pem"),
         "-out", str(etc / "tls" / "cert.pem")],
        capture_output=True, timeout=60, check=True)
    return etc, opt, cert_fp(etc / "tls" / "cert.pem")


def main() -> int:
    ch("self-update.sh exists", SCRIPT.exists())
    r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    ch("bash -n self-update.sh", r.returncode == 0, r.stderr[:200])

    eng = SCRIPT.read_text(encoding="utf-8")
    # ---------- static: identity-continuity guard exists in the engine ----------
    ch("engine: snapshot گواهی قبل از آپدیت (PRE_CERT)", "PRE_CERT=" in eng)
    ch("engine: مقایسهٔ cert_sha256 بعد از نصب", "cert_sha256" in eng)
    ch("engine: مقایسهٔ ip/port ضبط‌شده بعد از نصب",
       "recorded address changed" in eng and "port changed" in eng)
    ch("engine: rollback شامل TLS است (.prev-tls)", ".prev-tls" in eng)
    ch("engine: ردیف تاریخچه identity را ثبت می‌کند",
       "identity: cert+addr unchanged" in eng)
    ch("engine: بازگردانی کد از بکاپ یک-نسلی", ".prev-access_agent" in eng)
    ch("engine: تعویق حین lifecycle پرستو (یک بازیگر تغییردهنده)",
       "lifecycle_busy" in eng)
    inst = INSTALL.read_text(encoding="utf-8")
    ch("install.sh: قفل تک‌نویسنده (/run/access-agent-install.lock)",
        "/run/access-agent-install.lock" in inst)
    ch("install.sh: بکاپ یک-نسلی config + TLS",
        ".prev-config.json" in inst and ".prev-tls" in inst)
    ch("install.sh: پیوستگی IP مسیر ارتقا (OLD_IP بدون تشخیص مجدد)",
        "OLD_IP=" in inst and "IP CONTINUITY" in inst)
    ch("install.sh: تعمیر فقط با IP عمومیِ سخت‌گیر (هرگز تنزل)",
        "is_private_ip \"$CAND\"" in inst)
    ch("install.sh: موتور با inode تازه نصب می‌شود (rm+cp)",
        'rm -f "$OPT/deploy/self-update.sh"' in inst)
    ch("install.sh: حفظ حالت تایمر (on می‌ماند، off می‌ماند)",
        "staying OFF — owner disarmed it" in inst)

    base = Path(tempfile.mkdtemp(prefix="aa-smoke-su-"))
    PUB_IP = "193.151.142.128"

    # --- scenario 1: already up to date → noop, no download needed ---
    etc, opt, _fp = make_site(base, "1", "1.2.3", PUB_IP)
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
    etc, opt, _fp = make_site(base, "2", "2.0.0", PUB_IP)
    bundle = make_bundle(base, "1.9.0")
    man = make_manifest(base, "1.9.0", bundle)
    rc, out = run_selfupdate({"ACCESS_AGENT_MANIFEST_FILE": str(man),
                              "ACCESS_AGENT_BUNDLE_FILE": str(bundle)}, etc, opt)
    row = last_row(etc)
    ch("downgrade: exit 0 (refusal, not crash)", rc == 0, out[:200])
    ch("downgrade: row result=downgrade_refused",
       bool(row) and row.get("result") == "downgrade_refused", str(row))

    # --- scenario 3: --check prints availability, appends NOTHING ---
    etc, opt, _fp = make_site(base, "3", "1.0.0", PUB_IP)
    bundle = make_bundle(base, "3.0.0")
    man = make_manifest(base, "3.0.0", bundle)
    rc, out = run_selfupdate({"ACCESS_AGENT_MANIFEST_FILE": str(man),
                              "ACCESS_AGENT_BUNDLE_FILE": str(bundle)}, etc, opt, "--check")
    ch("check: exit 0", rc == 0, out[:200])
    ch("check: says update available", "update available" in out, out[:200])
    ch("check: no history row", last_row(etc) is None)

    # --- scenario 4: sha mismatch → hard reject, install untouched ---
    etc, opt, _fp = make_site(base, "4", "1.0.0", PUB_IP)
    bundle = make_bundle(base, "3.0.0")
    man = make_manifest(base, "3.0.0", bundle, sha="0" * 64)
    rc, out = run_selfupdate({"ACCESS_AGENT_MANIFEST_FILE": str(man),
                              "ACCESS_AGENT_BUNDLE_FILE": str(bundle)}, etc, opt)
    row = last_row(etc)
    ch("sha-mismatch: non-zero exit", rc != 0, out[:200])
    ch("sha-mismatch: row result=sha_mismatch",
       bool(row) and row.get("result") == "sha_mismatch", str(row))
    ch("sha-mismatch: config version untouched", cfg(etc)["version"] == "1.0.0")

    # --- scenario 5: malformed manifest → bad_manifest ---
    etc, opt, _fp = make_site(base, "5", "1.0.0", PUB_IP)
    badman = base / "bad_manifest.json"
    badman.write_text('{"version": ""}', encoding="utf-8")
    rc, out = run_selfupdate({"ACCESS_AGENT_MANIFEST_FILE": str(badman)}, etc, opt)
    row = last_row(etc)
    ch("bad-manifest: non-zero exit", rc != 0, out[:200])
    ch("bad-manifest: row result=bad_manifest",
       bool(row) and row.get("result") == "bad_manifest", str(row))

    # --- scenario 6: valid newer bundle + SKIP_INSTALL → plumbing to the hook ---
    etc, opt, _fp = make_site(base, "6", "1.0.0", PUB_IP)
    bundle = make_bundle(base, "3.0.0")
    man = make_manifest(base, "3.0.0", bundle)
    rc, out = run_selfupdate({"ACCESS_AGENT_MANIFEST_FILE": str(man),
                              "ACCESS_AGENT_BUNDLE_FILE": str(bundle)}, etc, opt)
    row = last_row(etc)
    ch("skip-install: exit 0", rc == 0, out[:200])
    ch("skip-install: row result=skip_install",
       bool(row) and row.get("result") == "skip_install", str(row))
    ch("skip-install: row to=3.0.0", bool(row) and row.get("to") == "3.0.0", str(row))

    # ================= full-install scenarios (stub install.sh + canned healthz) ====

    # --- scenario 7: SUCCESS — version + identity all intact ---
    etc, opt, fp = make_site(base, "7", "1.0.0", PUB_IP)
    bundle = make_bundle(base, "3.0.0", stub=STUB_INSTALL)
    man = make_manifest(base, "3.0.0", bundle)
    healthz = base / "hz7.json"
    healthz.write_text(json.dumps(
        {"ok": True, "version": "3.0.0", "cert_sha256": fp}), encoding="utf-8")
    rc, out = run_selfupdate(
        {"ACCESS_AGENT_MANIFEST_FILE": str(man),
         "ACCESS_AGENT_BUNDLE_FILE": str(bundle),
         "ACCESS_AGENT_HEALTHZ_FILE": str(healthz),
         "ACCESS_AGENT_STUB_MODE": "ok", "ACCESS_AGENT_STUB_NEWVER": "3.0.0"},
        etc, opt, skip_install=False)
    row = last_row(etc)
    ch("success: exit 0", rc == 0, out[:300])
    ch("success: row result=success", bool(row) and row.get("result") == "success", str(row))
    ch("success: identity در detail ثبت شد",
       bool(row) and "identity" in str(row.get("detail", "")), str(row))
    ch("success: نسخهٔ جدید در config.json", cfg(etc)["version"] == "3.0.0")
    ch("success: آدرس دست‌نخورده ماند", cfg(etc)["ip"] == PUB_IP)
    ch("success: بکاپ یک-نسلی ساخته شد", (opt / ".prev-config.json").exists()
       and (opt / ".prev-access_agent").exists())

    # --- scenario 8: THE FIELD BUG — installer writes a LOCAL IP over the real one ---
    # 2026-11-10: detect_ip روی هاست داکری 172.22.0.1 را به‌جای IP اصلی سرور در
    # config.json ثبت کرد → هیچ اتصالی ممکن نبود. امروز: گارد آدرس موتور باید
    # چنین دریفت را بگیرد و rollback کند.
    etc, opt, fp = make_site(base, "8", "1.0.0", PUB_IP)
    bundle = make_bundle(base, "3.0.0", stub=STUB_INSTALL)
    man = make_manifest(base, "3.0.0", bundle)
    healthz = base / "hz8.json"
    healthz.write_text(json.dumps(
        {"ok": True, "version": "3.0.0", "cert_sha256": fp}), encoding="utf-8")
    rc, out = run_selfupdate(
        {"ACCESS_AGENT_MANIFEST_FILE": str(man),
         "ACCESS_AGENT_BUNDLE_FILE": str(bundle),
         "ACCESS_AGENT_HEALTHZ_FILE": str(healthz),
         "ACCESS_AGENT_STUB_MODE": "bad_ip", "ACCESS_AGENT_STUB_NEWVER": "3.0.0"},
        etc, opt, skip_install=False)
    row = last_row(etc)
    ch("field-bug ip: non-zero exit (rollback)", rc != 0, out[:300])
    ch("field-bug ip: row result=rolled_back",
       bool(row) and row.get("result") == "rolled_back", str(row))
    ch("field-bug ip: detail آدرس را صدا می‌زند",
       bool(row) and "address" in str(row.get("detail", "")), str(row))
    ch("field-bug ip: config.json از بکاپ بازگشت (IP اصلی)",
       cfg(etc)["ip"] == PUB_IP, str(cfg(etc)))
    ch("field-bug ip: گواهی از Update جان سالم به‌در برد",
       cert_fp(etc / "tls" / "cert.pem") == fp)

    # --- scenario 9: TLS cert drift → rollback (pinned clients protected) ---
    etc, opt, fp = make_site(base, "9", "1.0.0", PUB_IP)
    bundle = make_bundle(base, "3.0.0", stub=STUB_INSTALL)
    man = make_manifest(base, "3.0.0", bundle)
    healthz = base / "hz9.json"
    fake_fp = ("A" * 64)
    healthz.write_text(json.dumps(
        {"ok": True, "version": "3.0.0", "cert_sha256": fake_fp}), encoding="utf-8")
    rc, out = run_selfupdate(
        {"ACCESS_AGENT_MANIFEST_FILE": str(man),
         "ACCESS_AGENT_BUNDLE_FILE": str(bundle),
         "ACCESS_AGENT_HEALTHZ_FILE": str(healthz),
         "ACCESS_AGENT_STUB_MODE": "ok", "ACCESS_AGENT_STUB_NEWVER": "3.0.0"},
        etc, opt, skip_install=False)
    row = last_row(etc)
    ch("cert-drift: non-zero exit (rollback)", rc != 0, out[:300])
    ch("cert-drift: row result=rolled_back",
       bool(row) and row.get("result") == "rolled_back", str(row))
    ch("cert-drift: detail گواهی را صدا می‌زند",
       bool(row) and "TLS cert changed" in str(row.get("detail", "")), str(row))
    ch("cert-drift: config.json بازگشت", cfg(etc)["ip"] == PUB_IP)

    # --- scenario 10: wrong version after install → rollback ---
    etc, opt, fp = make_site(base, "10", "1.0.0", PUB_IP)
    bundle = make_bundle(base, "3.0.0", stub=STUB_INSTALL)
    man = make_manifest(base, "3.0.0", bundle)
    healthz = base / "hz10.json"
    healthz.write_text(json.dumps(
        {"ok": True, "version": "2.5.0", "cert_sha256": fp}), encoding="utf-8")
    rc, out = run_selfupdate(
        {"ACCESS_AGENT_MANIFEST_FILE": str(man),
         "ACCESS_AGENT_BUNDLE_FILE": str(bundle),
         "ACCESS_AGENT_HEALTHZ_FILE": str(healthz),
         "ACCESS_AGENT_STUB_MODE": "ok", "ACCESS_AGENT_STUB_NEWVER": "3.0.0"},
        etc, opt, skip_install=False)
    row = last_row(etc)
    ch("bad-version: non-zero exit (rollback)", rc != 0, out[:300])
    ch("bad-version: row result=rolled_back",
       bool(row) and row.get("result") == "rolled_back", str(row))
    ch("bad-version: config.json از بکاپ بازگشت (نسخهٔ قبلی)",
       cfg(etc)["version"] == "1.0.0", str(cfg(etc)))

    shutil.rmtree(base, ignore_errors=True)

    print(f"\n  نتیجه: {n_pass} سبز / {n_fail} قرمز")
    if failures:
        print("  شکست‌ها:", "; ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
