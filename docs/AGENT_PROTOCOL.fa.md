# پروتکل عامل هوش مصنوعی برای ایجنت دسترسی (Access Agent Protocol)

این سند قرارداد اتصال عامل هوش مصنوعی به ایجنت دسترسی است — عامل بدون پرسیدن دوباره باید بتواند وصل شود، راستی‌آزمایی کند و ابتکار عمل را بگیرد. مرجع نهایی جزئیات پیاده‌سازی: کد و `README.md`.

## ۱) ورودی‌هایی که مالک به عامل می‌دهد (سه مقدار از کارت نصب)

| کلید | مثال | استفاده |
|---|---|---|
| `ACCESS_AGENT_URL` | `https://193.151.142.128:25437` | آدرس سرویس (پورت تصادفی هنگام نصب) |
| `ACCESS_AGENT_CERT_SHA256` | `A3F1...` (۶۴ کاراکتر hex، بدون دو‌نقطه) | پین گواهی خودامضا — جایگزین CA |
| `ACCESS_AGENT_AGENT_TOKEN` | `aa_...` | Bearer همهٔ مسیرهای عامل (به‌جز healthz) |

در سمت عامل این سه مقدار فقط در فایل امن کلون پرستو ذخیره می‌شود:
`/home/z/my-project/parastoo/.secrets/access-agent.env` (chmod 600، gitignored).

## ۲) اتصال با پین گواهی (بدون اعتماد کورکورانه)

گواهی self-signed است؛ اعتبارسنجی یعنی «هش گواهی دریافتی == هش اعلامی مالک». پایتون استاندارد:

```python
import hashlib, json, socket, ssl, urllib.request

def load_access_env():
    env = {}
    for line in open("/home/z/my-project/parastoo/.secrets/access-agent.env", encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env[k] = v
    return env

def pinned_context(host, port, fingerprint_hex):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ws:
            der = ws.getpeercert(binary_form=True)
    got = hashlib.sha256(der).hexdigest().upper()
    if got != fingerprint_hex.upper():
        raise RuntimeError(f"cert fingerprint MISMATCH: {got}")
    pin = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    pin.check_hostname = False
    pin.verify_mode = ssl.CERT_REQUIRED
    pin.load_verify_locations(ssl.DER_cert_to_PEM_cert(der))
    return pin
```

ملاحظات: هنگام تعویض گواهی ( reinstall با purge یا انقضا) مالک باید اثر انگشت جدید را بفرستد. برای `curl`: گواهی را با `openssl s_client` بگیرید و `--cacert cert.pem` بدهید (بدون `-k`).

## ۳) چرخهٔ اتصال استاندارد عامل (M0 ایجنت دسترسی)

```bash
set -a; . /home/z/my-project/parastoo/.secrets/access-agent.env; set +a
# ۱) سلامت
curl -sk "$ACCESS_AGENT_URL/healthz"
# ۲) وضعیت هاست
curl -sk -H "Authorization: Bearer $ACCESS_AGENT_AGENT_TOKEN" "$ACCESS_AGENT_URL/api/status"
# ۳) تست exec (کوچک و بی‌خطر)
curl -sk -H "Authorization: Bearer $ACCESS_AGENT_AGENT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"cmd":"echo ok-from-agent && uname -a","timeout_s":15}' \
     "$ACCESS_AGENT_URL/api/exec"
```

معیار عبور: هر سه پاسخ JSON با `ok:true` دادند → عامل مجاز است کار سروری را ادامه دهد.

## ۴) قرارداد `POST /api/exec`

```json
{"cmd": "<≤۸۰۰۰ کاراکتر>", "timeout_s": 60, "cwd": "/opt/parastoo"}
```

- اجرا با `bash -c` روی خودِ هاست، `stdin=/dev/null`، kill کل process-group در تایم‌اوت.
- پاسخ: `{ok, exit_code, stdout, stderr, duration_ms, timed_out}` — هر جریان ≤ ۲۰۰هزار کاراکتر.
- خطاها: `cmd_too_long` / `timeout_out_of_range` / `cwd_not_found` / `bad_timeout` / `busy` (429 — سقف هم‌زمانی ۲).
- **قاعدهٔ طلایی:** دستورهای طولانی/چندگانه را با `&&` یا اسکریپت موقتی در `/tmp` بزنید؛ خروجی بزرگ را خودتان فیلتر کنید (`tail`, `grep`) چون سقف خروجی سخت است.

## ۵) گرفتن توکن گیت‌هاب برای پوش

```bash
curl -sk -H "Authorization: Bearer $ACCESS_AGENT_AGENT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"purpose":"push parastoo v0.3.10 docs update","ttl_min":60}' \
     "$ACCESS_AGENT_URL/api/github/token"
```

- `purpose` اجباری (≥ ۸ کاراکتر) و در `sessions.jsonl` + audit ثبت می‌شود.
- پاسخ `token` را فقط در حافظهٔ فرایند استفاده کنید (push همان چرخه) — هرگز در فایل gitدار ننویسید.
- مدل v0.1 «افشای نشست‌محور» است: خودِ پات منقضی نمی‌شود؛ ابطال واقعی = چرخش پات توسط مالک (`access-agent set-github-token`). گزارش به مالک بعد از هر افشا لازم نیست، ولی رکورد grant قابل بازبینی ادمین است (`GET /api/admin/sessions`).

## ۶) خطوط قرمز ویژهٔ این پل

1. `audit.jsonl` فقط‌افزایشی است؛ عامل آن را نمی‌خواند برای پاک‌کاری و هرگز دستکاری نمی‌کند (خواندن با توکن ادمین است، نه عامل).
2. ADMIN_TOKEN مال عامل نیست — اگر کاری به آن نیاز شد، درخواست به مالک گزارش می‌شود.
3. `/etc/access-agent/**` را عامل از طریق exec دستکاری نمی‌کند (توکن‌ها/گواهی/پات) مگر با درخواست صریح مالک و با گزارش کامل.
4. عملیات تخریبی روی خود سرور (factory-reset پرستو، uninstall، تعویض دامنه/TLS، تغییر کاربر ادمین) بدون تأیید صریح مالک ممنوع — حتی از این پل.
5. توکن‌ها هرگز در لاگ، کامیت، پیام خطا یا پاسخ به کاربر نهایی ظاهر نمی‌شوند.

## ۷) الگوی ترتیب کارها وقتی پرستو پایین است (سناریوی اصلی این پروژه)

1. `GET /healthz` + `GET /api/status` روی access-agent → وضعیت واقعی هاست.
2. `exec: systemctl status parastoo-autoupdate.timer --no-pager` و `docker ps -a --format ...` → علت 502.
3. `exec: tail -n 40 <مسیر نصب پرستو>/logs/update.log` → آخرین چرخهٔ آپدیت.
4. تعمیر طبق پروتکل M5 سند پرستو: در صورت نیاز `sudo bash scripts/auto-update.sh --force` داخل مسیر نصب، یا بازسازی `docker compose up -d --build core`.
5. راستی‌آزمایی زندهٔ پرستو (`tests/e2e_live.py`) → اگر سبز شد، گزارش به مالک با SHA مستقر.

از این پس هیچ‌یک از این گام‌ها به زنده‌بودن پرستو وابسته نیست — این کل معنای معماری جدید است.
