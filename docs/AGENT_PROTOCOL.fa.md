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
- خطاها: `cmd_too_long` / `timeout_out_of_range` / `cwd_not_found` / `bad_timeout` / `busy` (429 — سقف هم‌زمانی ۲) / `lifecycle_busy` (409 از v0.5.1 — حین عملیات lifecycle پرستو، execِ متضاد با نصب/آپدیت/حذف — مثل bootstrap.sh، install.sh، docker compose — رد می‌شود؛ دستورهای خواندنی برای نظارت از راه می‌مانند و برعکس، شروع lifecycle حین اجرای execِ متضاد 409 exec_busy می‌گیرد).
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
- **v0.2 — دو حالت، با همان قرارداد:** اگر مالک GitHub App پیکربندی کرده باشد، پاسخ `mode: "github-app"` و `expires_at` دارد — توکن نصبِ واقعی است که حداکثر ۱ ساعت بعد خودش می‌میرد و فقط به مخزن‌های نصب‌شده می‌رسد؛ پات مالک هرگز سرو نمی‌شود. اگر `mode` نبود، حالت فالبک v0.1 فعال است (بند بعد). راهنمای پیکربندی برای مالک: `docs/GITHUB_APP_GUIDE.fa.md`.
- مدل فالبک v0.1 «افشای نشست‌محور» است: خودِ پات منقضی نمی‌شود؛ ابطال واقعی = چرخش پات توسط مالک (`access-agent set-github-token`). گزارش به مالک بعد از هر افشا لازم نیست، ولی رکورد grant قابل بازبینی ادمین است (`GET /api/admin/sessions`).

## ۵.۵) قابلیت‌های v0.3 — پرستو موبایل (ادمین در جیب)

این بخش قرارداد مسیرهای جدید v0.3 است؛ همه با **توکن ادمین** (قلمرو عامل هیچ‌کدام را ندارد):

| مسیر | کارکرد |
|---|---|
| `GET /api/admin/audit/stream` | جریان زندهٔ SSE از `audit/audit.jsonl` — هر خط audit یک رویداد `data:`؛ `id:` آفست بایت برای ادامه؛ `?cursor=<آفست>` پس از قطع‌شدن، `?backfill=N` (پیش‌فرض ۵۰، سقف ۵۰۰) تاریخچهٔ اولیه؛ ضربان `: ping` هر ~۱۵ ثانیه. خودِ جریان چیزی در audit نمی‌نویسد (بدون حلقهٔ بازخورد) |
| `GET /api/admin/agent-token` | متادیتای توکن عامل (`set`, `meta.label`, `meta.rotated_at`) — **هرگز خود توکن را نمی‌دهد** |
| `GET /api/admin/handoff` | بلوک تحویل آمادهٔ کپی برای عامل (همان خروجی `sudo access-agent handoff`)؛ اگر دادهٔ کامل نباشد `409 handoff_unavailable` |
| `POST /api/admin/agent-realm/pause` | **کلید توقف** — بدنهٔ `{"paused": true, "reason": "..."}`؛ در `state.json` ماندگار است (ریستارت هم می‌ماند). در حالت توقف، درخواست‌های قلمرو عامل به `/api/exec` و `/api/github/token` و `/api/status` → `403 agent_realm_paused`؛ ادمین همیشه آزاد؛ `healthz` عمومی دست‌نخورده |
| `POST /api/admin/rotate-agent-token` | v0.3: بدنهٔ اختیاری `{"label": "..."}` (≤۸۰ کاراکتر) در متادیتا ثبت می‌شود |
| `POST /api/admin/set-github-token` | **ذخیرهٔ پات مالک — «یک‌جای مناسب سرور»** (v0.2؛ از اپ 0.4.6 موبایل این مسیر رسمیِ تنظیم است): بدنهٔ `{"token": "..."}` → نوشتن در `github.env` با دسترسی ۶۰۰ (خارج از هر درخت git)، اعتبارسنجی بهترین‌تلاشی با `api.github.com/user` (آفلاین هم ذخیره می‌شود)، ثبت در audit بدون خودِ توکن. تعویض = همان مسیر؛ حذف = SSH (`rm $ACCESS_AGENT_HOME/github.env`). پرستو موبایل این را در جادوگر فراهم‌سازی (اختیاری) و در داشبورد (کارت «توکن گیت‌هاب برای عامل») ارائه می‌دهد؛ توکن روی گوشی ذخیره نمی‌شود |

**غنی‌سازی رکورد exec در audit (v0.3):** علاوه بر فیلدهای قبلی، `cmd_preview` (۴۰۰ کاراکتر)، `stdout_preview` (۶۰۰)، `stderr_preview` (۳۰۰) و `duration_ms` ثبت می‌شود — مانیتور زندهٔ موبایل فقط از این رکوردها تغذیه می‌کند؛ **عامل هیچ گزارش اضافه‌ای تولید نمی‌کند و هیچ باری نمی‌بیند.**

## ۶) خطوط قرمز ویژهٔ این پل

1. `audit.jsonl` فقط‌افزایشی است؛ عامل آن را نمی‌خواند برای پاک‌کاری و هرگز دستکاری نمی‌کند (خواندن با توکن ادمین است، نه عامل).
2. ADMIN_TOKEN مال عامل نیست — اگر کاری به آن نیاز شد، درخواست به مالک گزارش می‌شود.
3. `/etc/access-agent/**` را عامل از طریق exec دستکاری نمی‌کند (توکن‌ها/گواهی/پات) مگر با درخواست صریح مالک و با گزارش کامل.
4. عملیات تخریبی روی خود سرور (factory-reset پرستو، uninstall، تعویض دامنه/TLS، تغییر کاربر ادمین) بدون تأیید صریح مالک ممنوع — حتی از این پل.
5. توکن‌ها هرگز در لاگ، کامیت، پیام خطا یا پاسخ به کاربر نهایی ظاهر نمی‌شوند.

## ۷) الگوی ترتیب کارها وقتی پرستو پایین است (سناریوی اصلی این پروژه)

1. `GET /healthz` + `GET /api/status` روی access-agent → وضعیت واقعی هاست.
2. `GET /api/admin/parastoo/lifecycle-status` (ادمین) و `exec: docker ps -a --format ...` → علت 502. (از پل v0.5.1 تایمر آپدیت خودکار پرستو حذف شده — `systemctl status parastoo-autoupdate.timer` دیگر بخشی از تشخیص نیست.)
3. `exec: tail -n 40 <مسیر نصب پرستو>/logs/update.log` → آخرین چرخهٔ آپدیت.
4. تعمیر طبق پروتکل M5 سند پرستو: استقرار صریح با `POST /api/admin/parastoo/update` (lifecycle پل)، یا در سطح سرور `sudo parastoo update` / `docker compose up -d --build core`. نصب/آپدیت با exec مستقیمِ bootstrap ممنوع است — تنها کانال مجاز lifecycle پل است (گارد متقابل 409 جلوی بازیگر موازی را می‌گیرد).
5. راستی‌آزمایی زندهٔ پرستو (`tests/e2e_live.py`) → اگر سبز شد، گزارش به مالک با SHA مستقر.

از این پس هیچ‌یک از این گام‌ها به زنده‌بودن پرستو وابسته نیست — این کل معنای معماری جدید است.

## ۸) کانال انتشار پل — نصب/به‌روزرسانی مستقیم از گیت‌هاب (v0.5.2)

هر پوش به main یک رلیز خودکار می‌سازد (همان الگوی اپ موبایل با تگ متحرک):

| موجودیت | مقدار |
|---|---|
| تگ رلیز | `bridge-r<N>` — N شمارهٔ اجرای CI (همیشه «آخرین» یعنی releases/latest) |
| دارایی‌های رلیز | `access-agent-vX.Y.Z.tar.gz` + `.sha256` + `manifest.json` |
| چیدمان باندل | دقیقاً همان `pack-agent-bundle.sh` اپ موبایل — جریان `tar -xzf` + `bash install.sh <dir>` بدون تغییر کار می‌کند |
| کانال دوم صحت | `RELEASE_MANIFEST.json` روی شاخهٔ main (پیام کامیت `[skip ci]`) — نسخه، نام فایل، sha256 |

**قرارداد کلاینت نصب/به‌روزرسانی (اپ موبایل — و هر عامل دیگر):**
1. مانیفست را از `raw.githubusercontent.com/SelfEvolvingNetwork/access-agent/main/RELEASE_MANIFEST.json` بگیر — کانالی مستقل از فایل دارایی.
2. فایل باندل را از دارایی همان رلیز بگیر: اول مستقیم، در فالبک با پیش‌وند پروکسی (مثل `https://gh-proxy.com/`).
3. `sha256(باندل دانلودی) == sha256 مانیفست` — وگرنه رد قطعی (تزریق از مسیر آینه/پروکسی بسته می‌شود).
4. **هرگز downgrade ممنوع:** نسخهٔ مانیفست ≤ نسخهٔ نصب‌شده روی سرور → رد (مگر force صریح اپراتور).
5. نصب تازه: توکن‌های ساخته‌شده روی دستگاه + `ACCESS_AGENT_RESET_TOKENS=1` — قرارداد «رمز روت = مالکیت». **از v0.5.2 این متغیر در مسیر ارتقای `install.sh` واقعاً پیاده شده** (توکن‌های قبلی می‌میرند، هیچ‌چیز چاپ نمی‌شود، بدون توکن env ریست رد می‌شود تا قفل‌شدن پیش نیاید) — تا قبل از آن این قرارداد فقط در سند بود و فراهم‌سازی دوبارهٔ سرورِ دارای پل عملاً شکست می‌خورد.
6. به‌روزرسانی پلِ موجود: **بدون** `RESET_TOKENS` و **بدون** env توکن‌ها — مسیر ارتقا همهٔ رازها (توکن‌ها، گواهی TLS، PAT، audit) را نگه می‌دارد؛ سرویس ری‌استارت می‌شود و exec در-flight عامل ممکن است قطع شود — طبیعی است، عامل دوباره وصل می‌شود و بلوک تحویلش معتبر می‌ماند.
7. فالبک آفلاین: اگر هیچ کانالی باز نشد، باندل جاسازی‌شدهٔ اپ فقط برای **سرور نو** مجاز است؛ برای به‌روزرسانی، رد با پیام صادقانه فارسی (نسخهٔ فعلی حفظ می‌شود).
8. راستی‌آزمایی پس از نصب: نسخه از `/api/status` خوانده و با انتظار مانیفست مقایسه می‌شود؛ ناسازگار = گزارش صریح، نه سکوت.
