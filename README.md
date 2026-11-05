# ایجنت دسترسی (access-agent)

پل دسترسی **مستقل و همیشه‌روشن** برای عامل هوش مصنوعی به سرور — مستقل از پرستو، مستقل از داکر، مستقل از هر چیز دیگری که ممکن است کرش کند.

## چرا این پروژه وجود دارد؟ (تصمیم معماری ۲۰۲۶-۱۱-۰۵ مالک)

تا پیش از این، تنها مسیر دسترسی عامل هوشمند به سرور، خودِ پرستو بود (`/api/dev/*` روی پنل). اگر پرستو در نصب یا به‌روزرسانی شکست می‌خورد، عامل هیچ کاری نمی‌توانست بکند و **حلقهٔ تست و توسعه می‌شکست** — دقیقاً همان‌طور که در استقرار v0.3.9 (502 پایدار) اتفاق افتاد.

ایجنت دسترسی این حلقهٔ شکسته را می‌بندد:

```
مالک ──یک فرمان SSH──▶ ایجنت دسترسی (systemd، مستقل) ──▶ آدرس + توکن موقت
                                                              │
عامل هوش مصنوعی ◀───────── HTTPS + پین گواهی ────────────────┘
   │
   ├── دستور اجرا روی هاست (معادل SSH)
   ├── نصب/بازراه‌اندازی/تعمیر پرستو (حتی وقتی کاملاً پایین است)
   ├── تست و راستی‌آزمایی هر چیز روی سرور
   └── گرفتن توکن گیت‌هاب برای پوش (custodian: پات مالک روی سرور ذخیره است)
```

**اصل:** کاربر پس از نصب ایجنت دسترسی، هیچ کار دیگری روی سرور ندارد؛ همهٔ درخواست‌هایش را از طریق عامل هوش مصنوعی دنبال می‌کند — حتی نصب پرستو.

## نصب یک‌فرمانی (روی سرور، با SSH)

```bash
curl -fsSL https://raw.githubusercontent.com/SelfEvolvingNetwork/access-agent/main/bootstrap.sh | sudo bash
```

با ذخیرهٔ توکن گیت‌هاب مالک در همان لحظهٔ نصب (اختیاری ولی توصیه‌شده):

```bash
curl -fsSL https://raw.githubusercontent.com/SelfEvolvingNetwork/access-agent/main/bootstrap.sh | sudo ACCESS_AGENT_GITHUB_TOKEN=ghp_xxx bash
```

در ایران اگر گیت‌هاب مستقیم باز نشد:

```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/SelfEvolvingNetwork/access-agent/main/bootstrap.sh | sudo bash
```

**وابستگی‌ها فقط:** `python3` + `openssl` + `systemd` + `curl`. نه داکر، نه pip، نه هیچ بستهٔ دیگر — کل سرویس با کتابخانهٔ استاندارد پایتون اجرا می‌شود.

## بعد از نصب چه می‌شود؟

نصب‌کننده یک کارت گزارش چاپ می‌کند و در `/etc/access-agent/install-report.txt` (chmod 600) ذخیره می‌کند:

- `ACCESS_URL` — مثل `https://93.151.142.128:25437` (پورت تصادفی آزاد)
- `CERT_SHA256` — اثر انگشت گواهی خودامضای ۱۰ساله؛ عامل هوش مصنوعی این را پین می‌کند
- `AGENT_TOKEN` — توکن عامل؛ **این را به عامل هوش مصنوعی بدهید**
- `ADMIN_TOKEN` — توکن ادمین؛ **فقط پیش خودتان بمانید**، هرگز برای عامل نفرستید

مالک این سه مقدار (به‌جز ADMIN_TOKEN) را در چت به عامل هوش مصنوعی می‌دهد و از این پس عامل ابتکار عمل را در دست می‌گیرد: اتصال، تست، نصب/تعمیر پرستو، همه‌چیز.

## مدل امنیتی

| لایه | تصمیم |
|---|---|
| دو قلمرو توکن | `admin` (ادمین سرور) و `agent` (عامل هوش مصنوعی)؛ ادمین superset است |
| ذخیرهٔ توکن | فقط هش SHA-256 در `tokens.json` (chmod 600)؛ مقایسهٔ constant-time |
| انتقال | فقط HTTPS با گواهی خودامضا؛ عامل اثر انگشت گواهی را پین می‌کند |
| توکن گیت‌هاب | پات مالک فقط در `/etc/access-agent/github.env` (chmod 600، خارج از هر git)؛ عامل با هدف ثبت‌شده آن را می‌گیرد (افشای نشست‌محور + رکورد grant) |
| audit | هر فراخوانی در `audit/audit.jsonl` (append-only) — خط قرمز: عامل حق ویرایش ندارد |
| سقف‌های exec | cmd ≤ ۸۰۰۰ کاراکتر، timeout ≤ ۶۰۰ث، خروجی ≤ ۲۰۰هزار کاراکتر/جریان، هم‌زمانی ≤ ۲ (بیشتر → 429) |
| stdin | همیشه `/dev/null` (درس `curl \| bash` پرستو) |

چرخش و قطع توکن عامل هر وقت خواستید، یک فرمان است (بالا) — و `bootstrap.sh` را دوباره اجرا کنید، **کد ارتقا می‌یابد و همهٔ توکن‌ها/گواهی/پات/audit دست‌نخورده می‌مانند**.

## مرجع API (خلاصه؛ شرح کامل: `docs/AGENT_PROTOCOL.fa.md`)

| مسیر | دسترسی | کارکرد |
|---|---|---|
| `GET /healthz` | عمومی | سلامت سبک |
| `GET /` | عمومی | اطلاعات سرویس |
| `GET /api/status` | agent \| admin | وضعیت هاست (آپ‌تایم، دیسک، رم، داکر، مسیر نصب پرستو، وضعیت توکن‌ها) |
| `POST /api/exec` | agent \| admin | اجرای دستور روی هاست (معادل SSH) |
| `POST /api/github/token` | agent \| admin | گرفتن پات با هدف ثبت‌شده (افشای نشست‌محور) |
| `GET /api/admin/audit` | admin | دم audit |
| `GET /api/admin/sessions` | admin | فهرست grantهای توکن گیت‌هاب |
| `POST /api/admin/rotate-agent-token` | admin | توکن عامل جدید (قدیمی می‌میرد) |
| `POST /api/admin/revoke-agent-token` | admin | قطع قلمرو عامل |
| `POST /api/admin/set-github-token` | admin | ذخیره/تعویض پات مالک |

## فرمان‌های مالک روی سرور (CLI کمکی)

```bash
sudo access-agent status                 # وضعیت سرویس + آدرس + سلامت
sudo access-agent url                    # فقط ACCESS_URL
sudo access-agent show-agent-token       # توکن عامل (برای دادن به عامل)
sudo access-agent rotate-agent-token     # توکن جدید؛ قدیمی می‌میرد
sudo access-agent revoke-agent-token     # قطع دسترسی عامل
sudo access-agent show-admin-token       # توکن ادمین (فقط خودتان) — v0.1.1
sudo access-agent rotate-admin-token     # توکن ادمین جدید؛ قدیمی می‌میرد — v0.1.1
sudo access-agent set-github-token ghp_xxx   # تعویض پات (اعتبارسنجی best-effort)
sudo access-agent audit 30               # دم لاگ audit
```

## حذف کامل

```bash
curl -fsSL https://raw.githubusercontent.com/SelfEvolvingNetwork/access-agent/main/uninstall.sh | sudo bash
```

پیش‌فرض `secrets/audit` را نگه می‌دارد؛ با `--purge` همه‌چیز پاک می‌شود. پرستو هرگز لمس نمی‌شود.

## نقشهٔ راه

- **v0.1 (این نسخه):** پل مستقل + افشای نشست‌محور پات + CLI مالک
- **v0.2:** توکن موقت واقعی گیت‌هاب با GitHub App (توکن نصبی ۱ساعتهٔ فقط-مخزن) — مالک یک‌بار App می‌سازد؛ مسیر افشا به‌عنوان فال‌بک می‌ماند
- **v0.3:** کانال آپدیت پایدار (تگ) + آپدیتر خودکار access-agent جدا از پوش‌های main
- هر زمان: تعویض گواهی خودامضا با ACME اگر دامنه به این سرویس وصل شد

## خطوط قرمز (غیرقابل مذاکره)

1. توکن/رمز فقط در `/etc/access-agent/`؛ هرگز در کد، کامیت، لاگ یا گزارش.
2. `audit.jsonl` فقط‌افزایشی است — عامل حق ویرایش/پاک‌کردن آن را ندارد.
3. عامل ADMIN_TOKEN را هرگز دریافت یا درخواست نمی‌کند.
4. بدون تأیید مالک: `uninstall`، حذف audit، تعویض ADMIN_TOKEN، تغییر مسیرهای `-ETC` پیش‌فرض.
5. پوش به گیت‌هاب فقط با چک‌های سبز محلی (`python tests/smoke_test.py` + `bash -n`).
