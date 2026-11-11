# راهنمای GitHub App برای پل — توکن‌های موقتِ واقعی (access-agent v0.2)

> مخاطب: مالک (پیکربندی GitHub App) · عامل فقط §۵ پروتکل را می‌خواند

**چرا؟** گیت‌هاب به هیچ API اجازه نمی‌دهد PAT جدید بسازد؛ پس حالت v0.1 فقط «بروکر» بود: پات مالک را با ثبت هدف و مهلت تحویل می‌داد، ولی خودِ توکن منقضی نمی‌شد. با یک **GitHub App**، پل توکن‌های نصبِ واقعی می‌سازد که:

- **خودشان می‌میرند** — حداکثر ۱ ساعت، انقضا را خود گیت‌هاب اعمال می‌کند (نه حسابرسیِ پل)؛
- **محدود به مخزن‌های نصب‌شده‌اند** — فقط همان مخزن‌هایی که اپ رویشان نصب شده (مثلاً فقط `parastoo`)؛
- **پات مالک هرگز سرو نمی‌شود** — بعد از پیکربندی اپ، `/api/github/token` فقط توکن نصب می‌دهد و به `github.env` دست نمی‌زند.

اگر اپ پیکربندی نشود، همه‌چیز مثل قبل (حالت پات) کار می‌کند — هیچ‌چیز نمی‌شکند.

---

## گام ۱ — ساخت اپ در گیت‌هاب (فقط مالک، در UI — با API ممکن نیست)

1. گیت‌هاب → **Settings → Developer settings → GitHub Apps → New GitHub App**
2. فیلدها:
   - **GitHub App name**: هر نامی، مثلاً `parastoo-agent`
   - **Homepage URL**: `https://panel.zeolitecenter.ir`
   - **Webhook → Active**: ❌ غیرفعال (نیازی نیست)
   - **Permissions → Repository permissions → Contents**: `Read and write` (Metadata خودکار Read-only می‌ماند — کافی و الزام است)
3. **Where can this GitHub App be installed?** → `Only on this account` (یا هر گزینهٔ در دسترس شما)
4. **Create GitHub App** → در صفحهٔ اپ، **App ID** را کپی کنید (عددی).

## گام ۲ — کلید خصوصی

همان صفحهٔ اپ → تب **General → Private keys → Generate a private key**
→ فایل `.pem` دانلود می‌شود (مثلاً `parastoo-agent.2026-11-06.private-key.pem`).

## گام ۳ — نصب اپ روی مخزن

همان صفحه → تب **Install App** → حساب/سازمان `SelfEvolvingNetwork` را انتخاب کنید →
**Only select repositories** → `parastoo` → **Install**.

> سخت‌گیری بهتر: فقط همین یک مخزن. توکن‌های ساخته‌شده دقیقاً به همین محدود می‌مانند.

## گام ۴ — پیکربندی روی سرور (یک فرمان)

کلید `.pem` را **فقط با SSH/scp** به سرور برسانید — **هرگز از کانال هوش مصنوعی یا چت رد نکنید** (کلید اعتبارنامهٔ اپ است، نه چیزی برای عامل):

```bash
scp parastoo-agent.*.private-key.pem root@193.151.142.128:/root/
ssh root@193.151.142.128
sudo access-agent set-github-app <APP_ID> /root/parastoo-agent.*.private-key.pem
sudo access-agent test-github-app      # یک توکن واقعی می‌سازد و فقط metadata چاپ می‌کند
rm /root/parastoo-agent.*.private-key.pem   # پل نسخهٔ خودش را در /etc/access-agent/github-app.pem دارد (600)
```

خروجی `test-github-app` فقط `expires_at` و دسترسی‌ها را نشان می‌دهد — مقدار توکن هرگز چاپ نمی‌شود.

## گام ۵ — از این لحظه

- عامل با همان قرارداد قبلی (`POST /api/github/token` با `purpose`) توکن می‌گیرد — پاسخ حالا `mode: "github-app"` و `expires_at` دارد.
- هر grant در `sessions.jsonl` و `audit.jsonl` ثبت می‌شود (با `mode` جدید).
- پات مالک در `github.env` دست‌نخورده می‌ماند اما دیگر هیچ‌وقت سرو نمی‌شود — می‌توانید حتی آن را بچرخانید و فراموش کنید.

## مدیریت و اضطرار

```bash
sudo access-agent show-github-app     # خلاصهٔ پیکربندی (بدون راز)
sudo access-agent test-github-app     # تست مینت تازه
sudo access-agent clear-github-app    # بازگشت به حالت پات
```

- **چرخش کلید:** در UI اپ کلید جدید بسازید، دوباره `set-github-app` — کلید قدیمی بلافاصله بی‌اثر می‌شود.
- **قطع کامل دسترسی پوش عامل:** در UI اپ → **Uninstall** (یا **Delete**) — توکن‌های صادرشده حداکثر تا ۱ ساعت بعد می‌میرند و هیچ توکن جدیدی ساخته نمی‌شود. این دقیقاً همان کلید اضطراریِ واقعی است که با پات مالک ممکن نبود.
- اگر `api.github.com` از سرور در دسترس نباشد، مینت شکست می‌خورد (پاسخ ۵۰۲ با پیام روشن) و audit ثبت می‌شود — عامل هیچ رازی نمی‌بیند.

## اثر انگشت‌های امنیتی این طراحی

| راز | کجا زندگی می‌کند | چه کسی می‌بیند |
|---|---|---|
| کلید خصوصی اپ (`.pem`) | `/etc/access-agent/github-app.pem` (chmod 600) | فقط مالک روی سرور؛ عامل هرگز |
| پات مالک | `/etc/access-agent/github.env` (chmod 600) | فقط پل؛ از v0.2 دیگر حتی سرو هم نمی‌شود |
| توکن نصب ساعتی | فقط در پاسخ HTTP به عامل + کش تا ۵ دقیقه پیش از انقضا | عامل — و خودش تا یک ساعت بعد می‌میرد |
