# CDN Edge IP Checker

🌐 زبان‌ها: [English](README.md) | [فارسی](README_fa.md)

یک اسکنر سبک، سریع و چندنخی با پایتون برای بررسی IPهای Edge مربوط به CDN.

این ابزار برای این ساخته شده که قبل از تست‌های سنگین‌تر، یک لیست IP را سریع‌تر فیلتر کنید؛ مخصوصاً برای کلاینت‌هایی که ممکن است با IPهای CDN در حالت **Empty SNI** یا حالت **SNI/Fronting** کار کنند.

در حال حاضر ابزار دو حالت اصلی دارد:

- **FAST mode**: بررسی سریع TCP و TLS/HTTP روی IPهای CDN.
- **FULL mode**: برای تست واقعی تونل در آینده در نظر گرفته شده است. فعلاً فقط هشدار می‌دهد که تست تونل هنوز پیاده‌سازی نشده و همان تست‌های FAST را اجرا می‌کند.

نکته مهم: این ابزار ادعا نمی‌کند که اگر یک IP در TLS موفق شد، حتماً داخل کلاینت نهایی هم کار می‌کند. خروجی ابزار IPها را با وضعیت‌های `bad`، `maybe`، `candidate` و `strong` دسته‌بندی می‌کند تا نتیجه واقعی‌تر و قابل‌فهم‌تر باشد.

---

## فهرست مطالب

- [شروع سریع](#شروع-سریع)
- [آماده‌سازی IPها از روی CIDR Rangeهای CDN](#آماده‌سازی-ipها-از-روی-cidr-rangeهای-cdn)
- [نحوه کار](#نحوه-کار)
- [پروفایل‌های اسکن](#پروفایل‌های-اسکن)
  - [پروفایل Empty-SNI](#پروفایل-empty-sni)
  - [پروفایل SNI Fronting](#پروفایل-sni-fronting)
- [معنی وضعیت‌ها](#معنی-وضعیت‌ها)
- [خروجی](#خروجی)
- [نحوه استفاده](#نحوه-استفاده)
- [گزینه‌ها](#گزینه‌ها)
- [نیازمندی‌ها](#نیازمندی‌ها)
- [نصب](#نصب)
- [کاربردها](#کاربردها)
- [نکات و محدودیت‌ها](#نکات-و-محدودیت‌ها)

---

## شروع سریع

ابتدا پروژه را کلون کنید:

```bash
git clone https://github.com/FarazFe/cdn-ip-checker.git
cd cdn-ip-checker
```

یک فایل لیست IP بسازید:

```bash
echo "23.209.22.214" > ips.txt
```

یا اگر رنج‌های CDN را دارید، از روی CIDR Rangeها IP تولید کنید:

```bash
python generate_ips.py -f akamai_ranges.txt -m fast
```

اسکن پیش‌فرض FAST با Empty SNI را اجرا کنید:

```bash
python cdn_ip_checker.py -f ips.txt
```

برای اینکه هر IP چند بار تست شود:

```bash
python cdn_ip_checker.py -f ips.txt --attempts 3 -w 10 -t 10
```

برای اسکن FAST با SNI/fronting:

```bash
python cdn_ip_checker.py -f ips.txt --sni example.com --attempts 3
```

نتیجه‌ها در این فایل‌ها ذخیره می‌شوند:

```text
candidate_ips.txt
results.txt
results.jsonl
```

برای بیشتر کاربران، فایل اصلی برای کپی کردن IPها `candidate_ips.txt` است. این فایل فقط IPها را، هرکدام در یک خط، ذخیره می‌کند.

---

## آماده‌سازی IPها از روی CIDR Rangeهای CDN

قبل از اجرای checker، به یک لیست از IPهای واقعی نیاز دارید.

بسیاری از CDNها رنج IPهای edge خود را به صورت **CIDR notation** منتشر یا announce می‌کنند. برای مثال:

```text
104.64.0.0/10
23.32.0.0/11
23.192.0.0/11
```

این‌ها IP تکی نیستند؛ هرکدام یک رنج IP هستند. برای اینکه بتوانید آن‌ها را اسکن کنید، اول باید از روی این رنج‌ها IPهای واقعی تولید شود.

برای مثال، رنج‌ها را در فایلی به نام `akamai_ranges.txt` ذخیره کنید:

```text
104.64.0.0/10
23.32.0.0/11
23.192.0.0/11
23.0.0.0/12
```

برای گرفتن یک نمونه تصادفی از هر رنج:

```bash
python generate_ips.py -f akamai_ranges.txt -m fast
```

به صورت پیش‌فرض، خروجی در این فایل ذخیره می‌شود:

```text
ips.txt
```

اگر خواستید نام فایل خروجی را عوض کنید، می‌توانید از `-o` استفاده کنید:

```bash
python generate_ips.py -f akamai_ranges.txt -m fast -o my_ips.txt
```

اگر می‌خواهید مشخص کنید از هر رنج چند IP نمونه گرفته شود:

```bash
python generate_ips.py -f akamai_ranges.txt -m fast -s 1000
```

اگر واقعاً می‌خواهید تمام IPهای داخل همه CIDR Rangeها تولید شوند:

```bash
python generate_ips.py -f akamai_ranges.txt -m full
```

در استفاده از حالت `full` در `generate_ips.py` دقت کنید. رنج‌های CDN می‌توانند خیلی بزرگ باشند و ممکن است میلیون‌ها IP تولید شود.

جریان کلی کار به این شکل است:

```text
CDN CIDR ranges -> generate ips.txt -> run cdn_ip_checker.py
```

---

## نحوه کار

برای هر IP، ابزار ابتدا تلاش می‌کند به پورت TCP 443 وصل شود.

TCP شرط اصلی است:

```text
TCP failed -> bad
```

اگر TCP موفق شود، مرحله بعدی بستگی دارد به اینکه `--sni` داده باشید یا نه.

اگر `--sni` وارد نشده باشد، ابزار **پروفایل Empty-SNI** را اجرا می‌کند.

اگر `--sni` وارد شده باشد، ابزار **پروفایل SNI Fronting** را اجرا می‌کند.

با گزینه `--attempts` می‌توانید هر IP را چند بار تست کنید. این موضوع برای CDNها خیلی مهم است، چون رفتار IPهای Edge همیشه کاملاً پایدار نیست. یک TLS fail در یک تلاش، همیشه به معنی غیرقابل‌استفاده بودن IP نیست.

---

## پروفایل‌های اسکن

### پروفایل Empty-SNI

دستور:

```bash
python cdn_ip_checker.py -f ips.txt --mode fast
```

اگر `--sni` وارد نکنید، این پروفایل اجرا می‌شود.

این پروفایل دو چیز را تست می‌کند:

1. اتصال TCP به IP روی پورت 443.
2. TLS handshake با Python/OpenSSL بدون ارسال SNI.

این حالت مناسب سناریویی است که کاربر فقط IPهای CDN را وارد می‌کند و فیلد SNI را در کلاینت خالی می‌گذارد.

نمونه خروجی:

```text
185.200.232.40  mode=fast  profile=empty-sni  tcp_ok=true  tcp=3/3  tls_openssl=0/3  http_fronting=skipped  tls_go=skipped  tls_utls_chrome=skipped  score=0/1  status=maybe
```

معنی این خروجی:

- TCP در هر ۳ تلاش موفق بوده است.
- TLS بدون SNI با Python/OpenSSL در هر ۳ تلاش شکست خورده است.
- IP حذف قطعی نشده، چون TCP کار کرده است.
- وضعیت `maybe` است، نه `bad`.

### پروفایل SNI Fronting

دستور:

```bash
python cdn_ip_checker.py -f ips.txt --mode fast --sni example.com
```

اگر `--sni` وارد کنید، این پروفایل اجرا می‌شود.

این پروفایل سه چیز را تست می‌کند:

1. اتصال TCP به IP روی پورت 443.
2. TLS handshake با Python/OpenSSL و SNI داده‌شده.
3. ارسال یک درخواست HTTP/1.1 با `Host: <sni>`.

بعد از موفق شدن TLS، درخواست HTTP شبیه این ارسال می‌شود:

```http
GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Connection: close
```

نمونه خروجی:

```text
1.2.3.4  mode=fast  profile=sni-fronting  sni=example.com  tcp_ok=true  tcp=3/3  tls_openssl=3/3  http_fronting=2/3  tls_go=skipped  tls_utls_chrome=skipped  score=2/2  status=candidate
```

معنی این خروجی:

- TCP در هر ۳ تلاش موفق بوده است.
- TLS با SNI در هر ۳ تلاش موفق بوده است.
- پاسخ HTTP در ۲ تلاش از ۳ تلاش موفق بوده است.
- IP احتمالاً مفید است، اما کاملاً پایدار نبوده؛ برای همین وضعیت آن `candidate` است.

---

## معنی وضعیت‌ها

ابزار از این وضعیت‌ها استفاده می‌کند:

| وضعیت | معنی |
|---|---|
| `bad` | TCP شکست خورده است. این IP برای این اسکن مفید نیست. |
| `maybe` | TCP کار کرده، اما تست TLS/fronting موفق نشده است. برای سناریوهای کلاینت‌های CDN Edge، این را حذف قطعی در نظر نگیرید. |
| `candidate` | حداقل یکی از تست‌های سطح بالاتر موفق شده، اما نتیجه در همه تلاش‌ها پایدار نبوده است. |
| `strong` | همه تست‌های لازم برای پروفایل انتخاب‌شده، در همه تلاش‌ها موفق بوده‌اند. |

تفاوت مهم:

```text
TCP failed -> bad
TCP worked but TLS failed -> maybe
```

این رفتار عمدی است. شکست TLS با Python/OpenSSL می‌تواند به خاطر تفاوت fingerprint در TLS، فیلترینگ شبکه، رفتار CDN، timeout، یا ناپایداری مسیر باشد. پس همیشه ثابت نمی‌کند که IP داخل کلاینت نهایی هم کار نخواهد کرد.

---

## خروجی

ابزار سه فایل خروجی می‌سازد:

```text
candidate_ips.txt
results.txt
results.jsonl
```

`candidate_ips.txt` خروجی اصلی و آماده‌ی استفاده برای کاربر است. این فایل فقط IPها را، هرکدام در یک خط، ذخیره می‌کند و آن‌ها را از بهتر به ضعیف‌تر مرتب می‌کند تا بتوانید راحت داخل کلاینت خودتان کپی کنید:

```text
5.6.7.8
1.2.3.4
8.8.8.8
```

این فایل نتیجه‌های `strong`، `candidate` و `maybe` را نگه می‌دارد و `bad`ها را حذف می‌کند. دلیل نگه داشتن `maybe` این است که TCP کار کرده، و شکست TLS با Python/OpenSSL همیشه به معنی حذف قطعی IP نیست.

`results.txt` خروجی کامل‌تر و مناسب بررسی/debug است:

```text
185.200.232.40  mode=fast  profile=empty-sni  tcp_ok=true  tcp=3/3  tls_openssl=0/3  http_fronting=skipped  tls_go=skipped  tls_utls_chrome=skipped  score=0/1  status=maybe  error=TLS empty-SNI failed: ConnectionResetError: ConnectionResetError(104, 'Connection reset by peer')
```

`results.jsonl` برای پردازش ماشینی است؛ در هر خط یک JSON object قرار دارد. بعداً می‌شود از آن برای فیلتر کردن، امتیازدهی، مرتب‌سازی یا وارد کردن به ابزارهای دیگر استفاده کرد.

این نسخه دیگر فایل‌های جداگانه مثل این‌ها را نمی‌سازد:

```text
clean_domainless.txt
clean_fronting.txt
```

فایل آماده‌ی کپی کردن IPها حالا `candidate_ips.txt` است، و جزئیات کامل اسکن در `results.txt` و `results.jsonl` باقی می‌ماند.

---

## نحوه استفاده

ابتدا یک فایل متنی آماده کنید که در هر خط آن یک IP باشد:

```text
23.209.22.214
1.2.3.4
5.6.7.8
```

خط‌هایی که با `#` شروع شوند نادیده گرفته می‌شوند.

### FAST mode با Empty SNI

```bash
python cdn_ip_checker.py -f ips.txt --mode fast
```

چون `fast` حالت پیش‌فرض است، دستور زیر هم معادل همان است:

```bash
python cdn_ip_checker.py -f ips.txt
```

### FAST mode با Empty SNI و چند تلاش

```bash
python cdn_ip_checker.py -f ips.txt --attempts 5 -w 10 -t 10
```

### FAST mode با SNI/fronting

```bash
python cdn_ip_checker.py -f ips.txt --mode fast --sni example.com
```

### FULL mode

```bash
python cdn_ip_checker.py -f ips.txt --mode full
```

`FULL mode` برای تست واقعی تونل در آینده در نظر گرفته شده است. در نسخه فعلی، فقط یک هشدار چاپ می‌کند و تست‌های FAST را اجرا می‌کند.

---

## گزینه‌ها

```text
-f, --file       مسیر فایل لیست IPها. اجباری است.
--mode           حالت اسکن: fast یا full. پیش‌فرض: fast.
--sni            نام SNI. اگر وارد شود، پروفایل sni-fronting فعال می‌شود.
--attempts       تعداد تلاش برای هر IP. پیش‌فرض: 3.
-t, --timeout    زمان timeout برای هر اتصال، بر حسب ثانیه. پیش‌فرض: 10.
-w, --workers    تعداد worker threadهای همزمان. پیش‌فرض: 10.
```

مثال‌ها:

```bash
python cdn_ip_checker.py -f ips.txt --attempts 3 -w 10 -t 10
python cdn_ip_checker.py -f ips.txt --sni example.com --attempts 5 -w 5 -t 15
```

برای تست پایداری، بهتر است تعداد worker کمتر و تعداد attempts بیشتر باشد:

```bash
python cdn_ip_checker.py -f ips.txt --attempts 5 -w 5 -t 15
```

برای کشف اولیه روی لیست‌های بزرگ‌تر، می‌توانید workerها را بیشتر کنید؛ اما concurrency خیلی بالا ممکن است خودش باعث timeout، فشار روی شبکه محلی، یا false failure شود.

---

## نیازمندی‌ها

- Python نسخه 3.10 یا جدیدتر لازم است.
- به هیچ پکیج جانبی نیاز نیست.

اسکریپت فقط از standard library پایتون استفاده می‌کند.

---

## نصب

پروژه را کلون کنید یا فایل‌های اسکریپت را مستقیم دانلود کنید:

```bash
git clone https://github.com/FarazFe/cdn-ip-checker.git
cd cdn-ip-checker
```

نیازی به نصب پکیج خاصی نیست.

---

## کاربردها

- فیلتر اولیه IPهای CDN برای کلاینت‌هایی که از Empty SNI پشتیبانی می‌کنند.
- تست IPهای CDN با یک SNI/fronting hostname مشخص.
- مقایسه رفتار ناپایدار CDN Edgeها در چند تلاش پشت سر هم.
- ساختن لیست candidate قبل از تست‌های سنگین‌تر و کندتر در FULL mode آینده.

---

## نکات و محدودیت‌ها

FAST mode فقط یک pre-filter است. موفق شدن یک IP در FAST mode ثابت نمی‌کند که آن IP حتماً داخل کلاینت نهایی یا تونل واقعی هم کار می‌کند.

تست‌هایی که فعلاً در FAST mode پیاده‌سازی شده‌اند:

```text
TCP
Python/OpenSSL TLS
در صورت وارد شدن --sni: درخواست HTTP/1.1 برای fronting
```

تست‌هایی که برای آینده برنامه‌ریزی شده‌اند:

```text
Go TLS helper
uTLS Chrome-like TLS helper
FULL mode real tunnel verification
```

در خروجی، این فیلدها را از الان می‌بینید:

```text
tls_go=skipped
tls_utls_chrome=skipped
```

این فیلدها فعلاً پیاده‌سازی نشده‌اند، اما از الان در خروجی آمده‌اند تا وقتی این قابلیت‌ها اضافه شدند، فرمت خروجی تغییر اساسی نکند.