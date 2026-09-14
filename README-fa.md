# Proxy Builder

یک وب‌اپلیکیشن قدرتمند و مستقل با دو ابزار:

<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>🧬 Fragment + Fingerprint</b> — ارتقای لینک <b>VLESS</b> یا <b>Trojan</b> با افزودن پارامترهای <code>cs</code> (لیست Cipher Suites)، <code>fm</code> (Fragment Mask) و <code>fp</code> (اثر انگشت TLS) به‌همراه قابلیت تغییر سرور (IP/دامنه) — خروجی لینکی آماده برای وارد کردن در کلاینت خودتان.</li>
  <li><b>🔗 Chain Builder</b> — ترکیب دو کانفیگ پراکسی به یک کانفیگ واحد <b>Xray</b> یا <b>Sing-box</b> برای افزایش پایداری اتصال و استفاده از آی‌پی ثابت.</li>
</ul>

تمام پردازش‌ها درون مرورگر شما انجام می‌شود. هیچ داده‌ای به سروری ارسال نمی‌گردد.

## 🚀 ویژگی‌ها

### 🧬 Fragment + Fingerprint
<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>جای‌گذاری و ارتقا</b>: لینک تکی یا چندگانه (تک‌به‌تک در هر خط) از <code>vless://</code> یا <code>trojan://</code> را جای‌گذاری کنید و لینک‌های ارتقایافته با پارامترهای <code>cs</code>، <code>fm</code> و <code>fp</code> دریافت کنید.</li>
  <li><b>پشتیبانی از چندین کانفیگ همزمان</b>: امکان جای‌گذاری لیست انبوه کانفیگ‌ها جهت پردازش، اعتبارسنجی و ارتقای دسته‌جمعی بدون تداخل در remark کانفیگ‌ها.</li>
  <li><b>تغییر سرور</b>: فیلد سرور (IP/دامنه) فقط برای کانفیگ تکی به‌صورت خودکار از URL استخراج می‌شود و قابل ویرایش است. در حالت چند کانفیگ، این فیلد خالی می‌ماند و فقط اگر مقدار دلخواه وارد کنید روی همه کانفیگ‌ها اعمال می‌شود (پشتیبانی از IPv4، IPv6 و دامنه).</li>
  <li><b>اثر انگشت (Fingerprint)</b>: پیش‌فرض <code>unsafe</code> با گزینه‌های <code>chrome</code>، <code>firefox</code>، <code>safari</code>، <code>random</code> و <code>none</code>.</li>
  <li><b>نسخه‌های فرگمنت (Fragment)</b>: فیلد <code>fm</code> دارای دو preset است — <code>v1</code> کلاسیک (<code>5,94,1</code> / <code>109,1</code> / split برابر <code>355</code>) و <code>v2</code> جدید (پیش‌فرض: <code>0,104,1</code> / <code>114,1</code> / split برابر <code>11</code>). با سلکتور <code>Fragment Version</code> جابه‌جا شوید؛ فیلد همچنان دستی قابل ویرایش است.</li>
  <li><b>آگاه از TLS</b>: پارامترهای <code>cs</code> و <code>fm</code> فقط زمانی اضافه می‌شوند که کانفیگ از امنیت <code>tls</code> استفاده کند. با خالی کردن هر فیلد، آن پارامتر حذف می‌شود.</li>
  <li><b>کپی با یک کلیک</b>: کپی مستقیم لینک ارتقایافته در کلیپ‌بورد.</li>
  <li><b>پشتیبانی از پروتکل‌ها</b>: <b>VLESS</b> و <b>Trojan</b>.</li>
</ul>

### 🔗 Chain Builder
<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>ترکیب دوگانه کانفیگ</b>: به‌راحتی یک پراکسی اولیه (مانند Worker/CDN) را با یک پراکسی زنجیره‌ای (Chain Proxy) ترکیب کنید.</li>
  <li><b>پشتیبانی از پروتکل‌ها</b>: پشتیبانی از <b>VLESS</b>، <b>VMess</b>، <b>Trojan</b>، <b>Shadowsocks</b>، <b>SOCKS</b>، <b>HTTP</b> و <b>SSH</b>.</li>
  <li><b>خروجی دوگانه</b>: تولید کانفیگ JSON برای هر دو کلاینت <b>Xray</b> و <b>Sing-box</b>.</li>
  <li><b>پشتیبانی از ECH</b>: استخراج و افزودن خودکار تنظیمات ECH برای اتصالی امن‌تر.</li>
</ul>

## 📦 فرمت‌های خروجی

<table dir="rtl" width="100%" style="direction: rtl; text-align: right;">
  <thead>
    <tr>
      <th align="right">خروجی</th>
      <th align="right">کلاینت</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>Xray JSON</b></td>
      <td>قابل استفاده در تمام کلاینت‌های سازگار با Xray&rlm; (مانند v2rayN&rlm;، v2rayNG&rlm;، Nekoray&rlm; و غیره).</td>
    </tr>
    <tr>
      <td><b>Sing-box JSON</b></td>
      <td>دارای زیر-تب‌های تخصصی برای کلاینت‌های مختلف (بخش پایین را ببینید).</td>
    </tr>
  </tbody>
</table>

### 📦 فرمت‌های تخصصی Sing-box
<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>Standard</b>: کانفیگ استاندارد هسته Sing-box.</li>
  <li><b>Nekoray</b>: بهینه‌سازی شده برای حداکثر سازگاری با <b>Nekoray</b>.</li>
  <li><b>Nekobox (Android)</b>: مخصوص اندروید؛ دارای <b>رابط مجازی TUN</b> برای شناسایی صحیح VPN در سیستم‌عامل (نمایش آیکون کلید) و پایداری بیشتر در شبکه موبایل.</li>
</ul>

## 🔗 شیوه کار Chain Builder

این ابزار کانفیگی تولید می‌کند که ترافیک شما را به این ترتیب مسیریابی می‌کند:

<p dir="rtl" align="center" style="direction: rtl;">
  <code>شما ⬅️ کانفیگ ۱ (پراکسی اولیه) ⬅️ کانفیگ ۲ (Chain) ⬅️ اینترنت</code>
</p>

این ساختار تضمین می‌کند که آی‌پی خروجی و نهایی شما همان آی‌پی <b>کانفیگ ۲ (Chain Proxy&rlm;)</b> باشد، که هویتی ثابت و پایدار برای وب‌سایت‌هایی که از آنها بازدید می‌کنید، فراهم می‌آورد.

## 🛠️ نحوه استفاده

### 🧬 Fragment + Fingerprint
<ol dir="rtl" style="direction: rtl; text-align: right;">
  <li>به تب <b>Fragment + Fingerprint</b> بروید.</li>
  <li>لینک <b>VLESS</b> یا <b>Trojan</b> خود را جای‌گذاری کنید.</li>
  <li>در صورت نیاز گزینه‌ها را تنظیم کنید: تغییر سرور (به‌صورت خودکار از URL پر می‌شود)، اثر انگشت، لیست Cipher Suites و Final Mask.</li>
  <li>روی <b>«Enhance URL»</b> کلیک کنید و لینک حاصل را کپی کرده و در کلاینت خود وارد کنید.</li>
</ol>

#### ✅ الزامات کلاینت
<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>ویندوز</b>: حتماً از نرم‌افزار <a href="https://github.com/patterniha/PattN">PattN</a> استفاده کنید.</li>
  <li><b>اندروید</b>: حتماً از نرم‌افزار <a href="https://github.com/patterniha/PattNG">PattNG</a> استفاده کنید.</li>
</ul>

### 🔗 Chain Builder
<ol dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>کانفیگ ۱</b>: لینک پراکسی اول خود را جای‌گذاری کنید (این کانفیگ می‌تواند یک Cloudflare Worker&rlm;، CDN&rlm; یا هر پراکسی مشابهی باشد).</li>
  <li><b>کانفیگ ۲</b>: لینک پراکسی دوم که می‌خواهید ترافیک از آن عبور کند، جای‌گذاری نمایید.
    <ul>
      <li>برای <b>SSH</b>، روی دکمه 🔑 SSH کلیک کنید و مشخصات سرور، پورت، نام کاربری و رمز عبور را وارد نمایید.</li>
    </ul>
  </li>
  <li><b>تنظیمات</b>: در صورت نیاز، سرور DNS&rlm; یا پورت SOCKS&rlm; را تغییر دهید.</li>
  <li><b>تولید خروجی</b>: روی "Generate Chained Config" (تولید کانفیگ زنجیره‌ای) کلیک کنید تا JSON&rlm; شما آماده شود.</li>
  <li><b>استفاده در کلاینت</b>: کد JSON&rlm; را کپی کرده یا به‌صورت فایل دانلود کنید و در کلاینت دلخواه خود استفاده نمایید.</li>
</ol>

## 📋 پروتکل‌های پشتیبانی‌شده

<table dir="rtl" width="100%" style="direction: rtl; text-align: right;">
  <thead>
    <tr>
      <th align="right">پروتکل</th>
      <th align="right">فرمت لینک</th>
      <th align="right">توضیحات</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>VLESS</b></td>
      <td dir="ltr" align="left"><code>vless://uuid@server:port?params</code></td>
      <td>پشتیبانی در هر دو ابزار</td>
    </tr>
    <tr>
      <td><b>VMess</b></td>
      <td dir="ltr" align="left"><code>vmess://base64-json</code></td>
      <td>فقط Chain Builder</td>
    </tr>
    <tr>
      <td><b>Trojan</b></td>
      <td dir="ltr" align="left"><code>trojan://password@server:port?params</code></td>
      <td>پشتیبانی در هر دو ابزار</td>
    </tr>
    <tr>
      <td><b>Shadowsocks</b></td>
      <td dir="ltr" align="left"><code>ss://base64(method:pass)@server:port</code></td>
      <td>فقط Chain Builder — عدم پشتیبانی از transport&rlm; (مانند ws&rlm;، grpc&rlm; و غیره) و همچنین فاقد پشتیبانی از TLS&rlm;.</td>
    </tr>
    <tr>
      <td><b>SOCKS</b></td>
      <td dir="ltr" align="left"><code>socks://user:pass@server:port</code></td>
      <td>فقط Chain Builder — باید شامل نام کاربری و رمز عبور باشد.</td>
    </tr>
    <tr>
      <td><b>HTTP</b></td>
      <td dir="ltr" align="left"><code>http://user:pass@server:port</code></td>
      <td>فقط Chain Builder — باید شامل نام کاربری و رمز عبور باشد.</td>
    </tr>
    <tr>
      <td><b>SSH</b></td>
      <td>دارای ۴ فیلد (سرور، پورت، نام کاربری، رمز عبور)</td>
      <td>فقط Chain Builder — <b>فقط برای Sing-box&rlm;</b> — توسط Xray&rlm; پشتیبانی نمی‌شود.</td>
    </tr>
  </tbody>
</table>

## ⚠️ نکات مهم

<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li>ابزار <b>Fragment + Fingerprint</b> فقط از لینک‌های <b>VLESS</b> و <b>Trojan</b> پشتیبانی می‌کند.</li>
  <li><b>TLS الزامی است</b>: ابزار <b>Fragment + Fingerprint</b> فقط با کانفیگ‌هایی کار می‌کند که <b>TLS</b> فعال داشته باشند (امنیت <code>tls</code> یا <code>reality</code>). کانفیگ‌های غیر TLS پشتیبانی نمی‌شوند و کار نخواهند کرد.</li>
  <li>پارامترهای <b>cs</b> (Cipher Suites) و <b>fm</b> (Final Mask) فقط زمانی اضافه می‌شوند که کانفیگ از امنیت <b>tls</b> استفاده کند.</li>
  <li>کانفیگ‌های <b>SOCKS</b> و <b>HTTP</b> باید حتماً دارای <b>نام کاربری و رمز عبور</b> باشند.</li>
  <li>هسته <b>Xray</b> از کانفیگ‌های <b>raw</b> (بدون هدر TCP&rlm;) پشتیبانی نمی‌کند؛ به‌جای آن باید از TCP&rlm; با هدر http&rlm; استفاده کرد.</li>
  <li>کانفیگ‌های <b>Shadowsocks</b> نمی‌توانند هیچ نوع transport&rlm; (مانند WebSocket&rlm;، gRPC&rlm;، HTTPUpgrade&rlm; و غیره) داشته باشند و فاقد قابلیت TLS&rlm; هستند.</li>
  <li>پروتکل <b>SSH</b> تنها توسط <b>Sing-box</b> پشتیبانی می‌شود. زمانی که از SSH&rlm; استفاده می‌کنید، تب مربوط به Xray&rlm; به‌صورت خودکار غیرفعال خواهد شد. برای استفاده از آن، لطفاً کلاینت <a href="https://sing-box.sagernet.org/">sing-box&rlm;</a> را به کار ببرید.</li>
</ul>

## 🔧 انتقال‌های (Transports) پشتیبانی‌شده

TCP، TCP (http header)، WebSocket، gRPC، HTTPUpgrade

## 🔒 پروتکل‌های رمزنگاری (TLS) پشتیبانی‌شده

TLS، Reality، None

## 📦 تکنولوژی‌های استفاده‌شده

<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li><b>HTML5</b>: ساختار معنایی.</li>
  <li><b>CSS3</b>: متغیرهای سفارشی، افکت‌های شیشه‌ای (Glassmorphism) و انیمیشن‌ها.</li>
  <li><b>JavaScript</b>: منطق اصلی برای پارس لینک، ارتقای کانفیگ و تولید JSON.</li>
</ul>

## 🛡️ کردیت‌ها (Credits)

<ul dir="rtl" style="direction: rtl; text-align: right;">
  <li>منطق ارتقای <b>Fragment + Fingerprint</b> (افزودن پارامترهای <code>cs</code> / <code>fm</code> / <code>fp</code> و فرمت خروجی لینک) بر اساس رفتار «Export to Clipboard» پروژه‌ی <a href="https://github.com/patterniha/PattNG">PattNG</a> طراحی شده است.</li>
  <li>ابزار <b>Chain Builder</b> از منطق و ساختار پروژه متن‌باز <a href="https://github.com/bia-pain-bache/BPB-Worker-Panel">BPB-Worker-Panel</a> و این <a href="https://gist.github.com/alireza-delavari/62e56af0d59c92b5b1798f1442f90f61">تنظیمات Sing-box</a> ایده گرفته است.</li>
</ul>

---
توسعه‌یافته با ❤️ برای حریم خصوصی شما.