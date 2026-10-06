<div align="center">

<img src="docs/parvaz-logo.svg" width="160" alt="Parvaz VPN">

# Parvaz VPN · پرواز

**فیلترشکن اندرویدی برای کل دستگاه، بر پایه‌ی MSN-GUARD**

[![License](https://img.shields.io/badge/license-AGPL--3.0-6c5ce7?style=for-the-badge)](LICENSE)

**فارسی** · [English](README.en.md)

</div>

---

## این چیه؟

Parvaz VPN یک کلاینت VPN بومی اندروید است که کل ترافیک گوشی را از یک تونل امن عبور می‌دهد.
این پروژه یک **نسخه‌ی تغییریافته از [MSN-GUARD](https://github.com/mbm110/MSN-GUARD)** است و هسته‌ی شبکه
(Rust)، ترنسپورت‌ها (MASQUE/HTTP-3، WireGuard، WARP-on-WARP، Psiphon، Tor) و منطق اتصال آن بدون تغییر باقی مانده‌اند.
تغییرات فقط برند، آیکون، شناسه‌ی برنامه و مسیر آپدیت هستند.

## نصب

فایل APK را از بخش [Releases](https://github.com/Parvaz92/MSN-GUARD/releases) یا از Artifacts در
[Actions](https://github.com/Parvaz92/MSN-GUARD/actions) دانلود کنید. اندروید ۸ یا بالاتر لازم است.

| معماری گوشی | فایل |
|---|---|
| ۶۴ بیتی (بیشتر گوشی‌های امروزی) | `app-arm64-v8a-release.apk` |
| ۳۲ بیتی (گوشی‌های قدیمی) | `app-armeabi-v7a-release.apk` |

Parvaz VPN شناسه‌ی جداگانه (`com.parvaz.vpn`) دارد و کنار MSN-GUARD اصلی هم نصب می‌شود.

## ساخت از سورس

```bash
./gradlew assembleDebug -PtargetAbi=arm64-v8a,armeabi-v7a
```

Gradle قبل از هر بیلد خودکار `tools/rebrand.sh` را اجرا می‌کند (برای ساخت لوگو `librsvg2-bin` لازم است).
پیش‌نیازها همان پیش‌نیازهای پروژه‌ی اصلی است: JDK 17، Android SDK 36، NDK `26.3.11579264`، CMake `3.22.1`، Rust و `cargo-ndk`.
هر push روی `master` به‌طور خودکار APK می‌سازد.

## برند

همه‌ی برندینگ در دو جا است: پوشه‌ی `branding/` (لوگوها به صورت SVG) و اسکریپت `tools/rebrand.sh`.
برای عوض کردن اسم یا لوگو فقط همین‌ها را ویرایش کنید.

## لایسنس و قدردانی

این پروژه تحت لایسنس [GNU AGPL-3.0](LICENSE) منتشر می‌شود، همان لایسنس پروژه‌ی اصلی.
تمام اعتبار هسته‌ی فنی متعلق به سازنده‌ی **[MSN-GUARD](https://github.com/mbm110/MSN-GUARD)** است.
Parvaz VPN پروژه‌ای مستقل است و وابسته به سازندگان MSN-GUARD نیست. جزئیات تغییرات در [NOTICE.md](NOTICE.md).
