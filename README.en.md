<div align="center">

<img src="docs/parvaz-logo.svg" width="160" alt="Yekta VPN">

# Yekta VPN

**Device-wide Android VPN, based on MSN-GUARD**

[![License](https://img.shields.io/badge/license-AGPL--3.0-6c5ce7?style=for-the-badge)](LICENSE)

[فارسی](README.md) · **English**

</div>

---

## What this is

Yekta VPN is a native Android VPN client that routes every app's traffic through one tunnel.
It is a **modified version of [MSN-GUARD](https://github.com/mbm110/MSN-GUARD)**: the Rust network core,
the transports (MASQUE/HTTP-3, WireGuard, WARP-on-WARP, Psiphon, Tor) and the connection logic are
unchanged. Only the name, artwork, application ID and update source differ. For the full technical
write-up, see the [upstream README](https://github.com/mbm110/MSN-GUARD#readme).

## Install

Download the APK from [Yekta VPN Releases](https://github.com/Parvaz92/Yekta-VPN/releases) or from the
[Yekta Actions](https://github.com/Parvaz92/Yekta-VPN/actions) artifacts. Android 8.0+.
Yekta VPN uses its own application ID (`com.parvaz.vpn`), so it installs alongside MSN-GUARD.

## Build from source

```bash
./gradlew assembleDebug -PtargetAbi=arm64-v8a,armeabi-v7a
```

Gradle runs `tools/rebrand.sh` automatically before every build (artwork needs `librsvg2-bin`).
Prerequisites match upstream: JDK 17, Android SDK 36, NDK `26.3.11579264`, CMake `3.22.1`, Rust stable and `cargo-ndk`.

## Privacy

Read the [Yekta VPN privacy policy](https://parvaz92.github.io/Yekta-VPN/privacy-policy.html).

## License

[GNU AGPL-3.0](LICENSE), same as upstream. All credit for the technical core goes to the
[MSN-GUARD](https://github.com/mbm110/MSN-GUARD) author. Yekta VPN is independent and not affiliated
with the MSN-GUARD authors. See [NOTICE.md](NOTICE.md) for the list of modifications.
