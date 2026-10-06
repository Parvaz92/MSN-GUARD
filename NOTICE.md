# NOTICE

**Parvaz VPN** is a modified version of **MSN-GUARD**.

- Original work: MSN-GUARD, Copyright (C) its authors — https://github.com/mbm110/MSN-GUARD
- Modified work: Parvaz VPN, Copyright (C) 2026 Parvaz92 — https://github.com/Parvaz92/MSN-GUARD

Both are licensed under the **GNU Affero General Public License v3.0** (see [LICENSE](LICENSE)).
Vendored third-party components keep their own licenses as listed in the original README
(quiche, badvpn, lwIP, Psiphon, Tor, lyrebird).

## Modifications (2026-10-06)

- New name ("Parvaz VPN"), application ID (`com.parvaz.vpn`) and artwork (`branding/`).
- Build-time rebrand script `tools/rebrand.sh`, run by Gradle before every build.
- In-app update check points to this fork's GitHub Releases.
- Release builds fall back to the debug signing key when no release key is configured.

The network core, transports and server data feeds are unchanged from upstream.
"MSN-GUARD" and its logo belong to their respective owners; Parvaz VPN is an independent
project and is not affiliated with or endorsed by the MSN-GUARD authors.
