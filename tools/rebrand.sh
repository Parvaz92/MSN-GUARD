#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Yekta VPN build-time rebrand.
#
# Yekta VPN is a modified version of MSN-GUARD (https://github.com/mbm110/MSN-GUARD),
# licensed under the GNU Affero General Public License v3.0. This script swaps
# the user-visible name and artwork right before Gradle compiles, so the large
# upstream source files stay identical in git and upstream merges stay painless.
#
# Deliberately left untouched:
#   * raw.githubusercontent.com/mbm110/... feeds (node list, smart-split, policy)
#   * LogCipher.kt / SettingsBackup.kt: file-format markers, not branding
#   * Kotlin package com.msnguard.vpn and application ID com.parvaz.vpn, so existing
#     Yekta installations receive updates instead of becoming a second app
#   * Update checks are pointed at this fork's own GitHub Releases
#
# Gradle runs this automatically before every build. It is idempotent.
# Manual run: bash tools/rebrand.sh
# ---------------------------------------------------------------------------
set -euo pipefail

BRAND="${BRAND:-Yekta VPN}"
APP_ID="${APP_ID:-com.parvaz.vpn}"
REPO="${REPO:-Parvaz92/MSN-GUARD}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/app/src/main/java/com/msnguard/vpn"
RES="$ROOT/app/src/main/res"
ART="$ROOT/branding"

echo "==> Rebranding Android config"
perl -pi -e 's{android:label="MSN-GUARD"}{android:label="\@string/app_name"}' "$ROOT/app/src/main/AndroidManifest.xml"
for f in "$RES"/values*/strings.xml; do
  BRAND="$BRAND" perl -CSD -pi -e 's{MSN-GUARD}{$ENV{BRAND}}g' "$f"
done

echo "==> Rebranding Kotlin sources to '$BRAND' ($APP_ID)"
for f in "$SRC"/*.kt; do
  case "$(basename "$f")" in
    LogCipher.kt|SettingsBackup.kt) continue ;;
  esac
  BRAND="$BRAND" APP_ID="$APP_ID" REPO="$REPO" perl -CSD -pi -e '
    s{(?<![/\w.-])MSN-GUARD(?![\w-]*/)}{$ENV{BRAND}}g;
    s{"com\.msnguard\.vpn"}{"$ENV{APP_ID}"}g;
    s{mbm110/MSN-GUARD/releases}{$ENV{REPO}/releases}g;
  ' "$f"
done

# Add the two public channels to the home screen without hand-editing the very
# large upstream MainActivity. The marker makes this safe to run repeatedly.
python3 - "$ROOT/app/src/main/java/com/msnguard/vpn/MainActivity.kt" <<'PY'
from pathlib import Path
p = Path(__import__('sys').argv[1])
s = p.read_text()
marker = '        // YEKTA_SOCIAL_LINKS\n'
if marker not in s:
    s = s.replace('        // PARVAZ_SOCIAL_LINKS\n', marker, 1)
if marker not in s:
    needle = '''        addView(transportRail, LinearLayout.LayoutParams(\n'''
    insert = marker + '''        addView(ParvazSocialLinks.build(this@MainActivity), LinearLayout.LayoutParams(\n            ViewGroup.LayoutParams.MATCH_PARENT,\n            ViewGroup.LayoutParams.WRAP_CONTENT,\n        ).apply { topMargin = dp(10) })\n\n'''
    if needle not in s:
        raise SystemExit("home-screen insertion point not found")
    s = s.replace(needle, insert + needle, 1)
    p.write_text(s)
PY

echo "==> Rendering artwork"
if ! command -v rsvg-convert >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
  sudo -n apt-get update -qq >/dev/null 2>&1 && sudo -n apt-get install -y -qq librsvg2-bin >/dev/null 2>&1 || true
fi
if ! command -v rsvg-convert >/dev/null 2>&1; then
  echo "WARN: rsvg-convert not found (install librsvg2-bin); keeping existing artwork."
  exit 0
fi
rsvg-convert -w 432 -h 432 "$ART/icon_fg.svg" -o "$RES/drawable-nodpi/msnguard_icon_fg.png"
rsvg-convert -w 432 -h 432 "$ART/icon_bg.svg" -o "$RES/drawable-nodpi/msnguard_icon_bg.png"
rsvg-convert -w 512 -h 512 "$ART/splash.svg" -o "$RES/drawable-nodpi/msnguard_splash_logo.png"
rsvg-convert -w 512 -h 512 "$ART/icon_full.svg" -o "$RES/mipmap-nodpi/ic_launcher.png"
for pair in mdpi:48 hdpi:72 xhdpi:96 xxhdpi:144 xxxhdpi:192; do
  dpi="${pair%%:*}"; px="${pair##*:}"
  if [ -d "$RES/mipmap-$dpi" ]; then
    rsvg-convert -w "$px" -h "$px" "$ART/icon_full.svg" -o "$RES/mipmap-$dpi/ic_launcher.png"
  fi
done

echo "==> Rebrand done"
