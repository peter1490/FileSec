#!/usr/bin/env bash
# Build a signed, notarized macOS .dmg for one FileSec variant.
#
# Assembles a minimal .app bundle around an already-built (ideally universal)
# binary, code-signs it with a Developer ID Application certificate, packages it
# into a .dmg, then submits the .dmg for notarization and staples the ticket.
#
# Signing and notarization are SKIPPED (a plain, unsigned .dmg is still produced)
# when the corresponding credentials are absent — so the workflow runs end-to-end
# on a fork without Apple secrets, and a maintainer with certificates gets fully
# signed output. See RELEASE.md for the required secrets.
#
# Required env:
#   BIN_PATH      path to the built binary (e.g. target/universal/filesec)
#   APP_NAME      bundle/display name (e.g. "FileSec" or "FileSec (post-quantum)")
#   BUNDLE_ID     CFBundleIdentifier (e.g. dev.FileSec.FileSec)
#   VERSION       version string (e.g. 0.1.0)
#   OUT_DMG       output .dmg path
# Optional (signing): MACOS_SIGN_IDENTITY  (Developer ID Application: ... (TEAMID))
# Optional (notarization, pick ONE method):
#   API key:  AC_API_KEY_PATH  AC_API_KEY_ID  AC_API_ISSUER
#   Apple ID: AC_APPLE_ID      AC_APP_PASSWORD AC_TEAM_ID
set -euo pipefail

: "${BIN_PATH:?}" "${APP_NAME:?}" "${BUNDLE_ID:?}" "${VERSION:?}" "${OUT_DMG:?}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
app="$workdir/${APP_NAME}.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

# The executable inside the bundle keeps a stable, space-free name.
exe_name="$(basename "$BIN_PATH")"
cp "$BIN_PATH" "$app/Contents/MacOS/$exe_name"
chmod 755 "$app/Contents/MacOS/$exe_name"

# Bundle the app icon. Resolve it relative to this script so the lookup does
# not depend on the caller's working directory. A missing icon is non-fatal
# (matching the optional-signing philosophy) but warns loudly; without it the
# .app falls back to the generic placeholder icon in Finder.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
icon_src="$script_dir/../../crates/filesec-gui/assets/icon/AppIcon.icns"
icon_plist=""
if [[ -f "$icon_src" ]]; then
  cp "$icon_src" "$app/Contents/Resources/AppIcon.icns"
  icon_plist="  <key>CFBundleIconFile</key>       <string>AppIcon</string>"
else
  echo "WARNING: app icon not found at $icon_src — bundling without an icon." >&2
fi

cat >"$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>            <string>${APP_NAME}</string>
  <key>CFBundleDisplayName</key>     <string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key>      <string>${BUNDLE_ID}</string>
  <key>CFBundleExecutable</key>      <string>${exe_name}</string>
  <key>CFBundleVersion</key>         <string>${VERSION}</string>
  <key>CFBundleShortVersionString</key> <string>${VERSION}</string>
  <key>CFBundlePackageType</key>     <string>APPL</string>
${icon_plist}
  <key>LSMinimumSystemVersion</key>  <string>11.0</string>
  <key>NSHighResolutionCapable</key> <true/>
</dict>
</plist>
PLIST

# --- Code signing (optional) ---------------------------------------------
if [[ -n "${MACOS_SIGN_IDENTITY:-}" ]]; then
  echo "Signing $app with: $MACOS_SIGN_IDENTITY"
  # Hardened runtime + secure timestamp are required for notarization.
  codesign --force --deep --options runtime --timestamp \
    --sign "$MACOS_SIGN_IDENTITY" "$app"
  codesign --verify --strict --verbose=2 "$app"
else
  echo "WARNING: MACOS_SIGN_IDENTITY not set — producing an UNSIGNED .dmg." >&2
fi

# --- Build the .dmg -------------------------------------------------------
stage="$(mktemp -d)"
trap 'rm -rf "$workdir" "$stage"' EXIT
cp -R "$app" "$stage/"
ln -s /Applications "$stage/Applications"
rm -f "$OUT_DMG"
hdiutil create -volname "$APP_NAME" -srcfolder "$stage" -ov -format UDZO "$OUT_DMG"

if [[ -n "${MACOS_SIGN_IDENTITY:-}" ]]; then
  codesign --force --sign "$MACOS_SIGN_IDENTITY" "$OUT_DMG"
fi

# --- Notarize + staple (optional) ----------------------------------------
notarize() {
  if [[ -n "${AC_API_KEY_PATH:-}" && -n "${AC_API_KEY_ID:-}" && -n "${AC_API_ISSUER:-}" ]]; then
    xcrun notarytool submit "$OUT_DMG" --wait \
      --key "$AC_API_KEY_PATH" --key-id "$AC_API_KEY_ID" --issuer "$AC_API_ISSUER"
  elif [[ -n "${AC_APPLE_ID:-}" && -n "${AC_APP_PASSWORD:-}" && -n "${AC_TEAM_ID:-}" ]]; then
    xcrun notarytool submit "$OUT_DMG" --wait \
      --apple-id "$AC_APPLE_ID" --password "$AC_APP_PASSWORD" --team-id "$AC_TEAM_ID"
  else
    return 1
  fi
}

if [[ -n "${MACOS_SIGN_IDENTITY:-}" ]] && notarize; then
  xcrun stapler staple "$OUT_DMG"
  echo "Notarized and stapled: $OUT_DMG"
else
  echo "WARNING: skipping notarization (no credentials or unsigned)." >&2
fi

echo "Created: $OUT_DMG"
