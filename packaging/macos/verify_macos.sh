#!/usr/bin/env bash
# Verify every macOS distribution format of one FileSec variant *after*
# packaging (audit FS-13): the executable inside the portable archive, the app
# bundle inside the .dmg, and the .dmg itself.
#
# Usage: verify_macos.sh <portable.tar.gz> <installer.dmg>
#
# With RELEASE_SIGNING_REQUIRED=1 (official upstream tags) every artifact must
# carry a valid Developer ID signature with a team identifier and the hardened
# runtime, the app must pass Gatekeeper assessment, and the .dmg must have a
# valid stapled notarization ticket; any gap fails the release. Without the flag
# (forks, development runs) the same checks only warn.
set -euo pipefail

archive="${1:?portable archive}"
dmg="${2:?dmg}"
required="${RELEASE_SIGNING_REQUIRED:-}"
status=0

problem() {
  if [[ "$required" == "1" ]]; then
    echo "ERROR: $*" >&2
    status=1
  else
    echo "WARNING: $*" >&2
  fi
}

# A Developer ID signature with a team and the hardened runtime.
check_signed() {
  local what="$1" target="$2" details
  if ! codesign --verify --strict --verbose=2 "$target"; then
    problem "$what: code signature does not verify"
    return
  fi
  details="$(codesign -dvv "$target" 2>&1 || true)"
  grep -q '^Authority=Developer ID Application' <<<"$details" ||
    problem "$what: not signed with a Developer ID Application certificate"
  if grep -q '^TeamIdentifier=not set' <<<"$details" ||
    ! grep -q '^TeamIdentifier=' <<<"$details"; then
    problem "$what: no team identifier (ad-hoc signature)"
  fi
  grep -Eq '^CodeDirectory .*flags=.*runtime' <<<"$details" ||
    problem "$what: hardened runtime not enabled"
}

work="$(mktemp -d)"
mount_point="$work/dmg"
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  if [[ -d "$mount_point" ]]; then
    hdiutil detach "$mount_point" -quiet >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

# 1. The portable archive's executable — exactly what users unpack.
mkdir -p "$work/archive"
tar -xzf "$archive" -C "$work/archive"
# (A while-read loop rather than mapfile: macOS ships bash 3.2.)
found=0
while IFS= read -r exe; do
  found=1
  check_signed "archive executable $(basename "$exe")" "$exe"
done < <(find "$work/archive" -type f -perm -u+x)
if [[ "$found" -eq 0 ]]; then
  echo "ERROR: no executable in $archive" >&2
  exit 1
fi

# 2. The .dmg signature and its stapled notarization ticket.
codesign --verify --verbose=2 "$dmg" || problem "dmg: code signature does not verify"
xcrun stapler validate "$dmg" || problem "dmg: no valid stapled notarization ticket"

# 3. The app bundle inside the .dmg, including Gatekeeper's verdict.
mkdir -p "$mount_point"
hdiutil attach "$dmg" -readonly -nobrowse -mountpoint "$mount_point" -quiet
app="$(find "$mount_point" -maxdepth 1 -name '*.app' -print -quit)"
if [[ -z "$app" ]]; then
  echo "ERROR: no .app inside $dmg" >&2
  exit 1
fi
check_signed "app bundle $(basename "$app")" "$app"
spctl --assess --type execute --verbose=2 "$app" || problem "app bundle: rejected by Gatekeeper"

if [[ "$status" -eq 0 ]]; then
  echo "macOS distributions verified: $(basename "$archive"), $(basename "$dmg")"
fi
exit "$status"
