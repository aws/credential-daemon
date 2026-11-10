#!/bin/bash
# Assemble the UNSIGNED Credsd.app structure around the daemon and client binaries.
#
# The daemon needs a keychain-access-groups entitlement authorized by a provisioning profile,
# and a profile can only be embedded in an app-like bundle — so the daemon must execute from
# inside this bundle at runtime. A copy outside it loses the entitlement.
#
# The client lives in Contents/Resources. Nothing inside the bundle goes on PATH; the installer
# symlinks both commands into a bin directory that is already there.
#
# Usage:
#   packaging/assemble-app.sh <daemon-binary> <client-binary> <output-dir> [VERSION]
# Produces:
#   <output-dir>/Credsd.app/Contents/MacOS/credsd
#   <output-dir>/Credsd.app/Contents/Resources/creds
#   <output-dir>/Credsd.app/Contents/Resources/{LICENSE,NOTICE,THIRD-PARTY-LICENSES.md}
#   <output-dir>/Credsd.app/Contents/Info.plist
#
# The legal files are read from the repository root beside this script's directory, which is
# also the layout the signing stage unzips, so they are the same commit's as the binaries.
set -euo pipefail

# Must match the registered App ID the provisioning profile is bound to.
IDENTIFIER="com.amazon.aws.credsd.daemon"
BUNDLE_NAME="Credsd"
EXECUTABLE="credsd"
CLIENT="creds"

USAGE="usage: assemble-app.sh <daemon-binary> <client-binary> <output-dir> [VERSION]"
DAEMON_BIN="${1:?$USAGE}"
CLIENT_BIN="${2:?$USAGE}"
OUT_DIR="${3:?$USAGE}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE="$SCRIPT_DIR/Credsd.app.Info.plist.in"
LEGAL=(LICENSE NOTICE THIRD-PARTY-LICENSES.md)

VERSION="${4:-$(awk -F'"' '/^version = /{print $2; exit}' \
  "$SCRIPT_DIR/../crates/credsd-daemon/Cargo.toml")}"
[ -n "$VERSION" ] || { echo "could not determine version" >&2; exit 1; }

[ -f "$DAEMON_BIN" ] || { echo "missing daemon binary: $DAEMON_BIN" >&2; exit 1; }
[ -f "$CLIENT_BIN" ] || { echo "missing client binary: $CLIENT_BIN" >&2; exit 1; }
[ -f "$TEMPLATE" ]   || { echo "missing plist template: $TEMPLATE" >&2; exit 1; }
for f in "${LEGAL[@]}"; do
  [ -s "$ROOT/$f" ] || { echo "missing or empty legal file: $ROOT/$f" >&2; exit 1; }
done

APP="$OUT_DIR/$BUNDLE_NAME.app"
rm -rf "$APP"
install -d -m 0755 "$APP/Contents/MacOS" "$APP/Contents/Resources"

install -m 0755 "$DAEMON_BIN" "$APP/Contents/MacOS/$EXECUTABLE"
install -m 0755 "$CLIENT_BIN" "$APP/Contents/Resources/$CLIENT"

for f in "${LEGAL[@]}"; do
  install -m 0644 "$ROOT/$f" "$APP/Contents/Resources/$f"
done

sed -e "s/@IDENTIFIER@/$IDENTIFIER/g" \
    -e "s/@BUNDLE_NAME@/$BUNDLE_NAME/g" \
    -e "s/@EXECUTABLE@/$EXECUTABLE/g" \
    -e "s/@VERSION@/$VERSION/g" \
    "$TEMPLATE" > "$APP/Contents/Info.plist"

grep -q "<string>$IDENTIFIER</string>" "$APP/Contents/Info.plist" \
  || { echo "self-check FAILED: CFBundleIdentifier != $IDENTIFIER" >&2; exit 1; }
[ -x "$APP/Contents/MacOS/$EXECUTABLE" ] \
  || { echo "self-check FAILED: missing/execless Contents/MacOS/$EXECUTABLE" >&2; exit 1; }
[ -x "$APP/Contents/Resources/$CLIENT" ] \
  || { echo "self-check FAILED: missing/execless Contents/Resources/$CLIENT" >&2; exit 1; }
for f in "${LEGAL[@]}"; do
  [ -s "$APP/Contents/Resources/$f" ] \
    || { echo "self-check FAILED: missing Contents/Resources/$f" >&2; exit 1; }
done

echo "assembled: $APP"
