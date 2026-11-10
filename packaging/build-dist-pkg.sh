#!/bin/bash
# Build the distribution credsd .pkg around Credsd.app. A standalone run produces an UNSIGNED
# .pkg for structural validation only.
#
# Usage:   packaging/build-dist-pkg.sh [VERSION]
# Env:     PRESIGNED_APP=<dir/Credsd.app>   package a signed bundle instead of building one.
#          The signed bundle already contains the signed client.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST="$SCRIPT_DIR/dist"

# Audit label for the installer receipt, not an App ID.
IDENTIFIER="com.amazon.aws.credsd.daemon"

# BundleIsVersionChecked is false so the pkg payload always overwrites whatever bundle is
# already installed, regardless of its version. Setting it true allows installd to skip the
# payload copy for a higher-versioned installed bundle while still running postinstall —
# which would let a locally-planted bundle survive a genuine pkg install. The cost is that
# an older pkg will downgrade a newer already-installed bundle; only root can invoke the
# installer, so that is an accepted trade-off.
VERSION="${1:-$(awk -F'"' '/^version = /{print $2; exit}' "$ROOT/crates/credsd-daemon/Cargo.toml")}"
[ -n "$VERSION" ] || { echo "could not determine version" >&2; exit 1; }

# Relative, so it resolves against the chosen destination's root. The bundle sits directly in
# Applications, as every other application does.
INSTALL_SUBPATH="Applications"
BUNDLE="Credsd.app"
LEGAL=(LICENSE NOTICE THIRD-PARTY-LICENSES.md)
OUT="$DIST/credsd-${VERSION}-unsigned.pkg"

STAGE="$(mktemp -d)"; BUILD="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$BUILD"' EXIT

if [ -n "${PRESIGNED_APP:-}" ]; then
  # The signed bundle already contains the signed client, sealed by the bundle's own signature.
  [ -d "$PRESIGNED_APP" ] || { echo "PRESIGNED_APP not found: $PRESIGNED_APP" >&2; exit 1; }
  cp -R "$PRESIGNED_APP" "$STAGE/$BUNDLE"
else
  # Always, because a stale binary yields a .pkg that installs cleanly and behaves like an
  # earlier revision. Cargo is the authority on which crate a given source file affects, and a
  # no-op build costs about half a second — so there is nothing here to hand-roll.
  # Two invocations, because the two binaries want opposite answers about the enclave and
  # Cargo unifies features within one. The daemon drops it: this artifact's supported path is
  # `credsd install --user`, whose keystore is the data protection keychain the bundle's
  # provisioning profile authorizes, and compiling the enclave in would make `sudo credsd
  # install` resolve a backend and look supported. The client keeps it, because that is what
  # signs a presence challenge with Touch ID. `file` is deliberately absent from both.
  ( cd "$ROOT" && cargo build --release -p credsd-daemon --no-default-features )
  ( cd "$ROOT" && cargo build --release -p creds )
  "$SCRIPT_DIR/assemble-app.sh" \
    "$ROOT/target/release/credsd" "$ROOT/target/release/creds" "$STAGE" "$VERSION"
fi
[ -x "$STAGE/$BUNDLE/Contents/Resources/creds" ] \
  || { echo "payload is missing Contents/Resources/creds" >&2; exit 1; }
# Also for a PRESIGNED_APP, which an older assemble-app.sh may have built without them.
for f in "${LEGAL[@]}"; do
  [ -s "$STAGE/$BUNDLE/Contents/Resources/$f" ] \
    || { echo "payload is missing Contents/Resources/$f" >&2; exit 1; }
done

# The payload root maps to Applications, which always exists, so installd never applies the
# recorded root mode to it. The bundle's own mode is the one that lands.
chmod 0755 "$STAGE" "$STAGE/$BUNDLE"

chmod +x "$SCRIPT_DIR/dist-scripts/postinstall"

# BundleIsRelocatable defaults to true for an inferred bundle component, which makes installd
# install over an existing copy of the same CFBundleIdentifier and ignore --install-location.
# pkgbuild has no flag for it.
cat > "$BUILD/component.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <dict>
        <key>BundleHasStrictIdentifier</key><true/>
        <key>BundleIsRelocatable</key><false/>
        <key>BundleIsVersionChecked</key><false/>
        <!-- upgrade: always overwrites an existing bundle; an older pkg can downgrade a newer
             already-installed bundle. Only root can invoke the installer, so this is an
             accepted trade-off. -->
        <key>BundleOverwriteAction</key><string>upgrade</string>
        <key>RootRelativeBundlePath</key><string>${BUNDLE}</string>
    </dict>
</array>
</plist>
PLIST

pkgbuild \
  --root "$STAGE" \
  --component-plist "$BUILD/component.plist" \
  --scripts "$SCRIPT_DIR/dist-scripts" \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  --install-location "$INSTALL_SUBPATH" \
  "$BUILD/credsd-component.pkg"

install -d -m 0755 "$BUILD/resources"
# From the staged bundle, so the pane shows the same bytes the install places.
install -m 0644 "$STAGE/$BUNDLE/Contents/Resources/LICENSE" "$BUILD/resources/LICENSE.txt"
cat > "$BUILD/resources/conclusion.html" <<'HTML'
<!DOCTYPE html>
<html><body style="font-family:-apple-system,sans-serif;font-size:13px">
<p><b>credsd is installed and the background service is running.</b></p>
<p>The service is user-scoped: secrets live in your home directory, under your own
account, where any process running as you can read the sealed blobs.</p>
<p>Open a new terminal window and set up your credentials once:</p>
<p style="font-family:ui-monospace,monospace">creds bootstrap</p>
<p>If you installed for all users of this computer, the service belongs to your
account alone. Every other account on this Mac starts its own, once, with
<span style="font-family:ui-monospace,monospace">credsd install --user</span>.</p>
</body></html>
HTML

cat > "$BUILD/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>credsd</title>
    <license file="LICENSE.txt" mime-type="text/plain"/>
    <conclusion file="conclusion.html" mime-type="text/html"/>
    <domains enable_anywhere="false" enable_currentUserHome="true" enable_localSystem="true"/>
    <options customize="never" require-scripts="true" hostArchitectures="arm64"/>
    <choices-outline>
        <line choice="default"><line choice="${IDENTIFIER}"/></line>
    </choices-outline>
    <choice id="default"/>
    <choice id="${IDENTIFIER}" visible="false"><pkg-ref id="${IDENTIFIER}"/></choice>
    <pkg-ref id="${IDENTIFIER}" version="${VERSION}" onConclusion="none">credsd-component.pkg</pkg-ref>
</installer-gui-script>
XML

mkdir -p "$DIST"
productbuild --distribution "$BUILD/distribution.xml" --package-path "$BUILD" \
  --resources "$BUILD/resources" "$OUT"

echo "built (UNSIGNED): $OUT"
FILES="$(pkgutil --payload-files "$OUT")"
echo "$FILES" | grep -qx "./$BUNDLE/Contents/MacOS/credsd" \
  || { echo "self-check FAILED: the daemon is not in the payload" >&2; exit 1; }
echo "$FILES" | grep -qx "./$BUNDLE/Contents/Resources/creds" \
  || { echo "self-check FAILED: the client is not inside the bundle" >&2; exit 1; }
for f in "${LEGAL[@]}"; do
  echo "$FILES" | grep -qx "./$BUNDLE/Contents/Resources/$f" \
    || { echo "self-check FAILED: $f is not in the payload" >&2; exit 1; }
done

RELOC="$(mktemp -d)"; trap 'rm -rf "$STAGE" "$BUILD" "$RELOC"' EXIT
pkgutil --expand "$OUT" "$RELOC/x"

grep -q '<license file="LICENSE.txt"' "$RELOC/x/Distribution" \
  || { echo "self-check FAILED: the installer declares no license pane" >&2; exit 1; }
[ -s "$RELOC/x/Resources/LICENSE.txt" ] \
  || { echo "self-check FAILED: the license pane's text is missing from the package" >&2; exit 1; }

# From the expanded package, so a --scripts directory other than this repo's is still checked.
# Comments are stripped so a script may explain the rule.
SCRIPT_BODY="$(sed 's/#.*//' "$RELOC"/x/credsd-component.pkg/Scripts/*)"
for forbidden in /Library/LaunchAgents /Library/LaunchDaemons; do
  if printf '%s' "$SCRIPT_BODY" | grep -q -- "$forbidden"; then
    echo "self-check FAILED: package scripts reference '$forbidden'; the service this" >&2
    echo "installer registers is user-scoped, in one account's own LaunchAgents" >&2
    exit 1
  fi
done

printf '%s' "$SCRIPT_BODY" | grep -q -- 'install --user --skip-security-warning' || {
  echo "self-check FAILED: package scripts do not register the user-scoped service" >&2
  exit 1
}
printf '%s' "$SCRIPT_BODY" | grep -q -- 'launchctl asuser' || {
  echo "self-check FAILED: package scripts do not hand a root install to the console" >&2
  echo "user's session; root cannot load the agent or mint the keychain item itself" >&2
  exit 1
}

if grep -q '<relocate>' "$RELOC/x/credsd-component.pkg/PackageInfo"; then
  echo "self-check FAILED: bundle is relocatable; installd would ignore the install location" >&2
  exit 1
fi

# When BundleIsVersionChecked=true, installd skips the payload write for a higher-versioned
# bundle while still running postinstall as root — the install-time substitution vector.
if grep -q '<bundle-version>' "$RELOC/x/credsd-component.pkg/PackageInfo"; then
  echo "self-check FAILED: PackageInfo contains bundle-version entries; BundleIsVersionChecked must be false" >&2
  exit 1
fi

# The bundle's own mode, not the payload root's: the root maps to Applications, which exists, so
# installd never applies the recorded root mode. A 0700 bundle would be unreachable under
# -target / while working fine under -target CurrentUserHomeDirectory.
BUNDLE_MODE="$(lsbom -p Mf "$RELOC/x/credsd-component.pkg/Bom" \
  | awk -F'\t' -v b="./$BUNDLE" '$2 == b { print $1 }')"
case "$BUNDLE_MODE" in
  drwxr-xr-x*) ;;
  *) echo "self-check FAILED: $BUNDLE is $BUNDLE_MODE, expected drwxr-xr-x" >&2; exit 1 ;;
esac

# Nothing inside the bundle is a PATH entry: the installer symlinks into a bin directory that
# is already on PATH. A bin/ directory here would mean that decision had been reverted halfway.
if echo "$FILES" | grep -q "^./$BUNDLE/Contents/Resources/bin"; then
  echo "self-check FAILED: the bundle has a Resources/bin directory; PATH access is by" >&2
  echo "symlink into /usr/local/bin or ~/.local/bin, not by a directory inside the bundle" >&2
  exit 1
fi

# Read off the packaged daemon, so a PRESIGNED_APP built some other way is checked too. The list
# is exact, and `secure-enclave` being absent is the point: with it compiled in, `sudo credsd
# install` from this artifact resolves a backend and installs a LaunchDaemon that can never
# reach the keychain this bundle exists to authorize. `file` is a regression for the same
# reason it always was.
pkgutil --expand-full "$OUT" "$RELOC/full"
BACKENDS="$("$RELOC/full/credsd-component.pkg/Payload/$BUNDLE/Contents/MacOS/credsd" --version \
  | grep '^storage backends: ')"
[ "$BACKENDS" = "storage backends: data-protection-keychain" ] || {
  echo "self-check FAILED: packaged daemon reports '$BACKENDS'; the official build ships" >&2
  echo "exactly data-protection-keychain" >&2
  exit 1
}

# Derived from the packaged binaries rather than compared to a literal: a host architecture
# the binaries were not built for installs cleanly and then cannot execute.
PKG_BIN="$RELOC/full/credsd-component.pkg/Payload/$BUNDLE/Contents"
archs_of() {
  lipo -archs "$1" | tr ' ' '\n' | sort -u | paste -sd, -
}
DAEMON_ARCHS="$(archs_of "$PKG_BIN/MacOS/credsd")"
CLIENT_ARCHS="$(archs_of "$PKG_BIN/Resources/creds")"
[ "$DAEMON_ARCHS" = "$CLIENT_ARCHS" ] || {
  echo "self-check FAILED: the daemon is '$DAEMON_ARCHS' and the client '$CLIENT_ARCHS';" >&2
  echo "one install places both, so a host that runs one must run the other" >&2
  exit 1; }
DECLARED="$(sed -n 's/.*hostArchitectures="\([^"]*\)".*/\1/p' "$RELOC/x/Distribution" \
  | tr ',' '\n' | sort -u | paste -sd, -)"
[ "$DECLARED" = "$DAEMON_ARCHS" ] || {
  echo "self-check FAILED: the installer accepts hosts '${DECLARED:-<none>}' but the packaged" >&2
  echo "binaries are '$DAEMON_ARCHS'; a host it accepts could not run them" >&2
  exit 1; }

DESTINATIONS="$(installer -dominfo -pkg "$OUT")"
for d in LocalSystem CurrentUserHomeDirectory; do
  echo "$DESTINATIONS" | grep -qx "$d" \
    || { echo "self-check FAILED: $d is not an enabled install destination" >&2; exit 1; }
done

echo "payload OK ($BUNDLE with MacOS/credsd + Resources/creds + ${LEGAL[*]}), destinations: $(echo "$DESTINATIONS" | tr '\n' ' ')"
echo "  sudo installer -pkg $(basename "$OUT") -target /   # /Applications/$BUNDLE + /usr/local/bin links"
echo "       installer -pkg $(basename "$OUT") -target CurrentUserHomeDirectory  # ~/Applications/$BUNDLE + ~/.local/bin links"
echo "Both register the user-scoped service: directly for a private install, and through"
echo "'launchctl asuser' for a root install with a console user. With no console user the"
echo "install places files only, and 'credsd install --user' remains the customer's step."
echo "This .pkg must be signed before distributing."
