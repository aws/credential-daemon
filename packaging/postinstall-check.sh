#!/bin/bash
# Runs dist-scripts/postinstall against a fake bundle in a throwaway HOME and asserts what
# it did. Covers the non-root branch only: the root branch needs launchctl asuser and a
# console user, which no unprivileged test can stand up.
#
# Usage: packaging/postinstall-check.sh
set -euo pipefail

[ "$(id -u)" -ne 0 ] || { echo "run this as yourself, not root" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BUNDLE="$TMP/dest/Credsd.app"
BIN="$TMP/bin"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources" "$TMP/home" "$BIN"

cat > "$BUNDLE/Contents/MacOS/credsd" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> "$TMP/argv"
EOF
chmod +x "$BUNDLE/Contents/MacOS/credsd"
printf '#!/bin/bash\n' > "$BUNDLE/Contents/Resources/creds"
chmod +x "$BUNDLE/Contents/Resources/creds"

fail() { echo "FAILED: $*" >&2; exit 1; }

# A throwaway HOME does not isolate the shell lookup: postinstall reads the invoking
# account's own directory-service record, so without this the outcome would depend on
# whoever runs the test.
shim_login_shell() {
    printf '#!/bin/bash\necho "UserShell: %s"\n' "$1" > "$BIN/dscl"
    chmod +x "$BIN/dscl"
}

run_postinstall() {
    HOME="$1" PATH="$BIN:/usr/bin:/bin:/usr/sbin:/sbin" \
        bash "$SCRIPT_DIR/dist-scripts/postinstall" '' "$TMP/dest" > "$2" 2>&1
}

shim_login_shell /bin/zsh
run_postinstall "$TMP/home" "$TMP/out" \
    || fail "postinstall exited non-zero$(printf '\n'; cat "$TMP/out")"

[ "$(cat "$TMP/argv" 2>/dev/null)" = "install --user --skip-security-warning" ] \
    || fail "daemon was not invoked as 'install --user --skip-security-warning'; got: $(cat "$TMP/argv" 2>/dev/null)"

for name in credsd creds; do
    [ -L "$TMP/home/.local/bin/$name" ] || fail "no ~/.local/bin/$name symlink"
done
[ "$(readlink "$TMP/home/.local/bin/credsd")" = "$BUNDLE/Contents/MacOS/credsd" ] \
    || fail "credsd symlink does not point into the bundle"

grep -qF 'Added by credsd' "$TMP/home/.zprofile" || fail "PATH block was not appended"

# Reinstall: one PATH block, and registration runs again.
run_postinstall "$TMP/home" "$TMP/out2" || fail "second postinstall exited non-zero"
[ "$(grep -cF 'Added by credsd' "$TMP/home/.zprofile")" -eq 1 ] \
    || fail "repeated install stacked PATH blocks"
[ "$(wc -l < "$TMP/argv")" -eq 2 ] || fail "second install did not re-register"

# A bash login shell writes to the other startup file, and nowhere else.
mkdir -p "$TMP/home-bash"
shim_login_shell /bin/bash
run_postinstall "$TMP/home-bash" "$TMP/out-bash" || fail "bash-shell postinstall exited non-zero"
grep -qF 'Added by credsd' "$TMP/home-bash/.bash_profile" \
    || fail "PATH block was not appended to .bash_profile"
[ ! -e "$TMP/home-bash/.zprofile" ] || fail "a bash login shell should not get a .zprofile"

# An unsupported login shell: no startup file is written, and the install still succeeds.
mkdir -p "$TMP/home-fish"
shim_login_shell /opt/homebrew/bin/fish
run_postinstall "$TMP/home-fish" "$TMP/out-fish" || fail "fish-shell postinstall exited non-zero"
grep -q "is not supported" "$TMP/out-fish" || fail "unsupported login shell was not reported"
for rc in .zprofile .bash_profile .profile; do
    [ ! -e "$TMP/home-fish/$rc" ] || fail "wrote $rc for a shell that does not read it"
done

# A failing registration must not fail the install.
printf '#!/bin/bash\nexit 1\n' > "$BUNDLE/Contents/MacOS/credsd"
shim_login_shell /bin/zsh
run_postinstall "$TMP/home" "$TMP/out-failed" \
    || fail "a failed registration made the install fail"
grep -q "could not register the user service" "$TMP/out-failed" \
    || fail "a failed registration was not reported"

echo "postinstall check OK (non-root branch)"
