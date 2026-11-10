#!/usr/bin/env bash
# install.sh — build credsd and put it on PATH.
#
# Usage:
#   ./scripts/install.sh             # debug build (default)
#   ./scripts/install.sh --release   # optimized build
#
# Env: BINDIR=/usr/local/bin        destination directory
#      FEATURES=                     extra cargo features. The enclave is in the default set,
#                                    so a Mac that has one needs nothing here. One without
#                                    (a VM, pre-T2 Intel) needs FEATURES=file: an unsigned
#                                    build has no other storage backend there.
#
# Requires: cargo, and write access to BINDIR (sudo is used when it is not).
#
# Installs a symlink rather than a copy, so rebuilds land behind the link and
# every *client* invocation picks them up with no reinstall. The tradeoff:
# `cargo clean` leaves the link dangling. Re-run this.
#
# The service does not use this link. `sudo credsd install` will not run the
# daemon from a path its owner can rewrite, so it stages a root-owned copy under
# /usr/local/libexec/credsd on Linux or /opt/credsd on macOS (both off PATH) and
# bakes that in, leaving this link for clients. That
# means a rebuild updates what you run interactively but NOT the service: re-run
# `sudo credsd install` to stage a new build behind it. `credsd status` prints
# the path the service actually uses; `sudo credsd uninstall` removes the copy.

set -euo pipefail

PROFILE=debug
BINDIR="${BINDIR:-/usr/local/bin}"

die() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

usage() {
    printf 'usage: %s [--release|--debug]\n' "$(basename "$0")"
    printf '  --release   build with optimizations (target/release)\n'
    printf '  --debug     build unoptimized (target/debug) [default]\n'
    printf '  BINDIR=     destination directory [%s]\n' "$BINDIR"
}

# ── args ──────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --release) PROFILE=release ;;
        --debug) PROFILE=debug ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown option: %s\n\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

# An unsigned macOS build cannot reach the data protection keychain, so the enclave is its only
# hardware-backed backend — which is why it is in the default feature set and nothing is added
# here.
FEATURES="${FEATURES-}"
CARGO_ARGS=()
[[ $PROFILE == release ]] && CARGO_ARGS+=(--release)
[[ -n $FEATURES ]] && CARGO_ARGS+=(--features "$FEATURES")

# ── build ─────────────────────────────────────────────────────────────────────
printf '▶  cargo build (%s%s)\n' "$PROFILE" "${FEATURES:+, features: $FEATURES}"
# The `+` form: bash 3.2 (macOS /bin/bash) treats an empty array as unset under `set -u`.
cargo build ${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"}

BINARY="$REPO_ROOT/target/$PROFILE/credsd"
[[ -x $BINARY ]] || die "build did not produce $BINARY"

# ── destination ───────────────────────────────────────────────────────────────
TARGET="$BINDIR/credsd"

# Writability has to be judged against the deepest ancestor that actually
# exists — testing -w on a path that is not there yet always fails, which would
# escalate to sudo for a BINDIR we could have created ourselves.
PROBE=$(cd "$BINDIR" 2>/dev/null && pwd || true)
if [[ -z $PROBE ]]; then
    PROBE="$BINDIR"
    while [[ -n $PROBE && ! -d $PROBE ]]; do
        PARENT=$(dirname "$PROBE")
        [[ $PARENT == "$PROBE" ]] && break
        PROBE="$PARENT"
    done
fi
SUDO=""
if [[ ! -w $PROBE ]]; then
    command -v sudo &>/dev/null || die "$PROBE is not writable and sudo is unavailable"
    printf '!  %s is not writable; escalating with sudo\n' "$PROBE"
    SUDO=sudo
fi
[[ -d $BINDIR ]] || $SUDO mkdir -p "$BINDIR"

if [[ -L $TARGET ]]; then
    printf '   replacing link → %s\n' "$(readlink "$TARGET")"
elif [[ -e $TARGET ]]; then
    printf '   replacing file %s\n' "$TARGET"
fi

# -n so an existing symlink is replaced, not dereferenced into.
$SUDO ln -sfn "$BINARY" "$TARGET"

# ── verify ────────────────────────────────────────────────────────────────────
printf '✓  %s → %s\n' "$TARGET" "$BINARY"
"$TARGET" --version

RESOLVED=$(command -v credsd 2>/dev/null || true)
if [[ -n $RESOLVED && $RESOLVED != "$TARGET" ]]; then
    printf '!  PATH resolves credsd to %s, which shadows %s\n' "$RESOLVED" "$TARGET"
elif [[ -z $RESOLVED ]]; then
    printf '!  %s is not on PATH\n' "$BINDIR"
fi

# A service installed from an earlier binary path keeps running the old one.
if [[ $OSTYPE == darwin* ]] && launchctl list com.amazon.aws.credsd.daemon &>/dev/null; then
    printf '   a credsd service is loaded — run `credsd install` to re-point it, `credsd status` to check\n'
fi
