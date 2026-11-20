#!/usr/bin/env bash
# manylinux-toolchain.sh — build the tpm2-tss link dependencies inside a
# manylinux2014 container, for the `manylinux-*-tpm` rows of build.yml.
#
# Usage: scripts/manylinux-toolchain.sh      (as root, in the container)
#
# Installs OpenSSL into /opt/ossl and tpm2-tss into /opt/tss. Callers then set
# PKG_CONFIG_PATH=/opt/tss/lib/pkgconfig and LD_LIBRARY_PATH=/opt/tss/lib.
#
# None of it ships. tss-esapi-sys 0.6.0 carries pregenerated bindings for both
# Linux architectures, so the build needs only the four tss2 pkg-config files and
# their shared objects to link against; the host's own tpm2-tss is what the
# binary loads at run time.

set -euo pipefail

# No yum anywhere in here: vault.centos.org serves 403 for CentOS 7, so a package
# install makes the image unbuildable. --disable-fapi below drops libuuid, the
# only dependency that would have needed one.

# 1.1.1 rather than 3.x: OpenSSL 3's Configure needs the IPC::Cmd perl module,
# which this image lacks and yum cannot supply. 1.1.1 clears tpm2-tss's
# `libcrypto >= 1.1.0` floor, and nothing links it into a shipped binary.
OPENSSL_VERSION=1.1.1w
OPENSSL_RELEASE_TAG=OpenSSL_1_1_1w
OPENSSL_SHA256=cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8

# Matches the version AL2023 packages, so the link-time ABI is the one the
# pregenerated bindings were generated against.
TPM2_TSS_VERSION=4.0.2
TPM2_TSS_SHA256=e5f9b6055c29cb8d653ec7576853ff3863aa65dbd9cf4b3638ae8e8e7ce968ea

# Hardening. tpm2-tss's own --enable-defaultflags (the default; --disable- would
# remove it) already adds -fstack-protector-all and -z relro,now,noexecstack, but
# its AX_ADD_FORTIFY_SOURCE probe declines on this image even though the compiler
# accepts the flag, so FORTIFY is set here instead. OpenSSL's ./config applies no
# hardening of its own.
#
# None of this reaches a shipped binary — only the symbol shape of these libraries
# is used, at link time. It does cover the one place they execute: the tpm rows run
# `cargo test --features tpm` with LD_LIBRARY_PATH pointing here.
HARDEN_CPPFLAGS='-D_FORTIFY_SOURCE=2'
HARDEN_CFLAGS='-O2 -fstack-protector-strong'
HARDEN_LDFLAGS='-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack'

fetch() {
  curl -fsSLo "$3" "$1"
  echo "$2  $3" | sha256sum -c -
}

fetch "https://github.com/openssl/openssl/releases/download/$OPENSSL_RELEASE_TAG/openssl-$OPENSSL_VERSION.tar.gz" \
  "$OPENSSL_SHA256" /tmp/openssl.tar.gz
mkdir -p /tmp/openssl
tar -xzf /tmp/openssl.tar.gz -C /tmp/openssl --strip-components=1
cd /tmp/openssl
./config --prefix=/opt/ossl --libdir=lib no-tests shared \
  $HARDEN_CPPFLAGS $HARDEN_CFLAGS $HARDEN_LDFLAGS
make -s -j"$(nproc)" build_libs
make -s install_dev

fetch "https://github.com/tpm2-software/tpm2-tss/releases/download/$TPM2_TSS_VERSION/tpm2-tss-$TPM2_TSS_VERSION.tar.gz" \
  "$TPM2_TSS_SHA256" /tmp/tss.tar.gz
mkdir -p /tmp/tss
tar -xzf /tmp/tss.tar.gz -C /tmp/tss --strip-components=1
cd /tmp/tss
# --disable-policy as well as --disable-fapi: tss2-policy pulls json-c
# independently, and json-c is another package yum cannot supply.
# The rpath points this libtss2-esys at the OpenSSL above so the cargo link step
# needs no library-path environment of its own.
./configure \
  --prefix=/opt/tss \
  --libdir=/opt/tss/lib \
  --disable-static \
  --disable-fapi \
  --disable-policy \
  --disable-doxygen-doc \
  --disable-tcti-swtpm \
  --disable-tcti-mssim \
  --disable-tcti-cmd \
  PKG_CONFIG_PATH=/opt/ossl/lib/pkgconfig \
  CPPFLAGS="$HARDEN_CPPFLAGS" \
  LDFLAGS="-L/opt/ossl/lib -Wl,-rpath,/opt/ossl/lib $HARDEN_LDFLAGS"
make -s -j"$(nproc)"
make -s install

cd /
rm -rf /tmp/openssl /tmp/openssl.tar.gz /tmp/tss /tmp/tss.tar.gz
