#!/usr/bin/env bash
#
# sshfm - standalone build
#
# Builds every dependency from the bundled sources and links a single
# fully static binary:
#
#     zlib 1.3.1  ->  OpenSSL 3.0.13 (libcrypto)  ->  libssh 0.12.2  ->  sshfm
#
# Usage:
#     ./build.sh [--clean] [--jobs N]
#
# Environment:
#     SSHFM_WORK   working/cache directory (default: ${TMPDIR:-/tmp}/sshfm-build)
#     JOBS         parallel make jobs (default: nproc)
#
# Requirements (build machine):
#     g++ (C++17), cmake >= 3.10, make, perl, tar, xz
#     A Linux / WSL environment.  The result is a static Linux x86-64 binary.
#
set -euo pipefail

PKG="$(cd "$(dirname "$0")" && pwd)"
SRC="$PKG/src"
DEPS="$PKG/deps"
OUT="$PKG/out"
WORK="${SSHFM_WORK:-${TMPDIR:-/tmp}/sshfm-build}"
PREFIX="$WORK/prefix"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

CLEAN=0
while [ $# -gt 0 ]; do
	case "$1" in
	--clean) CLEAN=1; shift ;;
	--jobs)  JOBS="$2"; shift 2 ;;
	-h|--help)
		sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
		exit 0 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 1; }; }

need g++
need cmake
need make
need perl
need tar

if [ "$CLEAN" = 1 ]; then
	say "cleaning $WORK and $OUT"
	rm -rf "$WORK" "$OUT"
fi

mkdir -p "$WORK/src" "$PREFIX" "$OUT"

# ------------------------------------------------------------------ zlib
if [ ! -f "$PREFIX/lib/libz.a" ]; then
	say "zlib 1.3.1"
	rm -rf "$WORK/src/zlib-1.3.1"
	tar -xzf "$DEPS/zlib-1.3.1.tar.gz" -C "$WORK/src"
	( cd "$WORK/src/zlib-1.3.1"
	  ./configure --static --prefix="$PREFIX" >/dev/null
	  make -j"$JOBS" >/dev/null
	  make install >/dev/null )
else
	say "zlib 1.3.1 (cached)"
fi

# --------------------------------------------------------------- openssl
if [ ! -f "$PREFIX/lib/libcrypto.a" ]; then
	say "OpenSSL 3.0.13 (static libcrypto)"
	rm -rf "$WORK/src/openssl-3.0.13"
	tar -xzf "$DEPS/openssl-3.0.13.tar.gz" -C "$WORK/src"
	( cd "$WORK/src/openssl-3.0.13"
	  ./Configure --prefix="$PREFIX" --libdir=lib no-shared no-tests \
	      >"$WORK/openssl-configure.log" 2>&1
	  make -j"$JOBS" >"$WORK/openssl-make.log" 2>&1
	  make install_sw >"$WORK/openssl-install.log" 2>&1 )
else
	say "OpenSSL 3.0.13 (cached)"
fi

# ----------------------------------------------------------------- libssh
if [ ! -f "$PREFIX/lib/libssh.a" ]; then
	say "libssh 0.12.2 (static, server support)"
	rm -rf "$WORK/src/libssh-0.12.2" "$WORK/src/libssh-build"
	tar -xJf "$DEPS/libssh-0.12.2.tar.xz" -C "$WORK/src"
	cmake -S "$WORK/src/libssh-0.12.2" -B "$WORK/src/libssh-build" \
	      -DCMAKE_BUILD_TYPE=Release \
	      -DBUILD_SHARED_LIBS=OFF \
	      -DCMAKE_INSTALL_PREFIX="$PREFIX" \
	      -DCMAKE_PREFIX_PATH="$PREFIX" \
	      -DOPENSSL_ROOT_DIR="$PREFIX" \
	      -DOPENSSL_USE_STATIC_LIBS=TRUE \
	      -DWITH_ZLIB=ON -DWITH_GCRYPT=OFF -DWITH_SERVER=ON \
	      -DWITH_EXAMPLES=OFF -DWITH_PCAP=OFF \
	      -DUNIT_TESTING=OFF -DCLIENT_TESTING=OFF -DSERVER_TESTING=OFF \
	      >"$WORK/libssh-cmake.log" 2>&1
	cmake --build "$WORK/src/libssh-build" -j"$JOBS" \
	      >"$WORK/libssh-make.log" 2>&1
	cmake --install "$WORK/src/libssh-build" \
	      >"$WORK/libssh-install.log" 2>&1
else
	say "libssh 0.12.2 (cached)"
fi

# ----------------------------------------------------------------- sshfm
say "sshfm"
g++ -O2 -std=c++17 -static -Wl,--unresolved-symbols=ignore-all \
    -DLIBSSH_STATIC -I"$PREFIX/include" \
    "$SRC/sshfm.cpp" \
    "$PREFIX/lib/libssh.a" "$PREFIX/lib/libcrypto.a" "$PREFIX/lib/libz.a" \
    -lpthread -lutil -lm -ldl \
    -o "$OUT/sshfm" 2>"$WORK/sshfm-build.log" \
    || { grep -iE 'error:' "$WORK/sshfm-build.log" | head; exit 1; }

say "done"
ls -la "$OUT/sshfm"
"$OUT/sshfm" --help 2>&1 | head -2
echo
echo "binary: $OUT/sshfm"
echo "run:    $OUT/sshfm -dir ./data -port 2222"
