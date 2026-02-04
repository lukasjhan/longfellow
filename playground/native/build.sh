#!/usr/bin/env bash
# Build the longfellow static library and the longfellow_cli wrapper.
#
# This environment ships a Swift-toolchain clang that cannot find libstdc++,
# so we use the system clang-17 and point it at the GCC 11 install dir via
# thin wrapper scripts (created on the fly if missing).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"          # /home/unknown/longfellow
LIB="$ROOT/longfellow-zk/lib"
BUILD="$ROOT/build"
TC="$ROOT/.toolchain"

GCC_DIR="${GCC_INSTALL_DIR:-/usr/lib/gcc/x86_64-linux-gnu/11}"

# --- 1. compiler wrappers ---------------------------------------------------
mkdir -p "$TC"
if [ ! -x "$TC/clang++w" ]; then
  printf '#!/bin/bash\nexec /usr/bin/clang++-17 --gcc-install-dir=%s "$@"\n' "$GCC_DIR" > "$TC/clang++w"
  printf '#!/bin/bash\nexec /usr/bin/clang-17 --gcc-install-dir=%s "$@"\n' "$GCC_DIR" > "$TC/clangw"
  chmod +x "$TC/clang++w" "$TC/clangw"
fi

# --- 2. configure + build the static library --------------------------------
if [ ! -f "$BUILD/CMakeCache.txt" ]; then
  echo ">> configuring cmake (Release)"
  CXX="$TC/clang++w" CC="$TC/clangw" cmake -D CMAKE_BUILD_TYPE=Release \
    -S "$LIB" -B "$BUILD"
fi
echo ">> building mdoc_static"
make -C "$BUILD" mdoc_static -j"$(nproc)"

# --- 3. compile the CLI -----------------------------------------------------
echo ">> compiling longfellow_cli"
"$TC/clang++w" -std=c++17 -O2 -mpclmul \
  -I"$LIB" \
  "$HERE/longfellow_cli.cc" \
  "$BUILD/circuits/mdoc/libmdoc_static.a" \
  -lcrypto -lzstd -lpthread \
  -o "$HERE/longfellow_cli"

echo ">> done: $HERE/longfellow_cli"
