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

# --- 3. compile the mdoc CLI ------------------------------------------------
echo ">> compiling longfellow_cli (mdoc)"
"$TC/clang++w" -std=c++17 -O2 -mpclmul \
  -I"$LIB" \
  "$HERE/longfellow_cli.cc" \
  "$BUILD/circuits/mdoc/libmdoc_static.a" \
  -lcrypto -lzstd -lpthread \
  -o "$HERE/longfellow_cli"

# --- 4. compile the JWT/SD-JWT CLI (experimental circuit) -------------------
echo ">> building base64 + compiling jwt_cli (SD-JWT)"
make -C "$BUILD" base64 -j"$(nproc)"
BASE64_OBJ="$(find "$BUILD" -name decode_util.cc.o | head -1)"
"$TC/clang++w" -std=c++17 -O2 -mpclmul \
  -I"$LIB" \
  "$HERE/jwt_cli.cc" \
  "$BASE64_OBJ" \
  "$BUILD/circuits/mdoc/libmdoc_static.a" \
  -lcrypto -lzstd -lpthread \
  -o "$HERE/jwt_cli"

# --- 5. compile the SD-JWT eval prototype (M2/M4 core, no ZK) ----------------
echo ">> compiling sdjwt_eval (SD-JWT Approach-C logic prototype)"
"$TC/clang++w" -std=c++17 -O2 -mpclmul \
  -I"$LIB" \
  "$HERE/sdjwt_eval.cc" \
  "$BASE64_OBJ" \
  "$BUILD/circuits/mdoc/libmdoc_static.a" \
  -lcrypto -lzstd -lpthread \
  -o "$HERE/sdjwt_eval"

# --- 6. compile the SD-JWT ZK circuit (M3+) ---------------------------------
echo ">> compiling sdjwt_zk (SD-JWT Approach-C real ZK circuit)"
"$TC/clang++w" -std=c++17 -O2 -mpclmul \
  -I"$LIB" \
  "$HERE/sdjwt_zk.cc" \
  "$BASE64_OBJ" \
  "$BUILD/circuits/mdoc/libmdoc_static.a" \
  -lcrypto -lzstd -lpthread \
  -o "$HERE/sdjwt_zk"

echo ">> done: longfellow_cli, jwt_cli, sdjwt_eval, sdjwt_zk"
