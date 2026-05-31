#!/usr/bin/env bash
# Build the SD-JWT/mdoc ZK benches on Android (Termux, aarch64).
#
#   pkg install clang cmake make openssl zstd binutils
#   bash playground/native/build-android.sh        # run from anywhere inside the tree
#
# Uses Termux's system clang/libc++/openssl/zstd. longfellow's CMake auto-detects
# aarch64 and sets -march=armv8-a+crypto (PMULL path for GF(2^128)); no -mpclmul.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # repo root
LIB="$ROOT/longfellow-zk/lib"
BUILD="$ROOT/build-android"                                   # separate from desktop build/
N="$ROOT/playground/native"

# The lib CMake configures the whole tree (tests + the circuit_maker tool), which needs
# benchmark/GTest/absl at *configure* time. Termux lacks them and mdoc_static links none,
# so make those find_package non-fatal and stub the link targets (idempotent).
PROOFS="$LIB/CMake/proofs.cmake"
sed -i 's/find_package(benchmark REQUIRED)/find_package(benchmark QUIET)/; s/find_package(GTest REQUIRED)/find_package(GTest QUIET)/' "$PROOFS"
grep -q longfellow-android-stub "$PROOFS" || cat >> "$PROOFS" <<'EOF'
# longfellow-android-stub
foreach(t benchmark::benchmark gtest gtest_main gmock gmock_main absl::flags absl::flags_parse absl::cleanup)
  if(NOT TARGET ${t})
    add_library(${t} INTERFACE IMPORTED)
  endif()
endforeach()
EOF

echo ">> cmake configure (Release, aarch64)"
CXX=clang++ CC=clang cmake -DCMAKE_BUILD_TYPE=Release -S "$LIB" -B "$BUILD"
echo ">> building mdoc_static (-j$(nproc))"
make -C "$BUILD" mdoc_static -j"$(nproc)"

LIBA="$BUILD/circuits/mdoc/libmdoc_static.a"
FLAGS=(-std=c++17 -O2 -march=armv8-a+crypto -I"$LIB")
LINK=("$LIBA" -lcrypto -lzstd -lpthread -llog)   # -llog: Android liblog (__android_log_print in log.cc)

for b in sdjwt_split sdjwt_null_split sdjwt_null_blind sdjwt_revoc_split \
         mdoc_null_split mdoc_null_blind mdoc_revoc_split; do
  echo ">> compiling $b"
  clang++ "${FLAGS[@]}" "$N/$b.cc" "${LINK[@]}" -o "$N/$b"
done
echo ">> done — binaries in playground/native/. Now: bash playground/native/bench-android.sh"
