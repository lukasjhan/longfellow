#!/usr/bin/env bash
# Benchmark the SD-JWT/mdoc ZK benches on-device (Termux or any Linux/aarch64).
#   RUNS=5 bash playground/native/bench-android.sh
#
# prove/verify/proof come from each binary's "TOTAL ... prove= verify= bundle=" line.
# Peak RSS is sampled from /proc/<pid>/status:VmHWM (monotonic high-water mark) while
# the prover runs — no source instrumentation, identical method on desktop and phone.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"                                   # so default fixtures (playground/fixtures/*) resolve
N="$ROOT/playground/native"
RUNS="${RUNS:-5}"
OUT="$ROOT/.zkbench.$$.out"
trap 'rm -f "$OUT"' EXIT

run_one() {                                  # echo: "prove verify proof peakMB rc"
  local bin="$1"; shift
  "$bin" "$@" >"$OUT" 2>&1 & local pid=$!
  local peak=0 hwm
  while kill -0 "$pid" 2>/dev/null; do
    hwm=$(awk '/^VmHWM/{print $2}' "/proc/$pid/status" 2>/dev/null || true)
    [ -n "${hwm:-}" ] && [ "$hwm" -gt "$peak" ] && peak=$hwm
    sleep 0.03
  done
  wait "$pid"; local rc=$?
  local line; line=$(grep -E 'TOTAL.*prove=' "$OUT" | tail -1)
  echo "$(sed -n 's/.*prove=\([0-9]*\).*/\1/p' <<<"$line") \
$(sed -n 's/.*verify=\([0-9]*\).*/\1/p' <<<"$line") \
$(sed -n 's/.*bundle=\([0-9]*\).*/\1/p' <<<"$line") \
$((peak/1024)) $rc"
}

median() { sort -n | awk '{a[NR]=$1} END{print (NR==0)?"-":(NR%2)?a[(NR+1)/2]:int((a[NR/2]+a[NR/2+1])/2)}'; }

bench() {                                    # $1 label, $2 binary
  local label="$1" bin="$2"
  [ -x "$bin" ] || { printf '%-20s (binary missing — build first)\n' "$label"; return; }
  sleep "${COOLDOWN:-0}"                      # cool the SoC between configs (mobile thermal throttling)
  run_one "$bin" >/dev/null                  # warmup (also generates circuit cache if absent)
  local P=() V=() S=() M=() p v s m rc
  for _ in $(seq 1 "$RUNS"); do
    read -r p v s m rc < <(run_one "$bin")
    [ "$rc" != 0 ] && { printf '%-20s FAILED (rc=%s) — last output:\n' "$label" "$rc"; tail -3 "$OUT"; return; }
    P+=("$p"); V+=("$v"); S+=("$s"); M+=("$m")
  done
  printf '%-20s prove=%4s ms  verify=%4s ms  proof=%4s KB  peakRSS=%5s MB\n' "$label" \
    "$(printf '%s\n' "${P[@]}" | median)" "$(printf '%s\n' "${V[@]}" | median)" \
    "${S[0]}" "$(printf '%s\n' "${M[@]}" | median)"
}

echo "device=$(getprop ro.product.model 2>/dev/null || uname -m)  cores=$(nproc)  runs=$RUNS"
echo "--- mdoc (smaller, ~95k hash inputs) ---"
bench "mdoc +nullifier"    "$N/mdoc_null_split"
bench "mdoc +blind"        "$N/mdoc_null_blind"
bench "mdoc +revocation"   "$N/mdoc_revoc_split"
echo "--- SD-JWT VC (~190k hash inputs) ---"
bench "SD-JWT base"        "$N/sdjwt_split"
bench "SD-JWT +nullifier"  "$N/sdjwt_null_split"
bench "SD-JWT +blind"      "$N/sdjwt_null_blind"
bench "SD-JWT +revocation" "$N/sdjwt_revoc_split"
