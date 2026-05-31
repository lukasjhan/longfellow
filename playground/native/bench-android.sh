#!/usr/bin/env bash
# Benchmark the SD-JWT/mdoc ZK benches on-device, COUNTERBALANCED against thermal
# throttling. A fixed run order biases results: the first config is measured coolest
# and later ones hotter, so on a throttling phone prove-time tracks run order, not
# circuit size. Here each config is measured once per round and the per-round starting
# config ROTATES, so over ROUNDS rounds every config occupies every thermal position
# equally; we report the per-config median. prove/verify/proof come from each binary's
# TOTAL line; peak RSS from /proc/<pid>/status:VmHWM (no source change).
#   ROUNDS=7 COOLDOWN=45 bash playground/native/bench-android.sh     # ~35-40 min
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"                                    # so default fixtures (playground/fixtures/*) resolve
N="$ROOT/playground/native"
ROUNDS="${ROUNDS:-7}"
COOLDOWN="${COOLDOWN:-45}"
OUT="$ROOT/.zkbench.$$.out"
trap 'rm -f "$OUT"' EXIT

run_one() {                                   # echo: "prove verify proof peakMB rc"
  local bin="$1"
  "$bin" >"$OUT" 2>&1 & local pid=$!
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

LABELS=("SD-JWT base" "SD-JWT +nullifier" "SD-JWT +blind" "SD-JWT +revocation" \
        "mdoc +nullifier" "mdoc +blind" "mdoc +revocation")
BINS=("$N/sdjwt_split" "$N/sdjwt_null_split" "$N/sdjwt_null_blind" "$N/sdjwt_revoc_split" \
      "$N/mdoc_null_split" "$N/mdoc_null_blind" "$N/mdoc_revoc_split")
n=${#LABELS[@]}
declare -A PV VV SV MV

echo "device=$(getprop ro.product.model 2>/dev/null || uname -m)  cores=$(nproc)  rounds=$ROUNDS  cooldown=${COOLDOWN}s"
echo "warmup (cold; builds circuit caches)…"
for ((i=0;i<n;i++)); do [ -x "${BINS[i]}" ] && run_one "${BINS[i]}" >/dev/null; done

for ((r=0;r<ROUNDS;r++)); do
  for ((k=0;k<n;k++)); do
    i=$(( (k+r) % n ))                        # rotate the starting config each round -> counterbalance
    [ -x "${BINS[i]}" ] || continue
    sleep "$COOLDOWN"
    read -r p v s m rc < <(run_one "${BINS[i]}")
    if [ "$rc" != 0 ] || [ -z "$p" ]; then echo "  ${LABELS[i]}: run failed (rc=$rc)"; continue; fi
    PV[$i]+=" $p"; VV[$i]+=" $v"; SV[$i]="$s"; MV[$i]+=" $m"
  done
  echo "  round $((r+1))/$ROUNDS done"
done

echo "--- per-config median over $ROUNDS counterbalanced rounds ---"
for ((i=0;i<n;i++)); do
  [ -n "${PV[$i]:-}" ] || { printf '%-20s (no data)\n' "${LABELS[i]}"; continue; }
  printf '%-20s prove=%4s ms  verify=%4s ms  proof=%4s KB  peakRSS=%5s MB\n' "${LABELS[i]}" \
    "$(printf '%s\n' ${PV[$i]} | median)" "$(printf '%s\n' ${VV[$i]} | median)" \
    "${SV[$i]}" "$(printf '%s\n' ${MV[$i]} | median)"
done
