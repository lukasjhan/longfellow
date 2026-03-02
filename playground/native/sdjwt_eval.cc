// M2 prototype (EvaluationBackend, no ZK): validate the NEW sub-circuit logic
// for Approach-C SD-JWT before wiring it into a real circuit.
//
// This file currently validates the `exp` (validity) check:
//   SD-JWT exp/iat are 10-digit UNIX timestamps. For equal-length decimal
//   strings, lexicographic byte comparison == numeric comparison (ASCII
//   '0'..'9' are monotonic). So "now <= exp" reduces to a per-byte compare —
//   no integer parsing needed, and it translates directly to the circuit.
//
// Build: see native/build.sh (sdjwt_eval target). Run: ./native/sdjwt_eval
// Exit 0 + "ALL ... PASS" means the logic is correct (EvaluationBackend(true)
// panics on any false assertion).

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "util/log.h"

namespace proofs {
namespace {

using EvalBackend = EvaluationBackend<Fp256Base>;
using L_t = Logic<Fp256Base, EvalBackend>;
using v8 = L_t::v8;
using BitW = L_t::BitW;

// Build n v8 bytes from an ASCII string.
void mk_bytes(const L_t& L, const char* s, v8* out, size_t n) {
  for (size_t i = 0; i < n; ++i) out[i] = L.template vbit<8>((uint8_t)s[i]);
}

// Lexicographic a <= b for equal-length byte arrays (index 0 = most
// significant). Built from per-byte eq/lt — circuit-translatable as-is.
BitW leq_bytes(const L_t& L, const v8* a, const v8* b, size_t n) {
  BitW le = L.bit(1);  // empty suffix: equal => a <= b
  for (size_t i = n; i-- > 0;) {
    BitW blt = L.lt(8, a[i].data(), b[i].data());
    BitW beq = L.eq(8, a[i].data(), b[i].data());
    le = L.lor(blt, L.land(beq, le));
  }
  return le;
}

// assert "now <= exp" (credential not expired).
void assert_not_expired(const L_t& L, const char* now, const char* exp) {
  v8 n[10], e[10];
  mk_bytes(L, now, n, 10);
  mk_bytes(L, exp, e, 10);
  L.assert1(leq_bytes(L, n, e, 10));
}

}  // namespace
}  // namespace proofs

int main() {
  using namespace proofs;
  set_log_level(ERROR);
  const EvalBackend ebk(p256_base, true);  // true => panic on false assert
  const L_t L(&ebk, p256_base);

  // 10-digit UNIX timestamps.
  const char* exp = "1748000000";  // expiry

  // 1) now < exp  => not expired => assert passes
  assert_not_expired(L, "1700000000", exp);
  printf("exp check  now<exp   : PASS (valid)\n");

  // 2) now == exp => boundary => not expired
  assert_not_expired(L, "1748000000", exp);
  printf("exp check  now==exp  : PASS (valid at boundary)\n");

  // 3) now > exp  => expired => leq must be FALSE (assert the negation)
  {
    v8 n[10], e[10];
    mk_bytes(L, "1800000000", n, 10);
    mk_bytes(L, "1748000000", e, 10);
    L.assert1(L.lnot(leq_bytes(L, n, e, 10)));  // correctly detected expired
  }
  printf("exp check  now>exp   : PASS (expiry correctly rejected)\n");

  printf("\nALL exp-comparison sub-circuit checks PASS (M2)\n");
  return 0;
}
