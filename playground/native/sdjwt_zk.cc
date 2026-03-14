// M3: compile the validated SD-JWT Approach-C logic into a REAL ZK circuit
// (CompilerBackend -> QuadCircuit) and run an actual ZkProver/ZkVerifier.
//
// M3a (this step): exp-only circuit. Proves, in zero knowledge, "I know a
// payload that contains a 10-digit `exp` at index `expAmount` such that
// now <= exp" — i.e. the credential is not expired. (No signature binding yet;
// ECDSA front-end is added in M5. This step validates the compile + ZK path for
// the novel logic, mirroring zk/zk_testing.h::run2_test_zk.)

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/routing.h"
#include "ec/p256.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace proofs {
namespace {

using f2_p256 = Fp2<Fp256Base>;
using Elt2 = f2_p256::Elt;
using FftExtConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
using RSFactory_b = ReedSolomonFactory<Fp256Base, FftExtConvolutionFactory>;

constexpr char kRootX[] =
    "112649224146410281873500457609690258373018840430489408729223714171582664"
    "680802";
constexpr char kRootY[] =
    "84087994358540907695740461427818660560182168997182378749313018254450460212"
    "908";
constexpr size_t kRate = 7;
constexpr size_t kNreq = 132;
constexpr size_t kVersion = 7;
constexpr const char* kSeed = "sdjwt-zk";

constexpr size_t MAXP = 256;   // max payload bytes
constexpr size_t LOGP = 10;    // index bits into payload

// ---- shared (templated) circuit logic ----
template <class LC>
typename LC::BitW leq_bytes(const LC& L, const typename LC::v8* a,
                            const typename LC::v8* b, size_t n) {
  typename LC::BitW le = L.bit(1);
  for (size_t i = n; i-- > 0;) {
    auto blt = L.lt(8, a[i].data(), b[i].data());
    auto beq = L.eq(8, a[i].data(), b[i].data());
    le = L.lor(blt, L.land(beq, le));
  }
  return le;
}

// Assert now <= exp, where exp's 10 digits live in `payload` at `expAmount`.
template <class LC>
void assert_not_expired(const LC& L, const typename LC::v8 payload[/*MAXP*/],
                        const typename LC::template bitvec<LOGP>& expAmount,
                        const typename LC::v8 now[/*10*/]) {
  using v8 = typename LC::v8;
  v8 ed[10];
  v8 zero = L.template vbit<8>(0);
  Routing<LC> r(L);
  r.shift(expAmount, 10, ed, MAXP, payload, zero, 3);
  L.assert1(leq_bytes(L, now, ed, 10));
}

// ---- build the circuit ----
std::unique_ptr<Circuit<Fp256Base>> make_circuit() {
  using CB = CompilerBackend<Fp256Base>;
  using LC = Logic<Fp256Base, CB>;
  using v8 = LC::v8;

  QuadCircuit<Fp256Base> Q(p256_base);
  const CB cbk(&Q);
  const LC L(&cbk, p256_base);

  // public input: now[10]
  v8 now[10];
  for (size_t i = 0; i < 10; ++i) now[i] = L.template vinput<8>();

  Q.private_input();
  // private witness: payload[MAXP], expAmount
  v8 payload[MAXP];
  for (size_t i = 0; i < MAXP; ++i) payload[i] = L.template vinput<8>();
  typename LC::template bitvec<LOGP> expAmount = L.template vinput<LOGP>();

  assert_not_expired(L, payload, expAmount, now);
  return Q.mkcircuit(/*nc=*/1);
}

// ---- fill witness ----
void fill(Dense<Fp256Base>& W, bool full, const char* now,
          const std::string& payload, size_t exp_idx) {
  DenseFiller<Fp256Base> f(W);
  f.push_back(p256_base.one());
  for (size_t i = 0; i < 10; ++i) f.push_back((uint8_t)now[i], 8, p256_base);
  if (full) {
    for (size_t i = 0; i < MAXP; ++i)
      f.push_back(i < payload.size() ? (uint8_t)payload[i] : 0, 8, p256_base);
    f.push_back(exp_idx, LOGP, p256_base);
  }
}

bool run_zk(const Circuit<Fp256Base>& C, Dense<Fp256Base>& W,
            const Dense<Fp256Base>& pub) {
  const f2_p256 p256_2(p256_base);
  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf(fft, p256_base);

  ZkProof<Fp256Base> zkp(C, kRate, kNreq);
  Transcript tp((const uint8_t*)kSeed, strlen(kSeed), kVersion);
  SecureRandomEngine rng;
  ZkProver<Fp256Base, RSFactory_b> prover(C, p256_base, rsf);
  prover.commit(zkp, W, tp, rng);
  if (!prover.prove(zkp, W, tp)) return false;

  std::vector<uint8_t> buf;
  zkp.write(buf, p256_base);
  printf("  proof: %zu bytes\n", buf.size());

  ZkProof<Fp256Base> pr(C, kRate, kNreq);
  ReadBuffer rb(buf);
  if (!pr.read(rb, p256_base)) return false;
  ZkVerifier<Fp256Base, RSFactory_b> ver(C, rsf, kRate, kNreq, p256_base);
  Transcript tv((const uint8_t*)kSeed, strlen(kSeed), kVersion);
  ver.recv_commitment(pr, tv);
  return ver.verify(pr, pub, tv);
}

}  // namespace
}  // namespace proofs

int main() {
  using namespace proofs;
  set_log_level(ERROR);

  printf("M3a: compiling exp-only SD-JWT circuit...\n");
  auto C = make_circuit();
  printf("  circuit: ninputs=%zu npub_in=%zu nl=%zu\n", C->ninputs, C->npub_in,
         C->nl);

  // A small synthetic payload containing "exp":<10 digits>.
  std::string payload = "{\"vct\":\"pid\",\"exp\":1748000000,\"x\":1}";
  size_t exp_idx = payload.find("\"exp\":") + 6;

  auto W = Dense<Fp256Base>(1, C->ninputs);
  auto pub = Dense<Fp256Base>(1, C->npub_in);
  fill(W, true, "1700000000", payload, exp_idx);   // now < exp
  fill(pub, false, "1700000000", payload, exp_idx);

  printf("M3a: running ZK prove/verify...\n");
  bool ok = run_zk(*C, W, pub);
  printf("  result: %s\n", ok ? "ACCEPT ✅" : "REJECT ❌");
  return ok ? 0 : 1;
}
