// Micro-benchmark: the SAME "K SHA-256 blocks" circuit over Fp256 vs GF(2^128).
// Measures circuit size AND actual ZK prove/verify time. This quantifies the
// benefit of the two-field split (mdoc does its hashing in GF(2^128)).

#include <cstdint>
#include <cstdio>
#include <chrono>
#include <memory>
#include <vector>

#include <openssl/sha.h>
#include <zstd.h>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "proto/circuit_io.h"
#include "proto/circuit_writer.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace proofs {
namespace {

using f_128 = GF2_128<>;
using f2_p256 = Fp2<Fp256Base>;
using Elt2 = f2_p256::Elt;
using FftExt = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
using RSFp = ReedSolomonFactory<Fp256Base, FftExt>;
using RSGf = LCH14ReedSolomonFactory<f_128>;

constexpr char kRootX[] =
    "112649224146410281873500457609690258373018840430489408729223714171582664680802";
constexpr char kRootY[] =
    "84087994358540907695740461427818660560182168997182378749313018254450460212908";
constexpr size_t kRate = 7, kNreq = 132, kVer = 7;
constexpr size_t PLK = 4;

template <class Field>
std::unique_ptr<Circuit<Field>> make_sha(const Field& F, size_t nb) {
  using CB = CompilerBackend<Field>;
  using LC = Logic<Field, CB>;
  using v8 = typename LC::v8;
  using v256 = typename LC::v256;
  using FlatSHA = FlatSHA256Circuit<LC, BitPlucker<LC, PLK>>;
  using SBW = typename FlatSHA::BlockWitness;
  QuadCircuit<Field> Q(F);
  const CB cbk(&Q);
  const LC L(&cbk, F);
  Q.private_input();  // everything private (constant-1 is the only public input)
  std::vector<v8> pre(64 * nb);
  for (auto& b : pre) b = L.template vinput<8>();
  v256 ebits = L.template vinput<256>();
  std::vector<SBW> sha(nb);
  for (auto& s : sha) s.input(L);
  v8 nbw = L.template vinput<8>();
  FlatSHA sh(L);
  sh.assert_message_hash(nb, nbw, pre.data(), ebits, sha.data());
  return Q.mkcircuit(1);
}

template <class Field>
void fill_w(const Field& F, Dense<Field>& W, bool full, size_t nb) {
  DenseFiller<Field> f(W);
  f.push_back(F.one());
  if (!full) return;
  size_t mlen = nb * 64 - 9;
  std::vector<uint8_t> msg(mlen, 'a');
  std::vector<uint8_t> in(64 * nb);
  std::vector<FlatSHA256Witness::BlockWitness> bw(nb);
  uint8_t numb = 0;
  FlatSHA256Witness::transform_and_witness_message(mlen, msg.data(), nb, numb, in.data(), bw.data());
  uint8_t dig[32];
  ::SHA256(msg.data(), mlen, dig);
  for (size_t i = 0; i < 64 * nb; ++i) f.push_back(in[i], 8, F);
  for (size_t i = 0; i < 256; ++i) f.push_back((dig[31 - i / 8] >> (i % 8)) & 1, 1, F);
  BitPluckerEncoder<Field, PLK> enc(F);
  for (size_t b = 0; b < nb; ++b) {
    for (size_t k = 0; k < 48; ++k) f.push_back(enc.mkpacked_v32(bw[b].outw[k]));
    for (size_t k = 0; k < 64; ++k) {
      f.push_back(enc.mkpacked_v32(bw[b].oute[k]));
      f.push_back(enc.mkpacked_v32(bw[b].outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) f.push_back(enc.mkpacked_v32(bw[b].h1[k]));
  }
  f.push_back(numb, 8, F);
}

long ms_since(std::chrono::steady_clock::time_point t) {
  return (long)std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t).count();
}

template <class Field, class RS>
void prove_bench(const char* name, const Field& F, FieldID fid, const RS& rsf, size_t nb) {
  auto C = make_sha<Field>(F, nb);
  std::vector<uint8_t> cb;
  CircuitWriter<Field> w(F, fid);
  w.to_bytes(*C, cb);
  std::vector<uint8_t> comp(ZSTD_compressBound(cb.size()));
  size_t csz = ZSTD_compress(comp.data(), comp.size(), cb.data(), cb.size(), 6);

  auto W = Dense<Field>(1, C->ninputs);
  auto pub = Dense<Field>(1, C->npub_in);
  fill_w<Field>(F, W, true, nb);
  fill_w<Field>(F, pub, false, nb);

  ZkProof<Field> zkp(*C, kRate, kNreq);
  Transcript tp((const uint8_t*)"bench", 5, kVer);
  SecureRandomEngine rng;
  ZkProver<Field, RS> prover(*C, F, rsf);
  auto t0 = std::chrono::steady_clock::now();
  prover.commit(zkp, W, tp, rng);
  bool pok = prover.prove(zkp, W, tp);
  long prove_ms = ms_since(t0);

  std::vector<uint8_t> pb;
  zkp.write(pb, F);

  ZkProof<Field> pr(*C, kRate, kNreq);
  ReadBuffer rb(pb);
  pr.read(rb, F);
  ZkVerifier<Field, RS> ver(*C, rsf, kRate, kNreq, F);
  Transcript tv((const uint8_t*)"bench", 5, kVer);
  auto t1 = std::chrono::steady_clock::now();
  ver.recv_commitment(pr, tv);
  bool vok = ver.verify(pr, pub, tv);
  long verify_ms = ms_since(t1);

  printf("  %-10s blocks=%2zu  circuit(zstd)=%5zu KB  proof=%5zu KB  prove=%5ld ms  verify=%4ld ms  %s\n",
         name, nb, csz / 1024, pb.size() / 1024, prove_ms, verify_ms,
         (pok && vok) ? "OK" : "FAIL");
}

}  // namespace
}  // namespace proofs

int main() {
  using namespace proofs;
  set_log_level(ERROR);

  const f_128 Fs;
  const f2_p256 p256_2(p256_base);
  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExt fft(p256_base, p256_2, omega, 1ull << 31);
  const RSFp rsf_fp(fft, p256_base);
  const RSGf rsf_gf(Fs);

  printf("SHA-256 ZK: Fp256 (prime field) vs GF(2^128) (binary field) — circuit size + prove/verify time\n\n");
  for (size_t k : {4u, 13u, 18u}) {
    prove_bench<Fp256Base, RSFp>("Fp256", p256_base, P256_ID, rsf_fp, k);
    prove_bench<f_128, RSGf>("GF(2^128)", Fs, GF2_128_ID, rsf_gf, k);
    printf("\n");
  }
  return 0;
}
