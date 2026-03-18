// M3: compile the validated SD-JWT Approach-C logic into a REAL ZK circuit
// (CompilerBackend -> QuadCircuit) and run an actual ZkProver/ZkVerifier.
//
//   M3a: exp check (now <= exp located in payload).
//   M3b: + `_sd` membership: SHA(disclosure) == base64decode(entry located in
//        payload). The SHA witness (FlatSHA256 block witnesses) becomes circuit
//        input, filled from FlatSHA256Witness.
//
// No signature binding yet (ECDSA front-end is M5); this validates the compile
// + ZK path for the novel logic. Mirrors zk/zk_testing.h::run2_test_zk.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <openssl/sha.h>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/routing.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "circuits/tests/base64/decode.h"
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

using CB = CompilerBackend<Fp256Base>;
using LC = Logic<Fp256Base, CB>;
using v8 = LC::v8;
using v256 = LC::v256;
using BitW = LC::BitW;

constexpr size_t kPluck = 4;
using FlatSHA = FlatSHA256Circuit<LC, BitPlucker<LC, kPluck>>;
using SBW = FlatSHA::BlockWitness;

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
constexpr size_t kRate = 7, kNreq = 132, kVersion = 7;
constexpr const char* kSeed = "sdjwt-zk";

constexpr size_t MAXP = 256;    // max payload bytes
constexpr size_t LOGP = 10;     // index bits into payload
constexpr size_t MAXB = 2;      // SHA blocks for a disclosure (<=128 bytes)

// ----- circuit logic (CompilerBackend) -----
v8 vb(const LC& L, uint8_t c) { return L.template vbit<8>(c); }

// Verify decoded disclosure dd = ["<salt>","<name>",<value>] encodes (name,
// value). `shiftAmt` = 2 + saltLen positions the salt-closing quote at 0.
void assert_disclosure_struct(const LC& L, const v8* dd, size_t maxd,
                              const LC::bitvec<8>& shiftAmt, const char* name,
                              size_t nlen, const char* value, size_t vlen) {
  L.assert1(L.eq(8, dd[0].data(), vb(L, '[').data()));
  L.assert1(L.eq(8, dd[1].data(), vb(L, '"').data()));
  std::vector<v8> P;
  P.push_back(vb(L, '"'));
  P.push_back(vb(L, ','));
  P.push_back(vb(L, '"'));
  for (size_t i = 0; i < nlen; ++i) P.push_back(vb(L, (uint8_t)name[i]));
  P.push_back(vb(L, '"'));
  P.push_back(vb(L, ','));
  for (size_t i = 0; i < vlen; ++i) P.push_back(vb(L, (uint8_t)value[i]));
  P.push_back(vb(L, ']'));

  std::vector<v8> S(P.size());
  Routing<LC> r(L);
  r.shift(shiftAmt, P.size(), S.data(), maxd, dd, vb(L, 0), 3);
  for (size_t i = 0; i < P.size(); ++i)
    L.assert1(L.eq(8, S[i].data(), P[i].data()));
}

BitW leq_bytes(const LC& L, const v8* a, const v8* b, size_t n) {
  BitW le = L.bit(1);
  for (size_t i = n; i-- > 0;) {
    auto blt = L.lt(8, a[i].data(), b[i].data());
    auto beq = L.eq(8, a[i].data(), b[i].data());
    le = L.lor(blt, L.land(beq, le));
  }
  return le;
}

// Inputs that make up the circuit (declared in a fixed order; the witness Dense
// must be filled in the SAME order).
struct Inputs {
  v8 now[10];                       // public
  v8 payload[MAXP];                 // private
  LC::bitvec<LOGP> expAmount;       // private
  LC::bitvec<LOGP> sdAmount;        // private
  v8 disc_pre[64 * MAXB];           // private: disclosure preimage (padded)
  v8 disc_nb;                       // private
  v256 disc_ebits;                  // private: SHA(disclosure) bits
  SBW disc_sha[MAXB];               // private: SHA block witness
  LC::bitvec<8> disc_len;           // private: disclosure base64 length
  LC::bitvec<8> disc_shift;         // private: 2 + saltLen (structural shift)
};

void declare_inputs(const LC& L, QuadCircuit<Fp256Base>& Q, Inputs& in) {
  for (size_t i = 0; i < 10; ++i) in.now[i] = L.template vinput<8>();
  Q.private_input();
  for (size_t i = 0; i < MAXP; ++i) in.payload[i] = L.template vinput<8>();
  in.expAmount = L.template vinput<LOGP>();
  in.sdAmount = L.template vinput<LOGP>();
  for (size_t i = 0; i < 64 * MAXB; ++i) in.disc_pre[i] = L.template vinput<8>();
  in.disc_nb = L.template vinput<8>();
  in.disc_ebits = L.template vinput<256>();
  for (size_t i = 0; i < MAXB; ++i) in.disc_sha[i].input(L);
  in.disc_len = L.template vinput<8>();
  in.disc_shift = L.template vinput<8>();
}

void assert_logic(const LC& L, const Inputs& in) {
  v8 zero = L.template vbit<8>(0);
  Routing<LC> r(L);

  // (1) exp: now <= exp(payload at expAmount)
  v8 ed[10];
  r.shift(in.expAmount, 10, ed, MAXP, in.payload, zero, 3);
  L.assert1(leq_bytes(L, in.now, ed, 10));

  // (2) SHA(disclosure preimage) == disc_ebits
  FlatSHA sha(L);
  sha.assert_message_hash(MAXB, in.disc_nb, in.disc_pre, in.disc_ebits,
                          in.disc_sha);

  // (3) membership: base64decode(_sd entry @ sdAmount) == disc_ebits digest
  v8 entry[43];
  r.shift(in.sdAmount, 43, entry, MAXP, in.payload, zero, 3);
  v8 out[33];
  Base64Decoder<LC> b64(L);
  b64.base64_rawurl_decode(entry, out, 43);
  for (size_t j = 0; j < 32; ++j) {
    v8 tb;
    for (size_t c = 0; c < 8; ++c) tb[c] = in.disc_ebits[8 * (31 - j) + c];
    L.assert1(L.eq(8, out[j].data(), tb.data()));
  }

  // (4) structural: decode disclosure (disc_pre, length disc_len) and verify
  //     it encodes (age_over_18, true). Works for any value type.
  constexpr size_t MAXDD = (64 * MAXB * 6) / 8;  // 96
  v8 dd[MAXDD];
  Base64Decoder<LC> b64b(L);
  LC::bitvec<8> dlen(in.disc_len);  // decode_len takes a non-const ref
  b64b.base64_rawurl_decode_len(in.disc_pre, dd, 64 * MAXB, dlen);
  assert_disclosure_struct(L, dd, MAXDD, in.disc_shift, "age_over_18", 11,
                           "true", 4);
}

std::unique_ptr<Circuit<Fp256Base>> make_circuit() {
  QuadCircuit<Fp256Base> Q(p256_base);
  const CB cbk(&Q);
  const LC L(&cbk, p256_base);
  Inputs in;
  declare_inputs(L, Q, in);
  assert_logic(L, in);
  return Q.mkcircuit(/*nc=*/1);
}

// ----- witness fill -----
struct Concrete {
  std::string now;       // 10 digits
  std::string payload;
  size_t exp_idx, sd_idx;
  std::string disc;      // disclosure base64url string
  size_t salt_len;       // salt byte length in the decoded disclosure
};

void fill(Dense<Fp256Base>& W, bool full, const Concrete& c) {
  DenseFiller<Fp256Base> f(W);
  f.push_back(p256_base.one());
  for (size_t i = 0; i < 10; ++i) f.push_back((uint8_t)c.now[i], 8, p256_base);
  if (!full) return;

  for (size_t i = 0; i < MAXP; ++i)
    f.push_back(i < c.payload.size() ? (uint8_t)c.payload[i] : 0, 8, p256_base);
  f.push_back(c.exp_idx, LOGP, p256_base);
  f.push_back(c.sd_idx, LOGP, p256_base);

  // disclosure SHA witness
  uint8_t in[64 * MAXB];
  FlatSHA256Witness::BlockWitness bw[MAXB];
  uint8_t numb = 0;
  FlatSHA256Witness::transform_and_witness_message(
      c.disc.size(), (const uint8_t*)c.disc.data(), MAXB, numb, in, bw);
  for (size_t i = 0; i < 64 * MAXB; ++i) f.push_back(in[i], 8, p256_base);
  f.push_back(numb, 8, p256_base);

  uint8_t dig[32];
  ::SHA256((const uint8_t*)c.disc.data(), c.disc.size(), dig);
  for (size_t i = 0; i < 256; ++i)
    f.push_back((dig[31 - i / 8] >> (i % 8)) & 1, 1, p256_base);

  BitPluckerEncoder<Fp256Base, kPluck> enc(p256_base);
  for (size_t i = 0; i < MAXB; ++i) {
    for (size_t k = 0; k < 48; ++k) f.push_back(enc.mkpacked_v32(bw[i].outw[k]));
    for (size_t k = 0; k < 64; ++k) {
      f.push_back(enc.mkpacked_v32(bw[i].oute[k]));
      f.push_back(enc.mkpacked_v32(bw[i].outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) f.push_back(enc.mkpacked_v32(bw[i].h1[k]));
  }

  f.push_back(c.disc.size(), 8, p256_base);     // disc_len
  f.push_back(2 + c.salt_len, 8, p256_base);    // disc_shift = 2 + saltLen
}

std::string b64url(const uint8_t* d, size_t n) {
  static const char* T =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string o;
  int val = 0, bits = 0;
  for (size_t i = 0; i < n; ++i) {
    val = (val << 8) | d[i];
    bits += 8;
    while (bits >= 6) { o += T[(val >> (bits - 6)) & 63]; bits -= 6; }
  }
  if (bits > 0) o += T[(val << (6 - bits)) & 63];
  return o;
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

  printf("M3c: compiling exp + _sd-membership + structural SD-JWT circuit...\n");
  auto C = make_circuit();
  printf("  circuit: ninputs=%zu npub_in=%zu nl=%zu\n", C->ninputs, C->npub_in,
         C->nl);

  // Self-contained payload with exp + one _sd entry = base64url(SHA(disc)).
  Concrete c;
  c.now = "1700000000";
  c.disc = "WyJHUG5sZVRnZVp2YkMzVUpuUEJ2ck5BIiwiYWdlX292ZXJfMTgiLHRydWVd";
  uint8_t dig[32];
  ::SHA256((const uint8_t*)c.disc.data(), c.disc.size(), dig);
  std::string entry = b64url(dig, 32);
  c.payload = std::string("{\"exp\":1748000000,\"_sd\":[\"") + entry + "\"]}";
  c.exp_idx = c.payload.find("\"exp\":") + 6;
  c.sd_idx = c.payload.find(entry);
  c.salt_len = 22;  // decoded disc = ["<22-char salt>","age_over_18",true]
  printf("  payload(%zu): %s\n", c.payload.size(), c.payload.c_str());

  auto W = Dense<Fp256Base>(1, C->ninputs);
  auto pub = Dense<Fp256Base>(1, C->npub_in);
  fill(W, true, c);
  fill(pub, false, c);

  printf("M3c: running ZK prove/verify...\n");
  bool ok = run_zk(*C, W, pub);
  printf("  result: %s (exp valid + age_over_18 ∈ _sd + decodes to true, in ZK)\n",
         ok ? "ACCEPT ✅" : "REJECT ❌");
  return ok ? 0 : 1;
}
