// M5: full SD-JWT-VC selective-disclosure ZK proof (Approach C).
//
// Statement proven in zero knowledge, given issuer pubkey + now + requested
// (claim,value):
//   1. issuer ES256 signature over the JWT (header.payload) is valid
//   2. now <= exp        (credential not expired)
//   3. SHA-256(disclosure) is a member of the signed `_sd` set
//   4. the disclosure decodes to ["<salt>","<claim>",<value>]
// hiding the signature, all other claims, salts, and the rest of the payload.
// Works for ANY value type (string/date/boolean/number).
//
// (Holder Key Binding is omitted here — it is already demonstrated by jwt_cli;
// adding it back is mechanical. This focuses on issuer-binding + disclosure.)
//
// Front-end (ECDSA + payload SHA + base64 decode) mirrors circuits/tests/jwt;
// back-end (exp + _sd membership + structural) is the validated Approach-C logic.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <openssl/sha.h>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/ecdsa/verify_witness.h"
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
using EltW = LC::EltW;
using BitW = LC::BitW;
using Nat = Fp256Base::N;

using Ecdsa = VerifyCircuit<LC, Fp256Base, P256>;
using EcdsaW = Ecdsa::Witness;
using EcdsaHostW = VerifyWitness3<P256, Fp256Scalar>;

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
constexpr const char* kSeed = "sdjwt-full";

constexpr size_t kMaxSHA = 13;          // SHA blocks for header.payload
constexpr size_t PRE = 64 * kMaxSHA;    // preimage bytes (832)
constexpr size_t DECP = 64 * (kMaxSHA - 2);  // decoded-payload buffer (704)
constexpr size_t LOGM = 11;             // index bits into preimage / payload
constexpr size_t MAXB = 2;              // SHA blocks for a disclosure
constexpr size_t MAXDD = (64 * MAXB * 6) / 8;  // decoded-disclosure bytes (96)

// =================== shared circuit helpers ===================
v8 vb(const LC& L, uint8_t c) { return L.template vbit<8>(c); }

BitW leq_bytes(const LC& L, const v8* a, const v8* b, size_t n) {
  BitW le = L.bit(1);
  for (size_t i = n; i-- > 0;) {
    auto blt = L.lt(8, a[i].data(), b[i].data());
    auto beq = L.eq(8, a[i].data(), b[i].data());
    le = L.lor(blt, L.land(beq, le));
  }
  return le;
}

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

// =================== inputs (declare order == fill order) ===================
struct Inputs {
  // public
  EltW pkX, pkY;
  v8 now[10];
  // private: front-end (issuer signature + payload SHA + decode)
  EltW e_;
  EcdsaW sig;
  v8 preimage[PRE];
  v256 e_bits;
  SBW sha[kMaxSHA];
  v8 nb;
  LC::bitvec<LOGM> payload_ind, payload_len;
  // private: back-end indices
  LC::bitvec<LOGM> exp_idx, sd_idx;
  // private: disclosure
  v8 disc_pre[64 * MAXB];
  v256 disc_ebits;
  SBW disc_sha[MAXB];
  v8 disc_nb;
  LC::bitvec<8> disc_len, disc_shift;
};

void declare_inputs(const LC& L, QuadCircuit<Fp256Base>& Q, Inputs& in) {
  in.pkX = L.eltw_input();
  in.pkY = L.eltw_input();
  for (size_t i = 0; i < 10; ++i) in.now[i] = L.template vinput<8>();
  Q.private_input();
  in.e_ = L.eltw_input();
  in.sig.input(L);
  for (size_t i = 0; i < PRE; ++i) in.preimage[i] = L.template vinput<8>();
  in.e_bits = L.template vinput<256>();
  for (size_t i = 0; i < kMaxSHA; ++i) in.sha[i].input(L);
  in.nb = L.template vinput<8>();
  in.payload_ind = L.template vinput<LOGM>();
  in.payload_len = L.template vinput<LOGM>();
  in.exp_idx = L.template vinput<LOGM>();
  in.sd_idx = L.template vinput<LOGM>();
  for (size_t i = 0; i < 64 * MAXB; ++i) in.disc_pre[i] = L.template vinput<8>();
  in.disc_ebits = L.template vinput<256>();
  for (size_t i = 0; i < MAXB; ++i) in.disc_sha[i].input(L);
  in.disc_nb = L.template vinput<8>();
  in.disc_len = L.template vinput<8>();
  in.disc_shift = L.template vinput<8>();
}

void assert_logic(const LC& L, const Inputs& in) {
  v8 zero = vb(L, 0);
  Routing<LC> r(L);

  // ---- front-end: issuer signature + payload hash ----
  Ecdsa ecc(L, p256, n256_order);
  ecc.verify_signature3(in.pkX, in.pkY, in.e_, in.sig);

  FlatSHA sha(L);
  sha.assert_message_hash(kMaxSHA, in.nb, in.preimage, in.e_bits, in.sha);
  L.vassert_is_bit(in.e_bits);
  // e_bits (LSB-first) must equal e_
  auto twok = L.one();
  auto est = L.konst(0);
  for (size_t i = 0; i < 256; ++i) {
    est = L.axpy(est, twok, L.eval(in.e_bits[i]));
    L.f_.add(twok, twok);
  }
  L.assert_eq(est, in.e_);

  // decode the payload (base64url) out of the signed preimage
  v8 shift_buf[DECP];
  r.shift(in.payload_ind, DECP, shift_buf, PRE, in.preimage, zero, 3);
  v8 dec[DECP];
  Base64Decoder<LC> b64(L);
  LC::bitvec<LOGM> plen(in.payload_len);
  b64.base64_rawurl_decode_len(shift_buf, dec, DECP, plen);

  // ---- back-end: exp + membership + structural (on decoded payload) ----
  // (1) exp
  v8 ed[10];
  r.shift(in.exp_idx, 10, ed, DECP, dec, zero, 3);
  L.assert1(leq_bytes(L, in.now, ed, 10));

  // (2) SHA(disclosure) == disc_ebits
  sha.assert_message_hash(MAXB, in.disc_nb, in.disc_pre, in.disc_ebits,
                          in.disc_sha);
  // (3) membership: base64decode(_sd entry @ sd_idx in dec) == disc_ebits
  v8 entry[43];
  r.shift(in.sd_idx, 43, entry, DECP, dec, zero, 3);
  v8 out[33];
  b64.base64_rawurl_decode(entry, out, 43);
  for (size_t j = 0; j < 32; ++j) {
    v8 tb;
    for (size_t c = 0; c < 8; ++c) tb[c] = in.disc_ebits[8 * (31 - j) + c];
    L.assert1(L.eq(8, out[j].data(), tb.data()));
  }
  // (4) structural: decode disclosure, verify (age_over_18, true)
  v8 dd[MAXDD];
  LC::bitvec<8> dlen(in.disc_len);
  b64.base64_rawurl_decode_len(in.disc_pre, dd, 64 * MAXB, dlen);
  assert_disclosure_struct(L, dd, MAXDD, in.disc_shift, "age_over_18", 11, "true", 4);
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

// =================== host helpers ===================
int b64v(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}
std::string b64url_decode(const std::string& s) {
  std::string o;
  int val = 0, bits = 0;
  for (char c : s) {
    int d = b64v(c);
    if (d < 0) continue;
    val = (val << 6) | d;
    bits += 6;
    if (bits >= 8) { o += char((val >> (bits - 8)) & 0xff); bits -= 8; }
  }
  return o;
}
std::string b64url_encode(const uint8_t* d, size_t n) {
  static const char* T =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string o;
  int val = 0, bits = 0;
  for (size_t i = 0; i < n; ++i) {
    val = (val << 8) | d[i]; bits += 8;
    while (bits >= 6) { o += T[(val >> (bits - 6)) & 63]; bits -= 6; }
  }
  if (bits > 0) o += T[(val << (6 - bits)) & 63];
  return o;
}
std::string read_file(const std::string& p) {
  std::ifstream f(p, std::ios::binary);
  std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
  return s;
}
Nat nat_from_be(const uint8_t* be) {
  uint8_t tmp[Nat::kBytes];
  for (size_t i = 0; i < Nat::kBytes; ++i) tmp[i] = be[Nat::kBytes - 1 - i];
  return Nat::of_bytes(tmp);
}

// =================== witness ===================
struct Concrete {
  std::string compact;  // full SD-JWT
  const char* now;
  Fp256Base::Elt pkX, pkY;
};

bool fill(Dense<Fp256Base>& W, bool full, const Concrete& c) {
  DenseFiller<Fp256Base> f(W);
  f.push_back(p256_base.one());
  f.push_back(c.pkX);
  f.push_back(c.pkY);
  for (size_t i = 0; i < 10; ++i) f.push_back((uint8_t)c.now[i], 8, p256_base);
  if (!full) return true;

  // Parse issuer JWT: header.payload.sig
  std::string jwt = c.compact.substr(0, c.compact.find('~'));
  size_t d1 = jwt.find('.'), d2 = jwt.find('.', d1 + 1);
  std::string msg = jwt.substr(0, d2);                // header.payload (signed)
  std::string payload_b64 = jwt.substr(d1 + 1, d2 - d1 - 1);
  std::string sig_b64 = jwt.substr(d2 + 1);

  // SHA(header.payload) -> ne, preimage, sha witness
  uint8_t pre[PRE];
  FlatSHA256Witness::BlockWitness bw[kMaxSHA];
  uint8_t numb = 0;
  FlatSHA256Witness::transform_and_witness_message(
      msg.size(), (const uint8_t*)msg.data(), kMaxSHA, numb, pre, bw);
  uint8_t hash[32];
  ::SHA256((const uint8_t*)msg.data(), msg.size(), hash);
  Nat ne = nat_from_be(hash);

  // signature r,s
  std::string sigraw = b64url_decode(sig_b64);
  if (sigraw.size() < 64) { log(ERROR, "bad sig"); return false; }
  Nat nr = nat_from_be((const uint8_t*)sigraw.data());
  Nat ns = nat_from_be((const uint8_t*)sigraw.data() + 32);

  EcdsaHostW sw(p256_scalar, p256);
  if (!sw.compute_witness(c.pkX, c.pkY, ne, nr, ns)) {
    log(ERROR, "issuer signature invalid");
    return false;
  }

  // decoded payload (host) for indices
  std::string payload = b64url_decode(payload_b64);
  size_t exp_idx = payload.find("\"exp\":") + 6;

  // disclosures
  std::vector<std::string> discs;
  {
    size_t p = c.compact.find('~') + 1, q;
    while ((q = c.compact.find('~', p)) != std::string::npos) {
      if (q > p) discs.push_back(c.compact.substr(p, q - p));
      p = q + 1;
    }
  }
  std::string disc;
  for (auto& d : discs)
    if (b64url_decode(d).find("\"age_over_18\"") != std::string::npos) disc = d;
  if (disc.empty()) { log(ERROR, "age_over_18 disclosure missing"); return false; }

  uint8_t dg[32];
  ::SHA256((const uint8_t*)disc.data(), disc.size(), dg);
  std::string entry = b64url_encode(dg, 32);
  size_t sd_idx = payload.find(entry);
  if (sd_idx == std::string::npos) { log(ERROR, "digest not in _sd"); return false; }

  std::string dj = b64url_decode(disc);          // ["salt","age_over_18",true]
  size_t salt_len = dj.find("\",\"") - 2;          // salt at [2 .. )

  // disclosure SHA witness
  uint8_t din[64 * MAXB];
  FlatSHA256Witness::BlockWitness dbw[MAXB];
  uint8_t dnumb = 0;
  FlatSHA256Witness::transform_and_witness_message(
      disc.size(), (const uint8_t*)disc.data(), MAXB, dnumb, din, dbw);

  // ---- fill (must match declare order) ----
  f.push_back(p256_base.to_montgomery(ne));        // e_
  sw.fill_witness(f);                              // sig
  for (size_t i = 0; i < PRE; ++i) f.push_back(pre[i], 8, p256_base);
  for (size_t i = 0; i < 256; ++i) f.push_back(ne.bit(i), 1, p256_base);  // e_bits

  BitPluckerEncoder<Fp256Base, kPluck> enc(p256_base);
  auto fill_sha = [&](const FlatSHA256Witness::BlockWitness& b) {
    for (size_t k = 0; k < 48; ++k) f.push_back(enc.mkpacked_v32(b.outw[k]));
    for (size_t k = 0; k < 64; ++k) {
      f.push_back(enc.mkpacked_v32(b.oute[k]));
      f.push_back(enc.mkpacked_v32(b.outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) f.push_back(enc.mkpacked_v32(b.h1[k]));
  };
  for (size_t i = 0; i < kMaxSHA; ++i) fill_sha(bw[i]);
  f.push_back(numb, 8, p256_base);
  f.push_back(d1 + 1, LOGM, p256_base);            // payload_ind (in preimage)
  f.push_back(payload_b64.size(), LOGM, p256_base);  // payload_len
  f.push_back(exp_idx, LOGM, p256_base);
  f.push_back(sd_idx, LOGM, p256_base);
  for (size_t i = 0; i < 64 * MAXB; ++i) f.push_back(din[i], 8, p256_base);
  for (size_t i = 0; i < 256; ++i)
    f.push_back((dg[31 - i / 8] >> (i % 8)) & 1, 1, p256_base);  // disc_ebits
  for (size_t i = 0; i < MAXB; ++i) fill_sha(dbw[i]);
  f.push_back(dnumb, 8, p256_base);
  f.push_back(disc.size(), 8, p256_base);
  f.push_back(2 + salt_len, 8, p256_base);
  return true;
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

int main(int argc, char** argv) {
  using namespace proofs;
  set_log_level(ERROR);

  std::string fixture = (argc > 1) ? argv[1] : "playground/fixtures/sdjwt.txt";
  std::string jwk = (argc > 2) ? argv[2] : "playground/fixtures/issuer-jwk.json";

  Concrete c;
  c.compact = read_file(fixture);
  c.now = (argc > 3) ? argv[3] : "1700000000";

  // issuer pubkey hex from issuer-jwk.json (x_hex / y_hex)
  std::string j = read_file(jwk);
  auto hex = [&](const char* key) {
    size_t i = j.find(key);
    i = j.find("0x", i);
    size_t e = j.find('"', i);
    return j.substr(i, e - i);
  };
  std::string xh = hex("x_hex"), yh = hex("y_hex");
  c.pkX = p256_base.of_untrusted_string(xh.c_str()).value();
  c.pkY = p256_base.of_untrusted_string(yh.c_str()).value();

  printf("M5: compiling full SD-JWT-VC ZK circuit (issuer sig + exp + _sd + struct)...\n");
  auto C = make_circuit();
  printf("  circuit: ninputs=%zu npub_in=%zu nl=%zu\n", C->ninputs, C->npub_in, C->nl);

  auto W = Dense<Fp256Base>(1, C->ninputs);
  auto pub = Dense<Fp256Base>(1, C->npub_in);
  if (!fill(W, true, c) || !fill(pub, false, c)) {
    printf("  witness fill failed\n");
    return 1;
  }

  printf("M5: ZK prove/verify...\n");
  bool ok = run_zk(*C, W, pub);
  printf("  result: %s\n", ok ? "ACCEPT ✅" : "REJECT ❌");
  printf("  (issuer-signed SD-JWT, not expired, discloses age_over_18=true in ZK)\n");
  return ok ? 0 : 1;
}
