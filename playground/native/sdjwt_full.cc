// M5 + M6a: full SD-JWT-VC selective-disclosure ZK proof (Approach C),
// supporting MULTIPLE attributes disclosed at once.
//
// Proven in zero knowledge, given issuer pubkey + now + N requested patterns:
//   1. issuer ES256 signature over the JWT (header.payload) is valid
//   2. now <= exp        (credential not expired)
//   for each of N disclosures:
//   3. SHA-256(disclosure) is a member of the signed `_sd` set
//   4. the disclosure decodes to ["<salt>",<pattern>]  where <pattern> =
//      `","<claim>",<value>]` is a PUBLIC input (the verifier's request)
// hiding the signature, salts, and all non-disclosed claims. Any value type.
//
// (Holder Key Binding: see M6b. Front-end mirrors circuits/tests/jwt.)

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <sys/stat.h>

#include <openssl/sha.h>
#include <zstd.h>

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
#include "proto/circuit_io.h"
#include "proto/circuit_reader.h"
#include "proto/circuit_writer.h"
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
constexpr size_t PRE = 64 * kMaxSHA;
constexpr size_t DECP = 64 * (kMaxSHA - 2);
constexpr size_t LOGM = 11;
constexpr size_t MAXB = 2;              // SHA blocks per disclosure
constexpr size_t MAXDD = (64 * MAXB * 6) / 8;
constexpr size_t MAXPAT = 96;          // max disclosure suffix pattern
constexpr size_t MAXVCT = 80;          // max `"vct":"<value>"` pattern
// number of disclosures (nattr) is now a runtime parameter
constexpr size_t KBB = 4;              // SHA blocks for KB header.payload (~212B)
constexpr size_t DECKB = 64 * KBB;     // KB payload decode buffer
constexpr size_t PB = 18;              // SHA blocks for the presented SD-JWT
constexpr size_t PRES = 64 * PB;       // presented bytes (issuer-jwt~disc…~)

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

// Assert that v256 `bits` (LSB-first integer) equals field element `e`.
void bits_eq_elt(const LC& L, const v256& bits, const EltW& e) {
  auto twok = L.one();
  auto est = L.konst(0);
  for (size_t i = 0; i < 256; ++i) {
    est = L.axpy(est, twok, L.eval(bits[i]));
    L.f_.add(twok, twok);
  }
  L.assert_eq(est, e);
}

// =================== per-disclosure inputs ===================
struct Slot {
  // public: the requested suffix pattern  `","<claim>",<value>]`
  v8 pattern[MAXPAT];
  v8 patlen;
  // private
  v8 disc_pre[64 * MAXB];
  v256 disc_ebits;
  SBW disc_sha[MAXB];
  v8 disc_nb;
  LC::bitvec<8> disc_len, disc_shift;
  LC::bitvec<LOGM> sd_idx;
};

struct Inputs {
  // public
  EltW pkX, pkY;
  v8 now[10];
  v8 vct_pat[MAXVCT];  // requested `"vct":"<type>"` (public)
  v8 vct_len;
  EltW e2;            // KB message hash (verifier computes from kbjwt)
  std::vector<Slot> slot;
  // private: front-end
  EltW e_;
  EcdsaW sig;
  v8 preimage[PRE];
  v256 e_bits;
  SBW sha[kMaxSHA];
  v8 nb;
  LC::bitvec<LOGM> payload_ind, payload_len, exp_idx, vct_idx;
  // private: Key Binding
  EltW dpkx, dpky;            // holder device key (from cnf.jwk)
  v256 dpkx_bits, dpky_bits;  // its coords as bits (bound to cnf in payload)
  EcdsaW kb_sig;
  LC::bitvec<LOGM> cnf_x_idx, cnf_y_idx;
  // private: sd_hash binding (Method A) — bind KB to the presented disclosures
  v8 kb_pre[DECKB];           // KB header.payload bytes (SHA == e2)
  SBW kb_sha[KBB];
  v8 kb_nb;
  v256 e2_bits;               // SHA(kb_pre) bits (== e2)
  LC::bitvec<LOGM> kb_pl_ind, kb_pl_len, sd_hash_idx;
  v8 presented[PRES];         // issuer-jwt~disc1~…~discN~  (SHA == sd_hash)
  SBW pres_sha[PB];
  v8 pres_nb;
  v256 pres_hash_bits;
  std::vector<LC::bitvec<LOGM>> disc_in_pres;  // offset of each disclosure in presented
};

void declare_inputs(const LC& L, QuadCircuit<Fp256Base>& Q, Inputs& in,
                    size_t nattr) {
  in.slot.resize(nattr);
  in.disc_in_pres.resize(nattr);
  in.pkX = L.eltw_input();
  in.pkY = L.eltw_input();
  for (size_t i = 0; i < 10; ++i) in.now[i] = L.template vinput<8>();
  for (size_t i = 0; i < MAXVCT; ++i) in.vct_pat[i] = L.template vinput<8>();
  in.vct_len = L.template vinput<8>();
  in.e2 = L.eltw_input();
  for (size_t s = 0; s < nattr; ++s) {
    for (size_t i = 0; i < MAXPAT; ++i) in.slot[s].pattern[i] = L.template vinput<8>();
    in.slot[s].patlen = L.template vinput<8>();
  }
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
  in.vct_idx = L.template vinput<LOGM>();
  in.dpkx = L.eltw_input();
  in.dpky = L.eltw_input();
  in.dpkx_bits = L.template vinput<256>();
  in.dpky_bits = L.template vinput<256>();
  in.kb_sig.input(L);
  in.cnf_x_idx = L.template vinput<LOGM>();
  in.cnf_y_idx = L.template vinput<LOGM>();
  // sd_hash binding
  for (size_t i = 0; i < DECKB; ++i) in.kb_pre[i] = L.template vinput<8>();
  for (size_t i = 0; i < KBB; ++i) in.kb_sha[i].input(L);
  in.kb_nb = L.template vinput<8>();
  in.e2_bits = L.template vinput<256>();
  in.kb_pl_ind = L.template vinput<LOGM>();
  in.kb_pl_len = L.template vinput<LOGM>();
  in.sd_hash_idx = L.template vinput<LOGM>();
  for (size_t i = 0; i < PRES; ++i) in.presented[i] = L.template vinput<8>();
  for (size_t i = 0; i < PB; ++i) in.pres_sha[i].input(L);
  in.pres_nb = L.template vinput<8>();
  in.pres_hash_bits = L.template vinput<256>();
  for (size_t s = 0; s < nattr; ++s) in.disc_in_pres[s] = L.template vinput<LOGM>();
  for (size_t s = 0; s < nattr; ++s) {
    Slot& sl = in.slot[s];
    for (size_t i = 0; i < 64 * MAXB; ++i) sl.disc_pre[i] = L.template vinput<8>();
    sl.disc_ebits = L.template vinput<256>();
    for (size_t i = 0; i < MAXB; ++i) sl.disc_sha[i].input(L);
    sl.disc_nb = L.template vinput<8>();
    sl.disc_len = L.template vinput<8>();
    sl.disc_shift = L.template vinput<8>();
    sl.sd_idx = L.template vinput<LOGM>();
  }
}

void assert_logic(const LC& L, const Inputs& in) {
  size_t nattr = in.slot.size();
  v8 zero = vb(L, 0);
  Routing<LC> r(L);

  // front-end: issuer signature + payload hash + decode
  Ecdsa ecc(L, p256, n256_order);
  ecc.verify_signature3(in.pkX, in.pkY, in.e_, in.sig);
  FlatSHA sha(L);
  sha.assert_message_hash(kMaxSHA, in.nb, in.preimage, in.e_bits, in.sha);
  L.vassert_is_bit(in.e_bits);
  auto twok = L.one();
  auto est = L.konst(0);
  for (size_t i = 0; i < 256; ++i) {
    est = L.axpy(est, twok, L.eval(in.e_bits[i]));
    L.f_.add(twok, twok);
  }
  L.assert_eq(est, in.e_);

  v8 shift_buf[DECP];
  r.shift(in.payload_ind, DECP, shift_buf, PRE, in.preimage, zero, 3);
  v8 dec[DECP];
  Base64Decoder<LC> b64(L);
  LC::bitvec<LOGM> plen(in.payload_len);
  b64.base64_rawurl_decode_len(shift_buf, dec, DECP, plen);

  // exp
  v8 ed[10];
  r.shift(in.exp_idx, 10, ed, DECP, dec, zero, 3);
  L.assert1(leq_bytes(L, in.now, ed, 10));

  // vct: payload contains the requested `"vct":"<type>"`
  v8 vs[MAXVCT];
  r.shift(in.vct_idx, MAXVCT, vs, DECP, dec, zero, 3);
  for (size_t j = 0; j < MAXVCT; ++j)
    L.assert_implies(L.vlt(j, in.vct_len), L.eq(8, vs[j].data(), in.vct_pat[j].data()));

  // Key Binding: holder signed e2 with the device key, and that device key is
  // the issuer-attested cnf.jwk inside the (hash-committed) payload.
  ecc.verify_signature3(in.dpkx, in.dpky, in.e2, in.kb_sig);
  bits_eq_elt(L, in.dpkx_bits, in.dpkx);
  bits_eq_elt(L, in.dpky_bits, in.dpky);
  auto check_coord = [&](const LC::bitvec<LOGM>& idx, const v256& bits) {
    v8 cc[43];
    r.shift(idx, 43, cc, DECP, dec, zero, 3);
    v8 cb[33];
    b64.base64_rawurl_decode(cc, cb, 43);
    for (size_t j = 0; j < 32; ++j) {
      v8 tb;
      for (size_t c = 0; c < 8; ++c) tb[c] = bits[8 * (31 - j) + c];
      L.assert1(L.eq(8, cb[j].data(), tb.data()));
    }
  };
  check_coord(in.cnf_x_idx, in.dpkx_bits);  // cnf.x in payload == dpkx
  check_coord(in.cnf_y_idx, in.dpky_bits);  // cnf.y in payload == dpky

  // sd_hash binding (Method A): the holder's KB commits (via sd_hash) to the
  // exact presented SD-JWT. Verify that commitment in-circuit.
  // 1) KB header.payload hashes to e2 (the value the holder signed).
  sha.assert_message_hash(KBB, in.kb_nb, in.kb_pre, in.e2_bits, in.kb_sha);
  bits_eq_elt(L, in.e2_bits, in.e2);
  // 2) decode the KB payload, pull out sd_hash (43 base64url chars -> 32 bytes).
  v8 kbshift[DECKB];
  r.shift(in.kb_pl_ind, DECKB, kbshift, DECKB, in.kb_pre, zero, 3);
  v8 kbdec[DECKB];
  LC::bitvec<LOGM> kbpl(in.kb_pl_len);
  b64.base64_rawurl_decode_len(kbshift, kbdec, DECKB, kbpl);
  v8 sdh_b64[43];
  r.shift(in.sd_hash_idx, 43, sdh_b64, DECKB, kbdec, zero, 3);
  v8 sdh[33];
  b64.base64_rawurl_decode(sdh_b64, sdh, 43);
  // 3) SHA(presented) and 4) sd_hash == SHA(presented).
  sha.assert_message_hash(PB, in.pres_nb, in.presented, in.pres_hash_bits, in.pres_sha);
  for (size_t j = 0; j < 32; ++j) {
    v8 tb;
    for (size_t c = 0; c < 8; ++c) tb[c] = in.pres_hash_bits[8 * (31 - j) + c];
    L.assert1(L.eq(8, sdh[j].data(), tb.data()));
  }

  // per-disclosure: membership + structural
  for (size_t s = 0; s < nattr; ++s) {
    const Slot& sl = in.slot[s];

    // SHA(disclosure) == disc_ebits
    sha.assert_message_hash(MAXB, sl.disc_nb, sl.disc_pre, sl.disc_ebits, sl.disc_sha);

    // membership: base64decode(_sd entry @ sd_idx) == disc_ebits
    v8 entry[43];
    r.shift(sl.sd_idx, 43, entry, DECP, dec, zero, 3);
    v8 out[33];
    b64.base64_rawurl_decode(entry, out, 43);
    for (size_t j = 0; j < 32; ++j) {
      v8 tb;
      for (size_t c = 0; c < 8; ++c) tb[c] = sl.disc_ebits[8 * (31 - j) + c];
      L.assert1(L.eq(8, out[j].data(), tb.data()));
    }

    // structural: decode disclosure, verify prefix + suffix == public pattern
    v8 dd[MAXDD];
    LC::bitvec<8> dlen(sl.disc_len);
    b64.base64_rawurl_decode_len(sl.disc_pre, dd, 64 * MAXB, dlen);
    L.assert1(L.eq(8, dd[0].data(), vb(L, '[').data()));
    L.assert1(L.eq(8, dd[1].data(), vb(L, '"').data()));
    v8 S[MAXPAT];
    r.shift(sl.disc_shift, MAXPAT, S, MAXDD, dd, zero, 3);
    for (size_t j = 0; j < MAXPAT; ++j) {
      auto inrange = L.vlt(j, sl.patlen);
      auto same = L.eq(8, S[j].data(), sl.pattern[j].data());
      L.assert_implies(inrange, same);
    }

    // consent binding: this disclosure must appear in `presented` (whose hash
    // the holder signed as sd_hash) -> disclosed ⊆ holder-presented set.
    v8 ps[64 * MAXB];
    r.shift(in.disc_in_pres[s], 64 * MAXB, ps, PRES, in.presented, zero, 3);
    for (size_t j = 0; j < 64 * MAXB; ++j) {
      auto inrange = L.vlt(j, sl.disc_len);
      auto same = L.eq(8, ps[j].data(), sl.disc_pre[j].data());
      L.assert_implies(inrange, same);
    }
  }
}

std::unique_ptr<Circuit<Fp256Base>> make_circuit(size_t nattr) {
  QuadCircuit<Fp256Base> Q(p256_base);
  const CB cbk(&Q);
  const LC L(&cbk, p256_base);
  Inputs in;
  declare_inputs(L, Q, in, nattr);
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
  std::string compact;
  const char* now;
  Fp256Base::Elt pkX, pkY;
  std::vector<std::string> claims;  // names to disclose (NATTR of them)
  std::string vct;                  // expected credential type
};

void push_v8(DenseFiller<Fp256Base>& f, uint8_t b) { f.push_back(b, 8, p256_base); }

void fill_sha(DenseFiller<Fp256Base>& f, BitPluckerEncoder<Fp256Base, kPluck>& enc,
              const FlatSHA256Witness::BlockWitness& b) {
  for (size_t k = 0; k < 48; ++k) f.push_back(enc.mkpacked_v32(b.outw[k]));
  for (size_t k = 0; k < 64; ++k) {
    f.push_back(enc.mkpacked_v32(b.oute[k]));
    f.push_back(enc.mkpacked_v32(b.outa[k]));
  }
  for (size_t k = 0; k < 8; ++k) f.push_back(enc.mkpacked_v32(b.h1[k]));
}

bool fill(Dense<Fp256Base>& W, bool full, const Concrete& c) {
  size_t nattr = c.claims.size();
  DenseFiller<Fp256Base> f(W);
  BitPluckerEncoder<Fp256Base, kPluck> enc(p256_base);

  // ---- gather host data ----
  std::string jwt = c.compact.substr(0, c.compact.find('~'));
  size_t d1 = jwt.find('.'), d2 = jwt.find('.', d1 + 1);
  std::string msg = jwt.substr(0, d2);
  std::string payload_b64 = jwt.substr(d1 + 1, d2 - d1 - 1);
  std::string payload = b64url_decode(payload_b64);

  std::vector<std::string> discs;
  {
    size_t p = c.compact.find('~') + 1, q;
    while ((q = c.compact.find('~', p)) != std::string::npos) {
      if (q > p) discs.push_back(c.compact.substr(p, q - p));
      p = q + 1;
    }
  }
  // pick the disclosure for each requested claim
  std::vector<std::string> chosen(nattr);
  for (size_t s = 0; s < nattr; ++s) {
    std::string key = "\"" + c.claims[s] + "\"";
    for (auto& d : discs)
      if (b64url_decode(d).find(key) != std::string::npos) chosen[s] = d;
    if (chosen[s].empty()) { log(ERROR, "claim %s not found", c.claims[s].c_str()); return false; }
  }

  // ---- Key Binding host data ----
  std::string kbjwt = c.compact.substr(c.compact.rfind('~') + 1);
  size_t kd1 = kbjwt.find('.'), kd2 = kbjwt.find('.', kd1 + 1);
  std::string kbmsg = kbjwt.substr(0, kd2);
  uint8_t kbhash[32];
  ::SHA256((const uint8_t*)kbmsg.data(), kbmsg.size(), kbhash);
  Nat e2_nat = nat_from_be(kbhash);
  Fp256Base::Elt e2 = p256_base.to_montgomery(e2_nat);
  std::string kbsigraw = b64url_decode(kbjwt.substr(kd2 + 1));
  if (kbsigraw.size() < 64) { log(ERROR, "bad kb sig"); return false; }
  Nat kr = nat_from_be((const uint8_t*)kbsigraw.data());
  Nat ks = nat_from_be((const uint8_t*)kbsigraw.data() + 32);
  size_t cnf = payload.find("\"cnf\"");
  size_t xi = payload.find("\"x\":\"", cnf) + 5;
  size_t yi = payload.find("\"y\":\"", cnf) + 5;
  std::string x32 = b64url_decode(payload.substr(xi, 43));
  std::string y32 = b64url_decode(payload.substr(yi, 43));
  Nat nx = nat_from_be((const uint8_t*)x32.data());
  Nat ny = nat_from_be((const uint8_t*)y32.data());
  Fp256Base::Elt dpkx = p256_base.to_montgomery(nx);
  Fp256Base::Elt dpky = p256_base.to_montgomery(ny);

  // ---- public ----
  f.push_back(p256_base.one());
  f.push_back(c.pkX);
  f.push_back(c.pkY);
  for (size_t i = 0; i < 10; ++i) push_v8(f, (uint8_t)c.now[i]);
  std::string vct_pat = "\"vct\":\"" + c.vct + "\"";
  for (size_t i = 0; i < MAXVCT; ++i) push_v8(f, i < vct_pat.size() ? (uint8_t)vct_pat[i] : 0);
  push_v8(f, (uint8_t)vct_pat.size());
  f.push_back(e2);
  for (size_t s = 0; s < nattr; ++s) {
    std::string dj = b64url_decode(chosen[s]);
    size_t salt_len = dj.find("\",\"") - 2;
    std::string pat = dj.substr(2 + salt_len);  // `","claim",value]`
    for (size_t i = 0; i < MAXPAT; ++i) push_v8(f, i < pat.size() ? (uint8_t)pat[i] : 0);
    push_v8(f, (uint8_t)pat.size());
  }
  if (!full) return true;

  // ---- private front-end ----
  uint8_t pre[PRE];
  FlatSHA256Witness::BlockWitness bw[kMaxSHA];
  uint8_t numb = 0;
  FlatSHA256Witness::transform_and_witness_message(
      msg.size(), (const uint8_t*)msg.data(), kMaxSHA, numb, pre, bw);
  uint8_t hash[32];
  ::SHA256((const uint8_t*)msg.data(), msg.size(), hash);
  Nat ne = nat_from_be(hash);
  std::string sigraw = b64url_decode(jwt.substr(d2 + 1));
  if (sigraw.size() < 64) { log(ERROR, "bad sig"); return false; }
  Nat nr = nat_from_be((const uint8_t*)sigraw.data());
  Nat ns = nat_from_be((const uint8_t*)sigraw.data() + 32);
  EcdsaHostW sw(p256_scalar, p256);
  if (!sw.compute_witness(c.pkX, c.pkY, ne, nr, ns)) { log(ERROR, "issuer sig invalid"); return false; }
  size_t exp_idx = payload.find("\"exp\":") + 6;

  f.push_back(p256_base.to_montgomery(ne));  // e_
  sw.fill_witness(f);                        // sig
  for (size_t i = 0; i < PRE; ++i) push_v8(f, pre[i]);
  for (size_t i = 0; i < 256; ++i) f.push_back(ne.bit(i), 1, p256_base);  // e_bits
  for (size_t i = 0; i < kMaxSHA; ++i) fill_sha(f, enc, bw[i]);
  push_v8(f, numb);
  f.push_back(d1 + 1, LOGM, p256_base);
  f.push_back(payload_b64.size(), LOGM, p256_base);
  f.push_back(exp_idx, LOGM, p256_base);
  f.push_back(payload.find(vct_pat), LOGM, p256_base);  // vct_idx

  // ---- private Key Binding ----
  f.push_back(dpkx);
  f.push_back(dpky);
  for (size_t i = 0; i < 256; ++i) f.push_back(nx.bit(i), 1, p256_base);
  for (size_t i = 0; i < 256; ++i) f.push_back(ny.bit(i), 1, p256_base);
  EcdsaHostW kbw(p256_scalar, p256);
  if (!kbw.compute_witness(dpkx, dpky, e2_nat, kr, ks)) {
    log(ERROR, "KB signature invalid");
    return false;
  }
  kbw.fill_witness(f);
  f.push_back(xi, LOGM, p256_base);
  f.push_back(yi, LOGM, p256_base);

  // ---- private sd_hash binding (Method A) ----
  std::string presented = c.compact.substr(0, c.compact.rfind('~') + 1);
  uint8_t pres_in[PRES];
  FlatSHA256Witness::BlockWitness pres_bw[PB];
  uint8_t pres_numb = 0;
  FlatSHA256Witness::transform_and_witness_message(
      presented.size(), (const uint8_t*)presented.data(), PB, pres_numb, pres_in, pres_bw);
  uint8_t predig[32];
  ::SHA256((const uint8_t*)presented.data(), presented.size(), predig);

  std::string kbhp = kbjwt.substr(0, kd2);  // KB header.payload
  uint8_t kb_in[DECKB];
  FlatSHA256Witness::BlockWitness kb_bw[KBB];
  uint8_t kb_numb = 0;
  FlatSHA256Witness::transform_and_witness_message(
      kbhp.size(), (const uint8_t*)kbhp.data(), KBB, kb_numb, kb_in, kb_bw);
  std::string kb_pl_b64 = kbjwt.substr(kd1 + 1, kd2 - kd1 - 1);
  std::string kb_pl = b64url_decode(kb_pl_b64);
  size_t sdh_pos = kb_pl.find("\"sd_hash\":\"") + 11;

  for (size_t i = 0; i < DECKB; ++i) push_v8(f, kb_in[i]);
  for (size_t i = 0; i < KBB; ++i) fill_sha(f, enc, kb_bw[i]);
  push_v8(f, kb_numb);
  for (size_t i = 0; i < 256; ++i) f.push_back(e2_nat.bit(i), 1, p256_base);
  f.push_back(kd1 + 1, LOGM, p256_base);
  f.push_back(kb_pl_b64.size(), LOGM, p256_base);
  f.push_back(sdh_pos, LOGM, p256_base);
  for (size_t i = 0; i < PRES; ++i) push_v8(f, pres_in[i]);
  for (size_t i = 0; i < PB; ++i) fill_sha(f, enc, pres_bw[i]);
  push_v8(f, pres_numb);
  for (size_t i = 0; i < 256; ++i) f.push_back((predig[31 - i / 8] >> (i % 8)) & 1, 1, p256_base);
  for (size_t s = 0; s < nattr; ++s)
    f.push_back(presented.find(chosen[s]), LOGM, p256_base);

  // ---- private per-slot ----
  for (size_t s = 0; s < nattr; ++s) {
    const std::string& disc = chosen[s];
    uint8_t dg[32];
    ::SHA256((const uint8_t*)disc.data(), disc.size(), dg);
    std::string entry = b64url_encode(dg, 32);
    size_t sd_idx = payload.find(entry);
    if (sd_idx == std::string::npos) { log(ERROR, "digest not in _sd"); return false; }
    std::string dj = b64url_decode(disc);
    size_t salt_len = dj.find("\",\"") - 2;
    uint8_t din[64 * MAXB];
    FlatSHA256Witness::BlockWitness dbw[MAXB];
    uint8_t dnumb = 0;
    FlatSHA256Witness::transform_and_witness_message(
        disc.size(), (const uint8_t*)disc.data(), MAXB, dnumb, din, dbw);

    for (size_t i = 0; i < 64 * MAXB; ++i) push_v8(f, din[i]);
    for (size_t i = 0; i < 256; ++i) f.push_back((dg[31 - i / 8] >> (i % 8)) & 1, 1, p256_base);
    for (size_t i = 0; i < MAXB; ++i) fill_sha(f, enc, dbw[i]);
    push_v8(f, dnumb);
    push_v8(f, (uint8_t)disc.size());
    push_v8(f, (uint8_t)(2 + salt_len));
    f.push_back(sd_idx, LOGM, p256_base);
  }
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
  // argv[4]: comma-separated claim names; argv[5]: expected vct
  if (argc > 4) {
    std::string cs = argv[4];
    size_t p = 0, q;
    while ((q = cs.find(',', p)) != std::string::npos) { c.claims.push_back(cs.substr(p, q - p)); p = q + 1; }
    c.claims.push_back(cs.substr(p));
  } else {
    c.claims = {"given_name", "age_over_18", "height"};  // string, boolean, number
  }
  c.vct = (argc > 5) ? argv[5] : "https://credentials.example/pid";

  std::string j = read_file(jwk);
  auto hex = [&](const char* key) {
    size_t i = j.find(key); i = j.find("0x", i);
    return j.substr(i, j.find('"', i) - i);
  };
  c.pkX = p256_base.of_untrusted_string(hex("x_hex").c_str()).value();
  c.pkY = p256_base.of_untrusted_string(hex("y_hex").c_str()).value();
  size_t nattr = c.claims.size();

  // Circuit cache: the compiled circuit depends only on nattr. Cache it next to
  // the binary so repeat runs skip the ~20s compile.
  std::string bindir(argv[0]);
  size_t sl = bindir.rfind('/');
  std::string cacheDir = (sl == std::string::npos ? std::string(".") : bindir.substr(0, sl)) + "/../circuits-cache";
  mkdir(cacheDir.c_str(), 0755);
  std::string cacheFile = cacheDir + "/sdjwt-" + std::to_string(nattr) + "attr.bin";

  std::unique_ptr<Circuit<Fp256Base>> C;
  std::ifstream cf(cacheFile, std::ios::binary);
  auto t0 = std::chrono::steady_clock::now();
  if (cf.good()) {
    std::vector<uint8_t> comp((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
    cf.close();
    uint64_t osz = 0;
    memcpy(&osz, comp.data(), 8);
    std::vector<uint8_t> bytes(osz);
    ZSTD_decompress(bytes.data(), osz, comp.data() + 8, comp.size() - 8);
    ReadBuffer rb(bytes);
    CircuitReader<Fp256Base> rdr(p256_base, P256_ID);
    C = rdr.from_bytes(rb, /*enforce_circuit_id=*/false);
    printf("M6: loaded cached %zu-attr circuit (%zu KB compressed)\n", nattr, comp.size() / 1024);
  } else {
    printf("M6: compiling %zu-attr SD-JWT-VC ZK circuit (issuer sig + KB + sd_hash + vct + exp + N×_sd)...\n", nattr);
    C = make_circuit(nattr);
    std::vector<uint8_t> bytes;
    CircuitWriter<Fp256Base> wr(p256_base, P256_ID);
    wr.to_bytes(*C, bytes);
    size_t bound = ZSTD_compressBound(bytes.size());
    std::vector<uint8_t> comp(8 + bound);
    uint64_t osz = bytes.size();
    memcpy(comp.data(), &osz, 8);
    size_t csz = ZSTD_compress(comp.data() + 8, bound, bytes.data(), bytes.size(), 6);
    std::ofstream of(cacheFile, std::ios::binary);
    of.write((const char*)comp.data(), 8 + csz);
    printf("M6: compiled + cached %zu-attr circuit (%zu KB compressed from %zu KB)\n",
           nattr, (8 + csz) / 1024, bytes.size() / 1024);
  }
  auto t1 = std::chrono::steady_clock::now();
  printf("  circuit ready in %ld ms: ninputs=%zu npub_in=%zu nl=%zu\n",
         (long)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count(),
         C->ninputs, C->npub_in, C->nl);
  printf("  disclosing: ");
  for (auto& cl : c.claims) printf("%s ", cl.c_str());
  printf("\n");

  auto W = Dense<Fp256Base>(1, C->ninputs);
  auto pub = Dense<Fp256Base>(1, C->npub_in);
  if (!fill(W, true, c) || !fill(pub, false, c)) { printf("  fill failed\n"); return 1; }

  printf("M6: ZK prove/verify...\n");
  bool ok = run_zk(*C, W, pub);
  printf("  result: %s (%zu attrs + issuer sig + KB + sd_hash + vct + exp, one ZK proof)\n",
         ok ? "ACCEPT ✅" : "REJECT ❌", nattr);
  return ok ? 0 : 1;
}
