// sdjwt_common.h — shared base for the SD-JWT-VC two-circuit (Fp256 sig +
// GF(2^128) hash) + MAC family of CLIs (split / null_split / null_blind /
// revoc_split). This is the SINGLE SOURCE OF TRUTH for everything that used to
// be copy-pasted across those files: includes, circuit capacities, byte/SHA
// helpers, the MAC machinery (a_p/a_v, compute/update), the circuit cache, and
// check_capacity. The per-feature .cc files #include this and add only their
// own feature block (nullifier / blind nullifier / revocation).
//
// Stage A scope: infrastructure + constants + helpers + check_capacity only.
// The sig/hash circuit *builders* still live in each .cc for now (Stage B will
// fold their shared base in here too).
#ifndef SDJWT_COMMON_H_
#define SDJWT_COMMON_H_

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <functional>
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
#include "circuits/mac/mac_circuit.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mac/mac_witness.h"
#include "circuits/mdoc/mdoc_signature.h"
#include "circuits/mdoc/mdoc_witness.h"  // fill_bit_string
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "circuits/tests/base64/decode.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
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

// ===================== shared helpers =====================
using f_128 = GF2_128<>;
using gf2k = f_128::Elt;
constexpr size_t kRate = 7, kNreq = 132, kVer = 7;

static int b64v(char c){if(c>='A'&&c<='Z')return c-'A';if(c>='a'&&c<='z')return c-'a'+26;if(c>='0'&&c<='9')return c-'0'+52;if(c=='-')return 62;if(c=='_')return 63;return -1;}
static std::string b64d(const std::string& s){std::string o;int v=0,b=0;for(char c:s){int d=b64v(c);if(d<0)continue;v=(v<<6)|d;b+=6;if(b>=8){o+=char((v>>(b-8))&0xff);b-=8;}}return o;}
static std::string b64e(const uint8_t* d,size_t n){static const char* T="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";std::string o;int v=0,b=0;for(size_t i=0;i<n;++i){v=(v<<8)|d[i];b+=8;while(b>=6){o+=T[(v>>(b-6))&63];b-=6;}}if(b>0)o+=T[(v<<(6-b))&63];return o;}
static std::string rf(const std::string&p){std::ifstream f(p,std::ios::binary);std::string s((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back();return s;}

// The prover's half of the MAC key (a_p). a_v and the macs are derived AFTER
// commitment (from the transcript) — this is what makes the link sound: the
// prover commits a_p and the values e/dpkx/dpky(/e_span) before learning a_v,
// so it cannot make two different values pass the same public mac (Schwartz-
// Zippel). ap is sized for the widest case (4 linked values × 2 = 8); callers
// use only the first 2*nv entries.
struct Linker { gf2k ap[8]; };

// a_v = a fresh field element pulled from the (post-commit) transcript.
inline gf2k generate_mac_key(Transcript& t, const f_128& gf) {
  uint8_t buf[f_128::kBytes];
  t.bytes(buf, f_128::kBytes);
  return gf.of_bytes_field(buf).value();
}

// MAC the `nv` common Fp256 values x[0..nv) -> gmacs[0..2*nv) (+ bundle bytes).
inline void compute_macs(const Fp256Base::Elt* x, int nv, gf2k* gmacs,
                         uint8_t* macs_b, const gf2k* ap, gf2k av,
                         const f_128& gf) {
  MACReference<f_128> mr;
  for (int i = 0; i < nv; ++i) {
    uint8_t buf[32];
    p256_base.to_bytes_field(buf, x[i]);
    mr.compute(&gmacs[2 * i], av, &ap[2 * i], buf);
    gf.to_bytes_field(&macs_b[2 * i * f_128::kBytes], gmacs[2 * i]);
    gf.to_bytes_field(&macs_b[(2 * i + 1) * f_128::kBytes], gmacs[2 * i + 1]);
  }
}

// Write the `nmac` macs (=2*nv) + av into the dense arrays AT/AFTER commit
// (public-input wires are not part of the hiding commitment). si/hi point at
// the first mac wire; sig stores each as 128 bits, hash as one native gf2k.
// (Mirrors mdoc's update_macs.)
inline void update_macs(Dense<Fp256Base>& Ws, Dense<f_128>& Wh, size_t si, size_t hi,
                        const gf2k* gmacs, int nmac, gf2k av) {
  auto put = [&](const gf2k& m) {
    for (size_t j = 0; j < f_128::kBits; ++j)
      Ws.v_[si++] = m[j] ? p256_base.one() : p256_base.zero();
    Wh.v_[hi++] = m;
  };
  for (int mi = 0; mi < nmac; ++mi) put(gmacs[mi]);
  put(av);
}

struct Result { long prove_ms = 0; size_t proof_kb = 0, circ_kb = 0, ninputs = 0; bool ok = false; };

// generic cache load/store for a compiled circuit
template <class Field>
std::unique_ptr<Circuit<Field>> get_circuit(const Field& F, FieldID fid,
    const std::string& cacheFile, std::function<std::unique_ptr<Circuit<Field>>()> build,
    size_t& circ_kb) {
  std::ifstream cf(cacheFile, std::ios::binary);
  if (cf.good()) {
    std::vector<uint8_t> comp((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
    cf.close();
    uint64_t osz = 0; memcpy(&osz, comp.data(), 8);
    std::vector<uint8_t> bytes(osz);
    ZSTD_decompress(bytes.data(), osz, comp.data() + 8, comp.size() - 8);
    ReadBuffer rb(bytes);
    CircuitReader<Field> rdr(F, fid);
    circ_kb = comp.size() / 1024;
    return rdr.from_bytes(rb, /*enforce_circuit_id=*/false);
  }
  auto C = build();
  std::vector<uint8_t> bytes; CircuitWriter<Field> wr(F, fid); wr.to_bytes(*C, bytes);
  size_t bound = ZSTD_compressBound(bytes.size());
  std::vector<uint8_t> comp(8 + bound);
  uint64_t osz = bytes.size(); memcpy(comp.data(), &osz, 8);
  size_t csz = ZSTD_compress(comp.data() + 8, bound, bytes.data(), bytes.size(), 6);
  std::ofstream of(cacheFile, std::ios::binary); of.write((const char*)comp.data(), 8 + csz);
  circ_kb = (8 + csz) / 1024;
  return C;
}

// ===================== Fp256 signature circuit: shared base =====================
namespace sigc {
using CB = CompilerBackend<Fp256Base>;
using LC = Logic<Fp256Base, CB>;
using EltW = LC::EltW;
using v128 = LC::v128;
using Nat = Fp256Base::N;
using MS = MdocSignature<LC, Fp256Base, P256>;
using EcdsaHostW = VerifyWitness3<P256, Fp256Scalar>;
using f2_p256 = Fp2<Fp256Base>;
using Elt2 = f2_p256::Elt;
using FftExt = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
using RSFp = ReedSolomonFactory<Fp256Base, FftExt>;
constexpr char kRootX[] = "112649224146410281873500457609690258373018840430489408729223714171582664680802";
constexpr char kRootY[] = "84087994358540907695740461427818660560182168997182378749313018254450460212908";

static Nat nat_be(const uint8_t* be){uint8_t t[Nat::kBytes];for(size_t i=0;i<Nat::kBytes;++i)t[i]=be[Nat::kBytes-1-i];return Nat::of_bytes(t);}

static void push_gf_bits(DenseFiller<Fp256Base>& f, const gf2k& g) {
  for (size_t j = 0; j < 128; ++j) f.push_back(g[j] ? p256_base.one() : p256_base.zero());
}
}  // namespace sigc

// ===================== GF(2^128) hash circuit: shared base =====================
namespace hashc {
using CB = CompilerBackend<f_128>;
using LC = Logic<f_128, CB>;
using v8 = LC::v8;
using v256 = LC::v256;
using BitW = LC::BitW;
using FlatSHA = FlatSHA256Circuit<LC, BitPlucker<LC, 4>>;
using SBW = FlatSHA::BlockWitness;
using MacBP = BitPlucker<LC, kMACPluckerBits>;
using MAC = MACGF2<CB, MacBP>;
using MACW = MAC::Witness;
using MACTag = MAC::v128;
using RSGf = LCH14ReedSolomonFactory<f_128>;

// Circuit capacities (compile-time fixed, like mdoc's kMaxSHABlocks etc).
// Set GENEROUSLY so realistic SD-JWT-VC credentials fit; the host checks every
// token against these and errors clearly if exceeded (see check_capacity).
// SINGLE SOURCE OF TRUTH — previously these were copied (and drifted: a token
// that grew past a per-file PB silently broke one demo). Feature-specific
// capacities (SECN/CTXLEN/NULLB/SPANB) stay in their own .cc.
constexpr size_t kMaxSHA = 32;            // issuer header.payload: up to 2048 B
constexpr size_t PRE = 64 * kMaxSHA;
constexpr size_t DECP = 64 * (kMaxSHA - 2);  // decoded payload buffer: 1920 B
constexpr size_t LOGM = 12;               // routing index width: up to 4096
constexpr size_t MAXVCT = 128;            // `"vct":"<type>"` pattern
constexpr size_t MAXNONCE = 64;           // `"nonce":"<n>"` pattern (KB freshness)
constexpr size_t MAXAUD = 128;            // `"aud":"<v>"` pattern (KB audience)
constexpr size_t MAXB = 4;                // SHA blocks per disclosure: up to 256 B
constexpr size_t MAXDD = (64 * MAXB * 6) / 8;
constexpr size_t MAXPAT = 160;            // disclosure suffix `","claim",value]`
constexpr size_t KBB = 6;                 // KB header.payload: up to 384 B
constexpr size_t DECKB = 64 * KBB;
constexpr size_t PB = 44;                 // presented bundle: up to 2816 B
constexpr size_t PRES = 64 * PB;

static v8 vb(const LC& L, uint8_t c) { return L.template vbit<8>(c); }
static BitW leq_bytes(const LC& L, const v8* a, const v8* b, size_t n) {
  BitW le = L.bit(1);
  for (size_t i = n; i-- > 0;) {
    auto blt = L.lt(8, a[i].data(), b[i].data());
    auto beq = L.eq(8, a[i].data(), b[i].data());
    le = L.lor(blt, L.land(beq, le));
  }
  return le;
}
static void assert_bits_eq_bytes(const LC& L, const v256& bits, const v8* out) {
  for (size_t j = 0; j < 32; ++j) {
    v8 tb;
    for (size_t c = 0; c < 8; ++c) tb[c] = bits[8 * (31 - j) + c];
    L.assert1(L.eq(8, out[j].data(), tb.data()));
  }
}

static void push_rev_bits(DenseFiller<f_128>& f, const uint8_t* be, const f_128& Fs) {
  uint8_t r[32]; for (size_t i = 0; i < 32; ++i) r[i] = be[31 - i];
  fill_bit_string(f, r, 32, 32, Fs);
}
static void fill_sha(DenseFiller<f_128>& f, BitPluckerEncoder<f_128, 4>& enc, const FlatSHA256Witness::BlockWitness& b) {
  for (size_t k = 0; k < 48; ++k) f.push_back(enc.mkpacked_v32(b.outw[k]));
  for (size_t k = 0; k < 64; ++k) { f.push_back(enc.mkpacked_v32(b.oute[k])); f.push_back(enc.mkpacked_v32(b.outa[k])); }
  for (size_t k = 0; k < 8; ++k) f.push_back(enc.mkpacked_v32(b.h1[k]));
}

// Validate that this credential fits the (fixed) circuit capacities. Returns a
// clear, specific error instead of letting host buffers overflow. (mdoc does the
// same with codes like MDOC_PROVER_TAGGED_MSO_TOO_BIG.)
inline bool check_capacity(const std::string& compact, const std::vector<std::string>& claims,
                           const std::string& vct, std::string& err) {
  auto blocks = [](size_t n) { return (n + 9 + 63) / 64; };  // SHA-256 padded blocks
  char buf[256];
  std::string jwt = compact.substr(0, compact.find('~'));
  size_t d1 = jwt.find('.'), d2 = jwt.find('.', d1 + 1);
  if (d1 == std::string::npos || d2 == std::string::npos) { err = "malformed issuer JWT"; return false; }
  std::string hp = jwt.substr(0, d2);
  std::string payload = b64d(jwt.substr(d1 + 1, d2 - d1 - 1));
  if (blocks(hp.size()) > kMaxSHA) {
    snprintf(buf, sizeof buf, "issuer header.payload %zuB needs %zu SHA blocks > kMaxSHA=%zu (%zuB)",
             hp.size(), blocks(hp.size()), kMaxSHA, kMaxSHA * 64); err = buf; return false; }
  if (payload.size() > DECP) {
    snprintf(buf, sizeof buf, "decoded payload %zuB > DECP=%zuB", payload.size(), DECP); err = buf; return false; }

  std::string kb = compact.substr(compact.rfind('~') + 1);
  size_t kd1 = kb.find('.'), kd2 = kb.find('.', kd1 + 1);
  if (kd2 == std::string::npos) { err = "malformed KB-JWT"; return false; }
  std::string kbhp = kb.substr(0, kd2);
  if (blocks(kbhp.size()) > KBB) {
    snprintf(buf, sizeof buf, "KB header.payload %zuB needs %zu SHA blocks > KBB=%zu (%zuB)",
             kbhp.size(), blocks(kbhp.size()), KBB, KBB * 64); err = buf; return false; }

  std::string pres = compact.substr(0, compact.rfind('~') + 1);
  if (blocks(pres.size()) > PB) {
    snprintf(buf, sizeof buf, "presented bundle %zuB needs %zu SHA blocks > PB=%zu (%zuB)",
             pres.size(), blocks(pres.size()), PB, PB * 64); err = buf; return false; }
  if (pres.size() >= (size_t(1) << LOGM)) {
    snprintf(buf, sizeof buf, "presented %zuB >= 2^LOGM=%zu (raise LOGM)", pres.size(), size_t(1) << LOGM); err = buf; return false; }

  std::string vp = "\"vct\":\"" + vct + "\"";
  if (vp.size() > MAXVCT) { snprintf(buf, sizeof buf, "vct pattern %zuB > MAXVCT=%zu", vp.size(), MAXVCT); err = buf; return false; }

  std::vector<std::string> discs;
  { size_t p = compact.find('~') + 1, q;
    while ((q = compact.find('~', p)) != std::string::npos) { if (q > p) discs.push_back(compact.substr(p, q - p)); p = q + 1; } }
  for (const auto& cl : claims) {
    std::string key = "\"" + cl + "\"", chosen;
    for (auto& d : discs) if (b64d(d).find(key) != std::string::npos) chosen = d;
    if (chosen.empty()) { err = "requested claim not found: " + cl; return false; }
    if (blocks(chosen.size()) > MAXB) {
      snprintf(buf, sizeof buf, "disclosure '%s' %zuB needs %zu SHA blocks > MAXB=%zu (%zuB)",
               cl.c_str(), chosen.size(), blocks(chosen.size()), MAXB, MAXB * 64); err = buf; return false; }
    std::string dj = b64d(chosen);
    size_t salt_len = dj.find("\",\"") - 2;
    std::string pat = dj.substr(2 + salt_len);
    if (pat.size() > MAXPAT) {
      snprintf(buf, sizeof buf, "claim '%s' pattern %zuB > MAXPAT=%zu", cl.c_str(), pat.size(), MAXPAT); err = buf; return false; }
  }
  return true;
}
}  // namespace hashc

}  // namespace proofs

#endif  // SDJWT_COMMON_H_
