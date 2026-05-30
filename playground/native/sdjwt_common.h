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

// ===================== hash-circuit shared base (declare / assert / fill) =====
// The split / null_split / null_blind / revoc CLIs share this base; each adds
// only its own feature block at the well-defined SEAMS below. The input WIRE
// ORDER lives ONLY here (declare_base / fill_base), so prover and verifier can
// never disagree on it. nv = number of MAC-linked Fp256 values (3 normally; 4
// for revocation's extra e_span).

struct Slot {
  v8 pattern[MAXPAT]; v8 patlen;
  v8 disc_pre[64 * MAXB]; v256 disc_ebits; SBW disc_sha[MAXB]; v8 disc_nb;
  LC::bitvec<8> disc_len, disc_shift; LC::bitvec<LOGM> sd_idx;
};

// Base inputs common to all features. mac[]/macw[] are sized for the widest
// case (nv=4); a circuit declares/fills only the first 2*nv+1 mac and nv macw.
// Feature .cc files derive `struct Inputs : BaseInputs { ...extra fields... }`.
struct BaseInputs {
  v8 now[10]; v8 vct_pat[MAXVCT]; v8 vct_len;
  v8 nonce_pat[MAXNONCE]; v8 nonce_len; v8 aud_pat[MAXAUD]; v8 aud_len;
  v256 e2;
  std::vector<Slot> slot; MACTag mac[9];
  v256 e, dpkx, dpky;
  v8 preimage[PRE]; SBW sha[kMaxSHA]; v8 nb;
  LC::bitvec<LOGM> payload_ind, payload_len, exp_idx, vct_idx, cnf_x_idx, cnf_y_idx;
  v8 kb_pre[DECKB]; SBW kb_sha[KBB]; v8 kb_nb;
  LC::bitvec<LOGM> kb_pl_ind, kb_pl_len, sd_hash_idx, nonce_idx, aud_idx;
  v8 presented[PRES]; SBW pres_sha[PB]; v8 pres_nb; v256 pres_hash_bits;
  std::vector<LC::bitvec<LOGM>> disc_in_pres;
  MACW macw[4];
};

// declare circuit inputs. feat_pub() runs after the base public inputs and
// BEFORE the macs; feat_priv() runs after the base private inputs and BEFORE
// begin_full_field()/macw. (Same seams a feature uses in fill_base.)
inline void declare_base(const LC& L, QuadCircuit<f_128>& Q, BaseInputs& in, size_t nattr, int nv,
                         const std::function<void()>& feat_pub = [] {},
                         const std::function<void()>& feat_priv = [] {}) {
  in.slot.resize(nattr); in.disc_in_pres.resize(nattr);
  for (auto& b : in.now) b = L.template vinput<8>();
  for (auto& b : in.vct_pat) b = L.template vinput<8>();
  in.vct_len = L.template vinput<8>();
  for (auto& b : in.nonce_pat) b = L.template vinput<8>();
  in.nonce_len = L.template vinput<8>();
  for (auto& b : in.aud_pat) b = L.template vinput<8>();
  in.aud_len = L.template vinput<8>();
  feat_pub();  // SEAM: feature public inputs (after aud, before e2)
  in.e2 = L.template vinput<256>();
  for (size_t s = 0; s < nattr; ++s) {
    for (auto& b : in.slot[s].pattern) b = L.template vinput<8>();
    in.slot[s].patlen = L.template vinput<8>();
  }
  for (int i = 0; i < 2 * nv + 1; ++i) in.mac[i] = L.eltw_input();
  Q.private_input();
  in.e = L.template vinput<256>(); in.dpkx = L.template vinput<256>(); in.dpky = L.template vinput<256>();
  for (auto& b : in.preimage) b = L.template vinput<8>();
  for (auto& s : in.sha) s.input(L);
  in.nb = L.template vinput<8>();
  in.payload_ind = L.template vinput<LOGM>(); in.payload_len = L.template vinput<LOGM>();
  in.exp_idx = L.template vinput<LOGM>(); in.vct_idx = L.template vinput<LOGM>();
  in.cnf_x_idx = L.template vinput<LOGM>(); in.cnf_y_idx = L.template vinput<LOGM>();
  for (auto& b : in.kb_pre) b = L.template vinput<8>();
  for (auto& s : in.kb_sha) s.input(L);
  in.kb_nb = L.template vinput<8>();
  in.kb_pl_ind = L.template vinput<LOGM>(); in.kb_pl_len = L.template vinput<LOGM>(); in.sd_hash_idx = L.template vinput<LOGM>();
  in.nonce_idx = L.template vinput<LOGM>(); in.aud_idx = L.template vinput<LOGM>();
  for (auto& b : in.presented) b = L.template vinput<8>();
  for (auto& s : in.pres_sha) s.input(L);
  in.pres_nb = L.template vinput<8>();
  in.pres_hash_bits = L.template vinput<256>();
  for (size_t s = 0; s < nattr; ++s) in.disc_in_pres[s] = L.template vinput<LOGM>();
  for (size_t s = 0; s < nattr; ++s) {
    Slot& sl = in.slot[s];
    for (auto& b : sl.disc_pre) b = L.template vinput<8>();
    sl.disc_ebits = L.template vinput<256>();
    for (auto& x : sl.disc_sha) x.input(L);
    sl.disc_nb = L.template vinput<8>();
    sl.disc_len = L.template vinput<8>(); sl.disc_shift = L.template vinput<8>();
    sl.sd_idx = L.template vinput<LOGM>();
  }
  feat_priv();  // SEAM: feature private inputs (before begin_full_field/macw)
  Q.begin_full_field();
  for (int i = 0; i < nv; ++i) in.macw[i].input(L);
}

// Shared primitives + decoded payload handed to a feature's assert hook, so the
// feature reuses them instead of re-decoding the payload (which would duplicate
// constraints). dec = decoded issuer payload buffer (DECP bytes).
struct HashCtx {
  const LC& L; Routing<LC>& r; FlatSHA& sha; MAC& mac_check; Base64Decoder<LC>& b64;
  const v8& zero; const v8* dec; int nv;
};

// assert the base statement (SHA + exp + vct + cnf + KB + sd_hash + nonce/aud +
// N×membership/structural/consent), then feat(ctx) (the feature block), then
// the nv standard MAC verifications (e/dpkx/dpky; av = mac[2*nv]). A feature
// that MACs extra values (revocation's e_span) verifies them inside feat().
inline void assert_base(const LC& L, const BaseInputs& in, int nv,
                        const std::function<void(HashCtx&)>& feat = [](HashCtx&) {}) {
  size_t nattr = in.slot.size();
  v8 zero = vb(L, 0);
  Routing<LC> r(L); FlatSHA sha(L); MAC mac_check(L); Base64Decoder<LC> b64(L);

  sha.assert_message_hash(kMaxSHA, in.nb, in.preimage, in.e, in.sha);
  v8 shbuf[DECP];
  r.shift(in.payload_ind, DECP, shbuf, PRE, in.preimage, zero, 3);
  v8 dec[DECP];
  LC::bitvec<LOGM> plen(in.payload_len);
  b64.base64_rawurl_decode_len(shbuf, dec, DECP, plen);

  // exp: anchor to `"exp":` (exp_idx -> opening `"`), require 10 ASCII digits +
  // delimiter, then now<=exp. Prevents pointing exp_idx at a >=now letters window.
  {
    v8 ew[17];
    r.shift(in.exp_idx, 17, ew, DECP, dec, zero, 3);
    static const char EK[6] = {'"', 'e', 'x', 'p', '"', ':'};
    for (size_t j = 0; j < 6; ++j)
      L.assert1(L.eq(8, ew[j].data(), vb(L, (uint8_t)EK[j]).data()));
    v8 c0 = vb(L, '0'), c9 = vb(L, '9');
    for (size_t j = 6; j < 16; ++j) {
      L.assert1(L.lnot(L.lt(8, ew[j].data(), c0.data())));
      L.assert1(L.lnot(L.lt(8, c9.data(), ew[j].data())));
    }
    L.assert1(L.lor(L.eq(8, ew[16].data(), vb(L, ',').data()),
                    L.eq(8, ew[16].data(), vb(L, '}').data())));
    L.assert1(leq_bytes(L, in.now, &ew[6], 10));
  }

  v8 vs[MAXVCT];
  r.shift(in.vct_idx, MAXVCT, vs, DECP, dec, zero, 3);
  for (size_t j = 0; j < MAXVCT; ++j)
    L.assert_implies(L.vlt(j, in.vct_len), L.eq(8, vs[j].data(), in.vct_pat[j].data()));

  auto check_coord = [&](const LC::bitvec<LOGM>& idx, const v256& bits) {
    v8 cc[43];
    r.shift(idx, 43, cc, DECP, dec, zero, 3);
    v8 out[33];
    b64.base64_rawurl_decode(cc, out, 43);
    assert_bits_eq_bytes(L, bits, out);
  };
  check_coord(in.cnf_x_idx, in.dpkx);
  check_coord(in.cnf_y_idx, in.dpky);

  sha.assert_message_hash(KBB, in.kb_nb, in.kb_pre, in.e2, in.kb_sha);
  v8 kbshift[DECKB];
  r.shift(in.kb_pl_ind, DECKB, kbshift, DECKB, in.kb_pre, zero, 3);
  v8 kbdec[DECKB];
  LC::bitvec<LOGM> kbpl(in.kb_pl_len);
  b64.base64_rawurl_decode_len(kbshift, kbdec, DECKB, kbpl);
  // KB freshness/audience: holder-signed KB payload must contain verifier-chosen
  // nonce/aud (pattern includes `"nonce":"`/`"aud":"` literal + closing quote).
  {
    v8 ns[MAXNONCE];
    r.shift(in.nonce_idx, MAXNONCE, ns, DECKB, kbdec, zero, 3);
    for (size_t j = 0; j < MAXNONCE; ++j)
      L.assert_implies(L.vlt(j, in.nonce_len), L.eq(8, ns[j].data(), in.nonce_pat[j].data()));
    v8 as[MAXAUD];
    r.shift(in.aud_idx, MAXAUD, as, DECKB, kbdec, zero, 3);
    for (size_t j = 0; j < MAXAUD; ++j)
      L.assert_implies(L.vlt(j, in.aud_len), L.eq(8, as[j].data(), in.aud_pat[j].data()));
  }
  v8 sdh_b64[43];
  r.shift(in.sd_hash_idx, 43, sdh_b64, DECKB, kbdec, zero, 3);
  v8 sdh[33];
  b64.base64_rawurl_decode(sdh_b64, sdh, 43);
  sha.assert_message_hash(PB, in.pres_nb, in.presented, in.pres_hash_bits, in.pres_sha);
  for (size_t j = 0; j < 32; ++j) {
    v8 tb;
    for (size_t c = 0; c < 8; ++c) tb[c] = in.pres_hash_bits[8 * (31 - j) + c];
    L.assert1(L.eq(8, sdh[j].data(), tb.data()));
  }

  for (size_t s = 0; s < nattr; ++s) {
    const Slot& sl = in.slot[s];
    sha.assert_message_hash(MAXB, sl.disc_nb, sl.disc_pre, sl.disc_ebits, sl.disc_sha);
    v8 entry[43];
    r.shift(sl.sd_idx, 43, entry, DECP, dec, zero, 3);
    v8 out[33];
    b64.base64_rawurl_decode(entry, out, 43);
    assert_bits_eq_bytes(L, sl.disc_ebits, out);
    v8 dd[MAXDD];
    LC::bitvec<8> dlen(sl.disc_len);
    b64.base64_rawurl_decode_len(sl.disc_pre, dd, 64 * MAXB, dlen);
    L.assert1(L.eq(8, dd[0].data(), vb(L, '[').data()));
    L.assert1(L.eq(8, dd[1].data(), vb(L, '"').data()));
    v8 S[MAXPAT];
    r.shift(sl.disc_shift, MAXPAT, S, MAXDD, dd, zero, 3);
    for (size_t j = 0; j < MAXPAT; ++j)
      L.assert_implies(L.vlt(j, sl.patlen), L.eq(8, S[j].data(), sl.pattern[j].data()));
    v8 ps[64 * MAXB];
    r.shift(in.disc_in_pres[s], 64 * MAXB, ps, PRES, in.presented, zero, 3);
    for (size_t j = 0; j < 64 * MAXB; ++j)
      L.assert_implies(L.vlt(j, sl.disc_len), L.eq(8, ps[j].data(), sl.disc_pre[j].data()));
  }

  HashCtx ctx{L, r, sha, mac_check, b64, zero, dec, nv};
  feat(ctx);  // SEAM: feature constraints (nullifier / revocation), incl any extra MAC

  mac_check.verify_mac(&in.mac[0], in.mac[2 * nv], in.e, in.macw[0]);
  mac_check.verify_mac(&in.mac[2], in.mac[2 * nv], in.dpkx, in.macw[1]);
  mac_check.verify_mac(&in.mac[4], in.mac[2 * nv], in.dpky, in.macw[2]);
}

// Fill the hash-circuit witness. feat_pub(f) runs after the base public values
// and BEFORE the macs; feat_priv(f, enc, payload, discs) runs after the base
// private witness and BEFORE the ap (macw) tail — same seams as declare_base.
// feat_priv returns false to abort (e.g. a required feature claim is missing).
inline bool fill_base(Dense<f_128>& W, bool pub_only, const std::string& compact, const char* now,
                      const std::vector<std::string>& claims, const std::string& vct,
                      const std::string& nonce, const std::string& aud, const f_128& Fs,
                      int nv, const gf2k macs6[], gf2k av, const gf2k* ap,
                      const std::function<void(DenseFiller<f_128>&)>& feat_pub =
                          [](DenseFiller<f_128>&) {},
                      const std::function<bool(DenseFiller<f_128>&, BitPluckerEncoder<f_128, 4>&,
                                               const std::string&, const std::vector<std::string>&)>&
                          feat_priv = [](DenseFiller<f_128>&, BitPluckerEncoder<f_128, 4>&,
                                         const std::string&, const std::vector<std::string>&) { return true; },
                      const std::vector<std::string>& assertVals = {}) {
  size_t nattr = claims.size();
  std::string jwt = compact.substr(0, compact.find('~'));
  size_t d1 = jwt.find('.'), d2 = jwt.find('.', d1 + 1);
  std::string msg = jwt.substr(0, d2);
  std::string payload_b64 = jwt.substr(d1 + 1, d2 - d1 - 1);
  std::string payload = b64d(payload_b64);
  size_t exp_idx = payload.find("\"exp\":");  // points at the `"` of `"exp":` (in-circuit anchor)
  std::string vct_pat = "\"vct\":\"" + vct + "\"";
  size_t vct_idx = payload.find(vct_pat);
  uint8_t edig[32]; ::SHA256((const uint8_t*)msg.data(), msg.size(), edig);
  uint8_t in_pre[PRE]; FlatSHA256Witness::BlockWitness bw[kMaxSHA]; uint8_t numb = 0;
  FlatSHA256Witness::transform_and_witness_message(msg.size(), (const uint8_t*)msg.data(), kMaxSHA, numb, in_pre, bw);
  size_t cnf = payload.find("\"cnf\"");
  size_t xi = payload.find("\"x\":\"", cnf) + 5, yi = payload.find("\"y\":\"", cnf) + 5;
  std::string cx_raw = b64d(payload.substr(xi, 43)), cy_raw = b64d(payload.substr(yi, 43));

  std::string kbjwt = compact.substr(compact.rfind('~') + 1);
  size_t kd1 = kbjwt.find('.'), kd2 = kbjwt.find('.', kd1 + 1);
  std::string kbhp = kbjwt.substr(0, kd2);
  uint8_t kbdig[32]; ::SHA256((const uint8_t*)kbhp.data(), kbhp.size(), kbdig);
  uint8_t kb_in[DECKB]; FlatSHA256Witness::BlockWitness kb_bw[KBB]; uint8_t kb_numb = 0;
  FlatSHA256Witness::transform_and_witness_message(kbhp.size(), (const uint8_t*)kbhp.data(), KBB, kb_numb, kb_in, kb_bw);
  std::string kb_pl_b64 = kbjwt.substr(kd1 + 1, kd2 - kd1 - 1);
  std::string kb_pl = b64d(kb_pl_b64);
  size_t sdh_pos = kb_pl.find("\"sd_hash\":\"") + 11;
  std::string nonce_pat = "\"nonce\":\"" + nonce + "\"";
  std::string aud_pat = "\"aud\":\"" + aud + "\"";
  size_t nonce_pos = kb_pl.find("\"nonce\":\"");
  size_t aud_pos = kb_pl.find("\"aud\":\"");
  std::string presented = compact.substr(0, compact.rfind('~') + 1);
  uint8_t pres_in[PRES]; FlatSHA256Witness::BlockWitness pres_bw[PB]; uint8_t pres_numb = 0;
  FlatSHA256Witness::transform_and_witness_message(presented.size(), (const uint8_t*)presented.data(), PB, pres_numb, pres_in, pres_bw);
  uint8_t predig[32]; ::SHA256((const uint8_t*)presented.data(), presented.size(), predig);

  std::vector<std::string> discs;
  { size_t p = compact.find('~') + 1, q;
    while ((q = compact.find('~', p)) != std::string::npos) { if (q > p) discs.push_back(compact.substr(p, q - p)); p = q + 1; } }
  std::vector<std::string> chosen(nattr);
  for (size_t s = 0; s < nattr; ++s) {
    std::string key = "\"" + claims[s] + "\"";
    for (auto& d : discs) if (b64d(d).find(key) != std::string::npos) chosen[s] = d;
    if (chosen[s].empty()) { printf("claim %s not found\n", claims[s].c_str()); return false; }
  }

  BitPluckerEncoder<f_128, 4> enc(Fs);
  DenseFiller<f_128> f(W);
  f.push_back(Fs.one());
  for (int i = 0; i < 10; ++i) f.push_back((uint8_t)now[i], 8, Fs);
  for (size_t i = 0; i < MAXVCT; ++i) f.push_back(i < vct_pat.size() ? (uint8_t)vct_pat[i] : 0, 8, Fs);
  f.push_back((uint8_t)vct_pat.size(), 8, Fs);
  for (size_t i = 0; i < MAXNONCE; ++i) f.push_back(i < nonce_pat.size() ? (uint8_t)nonce_pat[i] : 0, 8, Fs);
  f.push_back((uint8_t)nonce_pat.size(), 8, Fs);
  for (size_t i = 0; i < MAXAUD; ++i) f.push_back(i < aud_pat.size() ? (uint8_t)aud_pat[i] : 0, 8, Fs);
  f.push_back((uint8_t)aud_pat.size(), 8, Fs);
  feat_pub(f);  // SEAM: feature public witness (after aud, before e2)
  push_rev_bits(f, kbdig, Fs);
  for (size_t s = 0; s < nattr; ++s) {
    std::string pat;
    if (s < assertVals.size() && !assertVals[s].empty()) {
      // ASSERT mode: pin the public pattern to a verifier-required value
      // (`","name",<value>]`); the holder's actual disclosure must match it or
      // the proof is unsatisfiable. Empty -> DISCLOSE the holder's own value.
      pat = "\",\"" + claims[s] + "\"," + assertVals[s] + "]";
    } else {
      std::string dj = b64d(chosen[s]);
      size_t salt_len = dj.find("\",\"") - 2;
      pat = dj.substr(2 + salt_len);
    }
    for (size_t i = 0; i < MAXPAT; ++i) f.push_back(i < pat.size() ? (uint8_t)pat[i] : 0, 8, Fs);
    f.push_back((uint8_t)pat.size(), 8, Fs);
  }
  for (int i = 0; i < 2 * nv; ++i) f.push_back(macs6[i]);
  f.push_back(av);
  if (pub_only) return true;

  push_rev_bits(f, edig, Fs);
  push_rev_bits(f, (const uint8_t*)cx_raw.data(), Fs);
  push_rev_bits(f, (const uint8_t*)cy_raw.data(), Fs);
  for (size_t i = 0; i < PRE; ++i) f.push_back(in_pre[i], 8, Fs);
  for (size_t b = 0; b < kMaxSHA; ++b) fill_sha(f, enc, bw[b]);
  f.push_back(numb, 8, Fs);
  f.push_back(d1 + 1, LOGM, Fs); f.push_back(payload_b64.size(), LOGM, Fs);
  // [adversarial prover] EVIL_EXP points exp_idx at a letters run (>= now) to
  // try to bypass expiry. The `"exp":` anchor + digit check must REJECT this.
  size_t exp_idx_w = (getenv("EVIL_EXP") ? payload.find("https") : exp_idx);
  f.push_back(exp_idx_w, LOGM, Fs); f.push_back(vct_idx, LOGM, Fs);
  f.push_back(xi, LOGM, Fs); f.push_back(yi, LOGM, Fs);
  for (size_t i = 0; i < DECKB; ++i) f.push_back(kb_in[i], 8, Fs);
  for (size_t b = 0; b < KBB; ++b) fill_sha(f, enc, kb_bw[b]);
  f.push_back(kb_numb, 8, Fs);
  f.push_back(kd1 + 1, LOGM, Fs); f.push_back(kb_pl_b64.size(), LOGM, Fs); f.push_back(sdh_pos, LOGM, Fs);
  f.push_back(nonce_pos, LOGM, Fs); f.push_back(aud_pos, LOGM, Fs);
  for (size_t i = 0; i < PRES; ++i) f.push_back(pres_in[i], 8, Fs);
  for (size_t b = 0; b < PB; ++b) fill_sha(f, enc, pres_bw[b]);
  f.push_back(pres_numb, 8, Fs);
  push_rev_bits(f, predig, Fs);
  for (size_t s = 0; s < nattr; ++s) f.push_back(presented.find(chosen[s]), LOGM, Fs);
  for (size_t s = 0; s < nattr; ++s) {
    const std::string& disc = chosen[s];
    uint8_t dg[32]; ::SHA256((const uint8_t*)disc.data(), disc.size(), dg);
    std::string entry = b64e(dg, 32);
    size_t sd_idx = payload.find(entry);
    if (sd_idx == std::string::npos) { printf("digest not in _sd\n"); return false; }
    std::string dj = b64d(disc);
    size_t salt_len = dj.find("\",\"") - 2;
    uint8_t din[64 * MAXB]; FlatSHA256Witness::BlockWitness dbw[MAXB]; uint8_t dnumb = 0;
    FlatSHA256Witness::transform_and_witness_message(disc.size(), (const uint8_t*)disc.data(), MAXB, dnumb, din, dbw);
    for (size_t i = 0; i < 64 * MAXB; ++i) f.push_back(din[i], 8, Fs);
    push_rev_bits(f, dg, Fs);
    for (size_t b = 0; b < MAXB; ++b) fill_sha(f, enc, dbw[b]);
    f.push_back(dnumb, 8, Fs);
    f.push_back((uint8_t)disc.size(), 8, Fs);
    f.push_back((uint8_t)(2 + salt_len), 8, Fs);
    f.push_back(sd_idx, LOGM, Fs);
  }
  if (!feat_priv(f, enc, payload, discs)) return false;  // SEAM: feature private witness
  for (int i = 0; i < 2 * nv; ++i) f.push_back(ap[i]);  // SHARED, av-independent key
  return true;
}
}  // namespace hashc

}  // namespace proofs

#endif  // SDJWT_COMMON_H_
