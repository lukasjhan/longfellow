// Real mdoc (ISO 18013-5) ZK presentation as TWO linked circuits, PLUS a
// pseudonymous nullifier — the mdoc counterpart of sdjwt_null_split.cc.
//
//   * sig  circuit over Fp256:    issuer ECDSA over the MSO hash e  +  device
//                                 ECDSA over the session-transcript hash.
//                                 (longfellow's MdocSignature, unchanged.)
//   * hash circuit over GF(2^128): SHA(MSO) + validFrom/Until + deviceKey +
//                                 valueDigests membership + public attributes
//                                 (longfellow's MdocHash::assert_valid_hash_mdoc,
//                                 unchanged), PLUS a BLIND nullifier block:
//        - the credential commits a COMMITMENT C (a 32-byte CBOR byte string),
//          NOT the secret; its IssuerSignedItem SHA is proven to appear in the
//          signed MSO valueDigests (membership), so C is issuer-committed,
//        - C is extracted in-circuit by a literal CBOR anchor (elementIdentifier
//          "pseudonym_commitment" immediately followed by elementValue bytes(32)),
//        - opening: the holder proves SHA(secret ‖ blind) == C with secret/blind
//          hidden — so the issuer (which only saw C) cannot derive the nullifier,
//        - nullifier = SHA( secret(32) ‖ SHA(context)(32) ), a public output;
//          the SAME hidden secret wires feed the opening and the nullifier.
//
// The two circuits are MAC-linked over the common Fp256 values (e, dpkx, dpky):
// one shared committed key half a_p, a_v drawn from the post-commit transcript,
// the macs public in BOTH. Bundle = [6 macs][hash proof][sig proof].
//
// `pseudonym_commitment` is issued by @lukas.j.han/mdoc as a Buffer → CBOR byte
// string (58 20 <32B>), so its IssuerSignedItem is ~146 B (3 SHA blocks). The
// secret/blind live only on the holder side (mdoc-holder-secret.txt); the issuer
// never learns them — this is the blind counterpart of the proven split design.

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
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/routing.h"
#include "circuits/mac/mac_circuit.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mac/mac_witness.h"
#include "circuits/mdoc/mdoc_constants.h"
#include "circuits/mdoc/mdoc_hash.h"
#include "circuits/mdoc/mdoc_signature.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
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
using P256Nat = Fp256Base::N;
constexpr size_t kRate = 7, kNreq = 132, kVer = 7;

static std::string rf(const std::string& p) {
  std::ifstream f(p, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
}

// Extract a `"key":"0x...."` hex string from a small JSON blob.
static std::string json_hex(const std::string& j, const char* key) {
  size_t i = j.find(key);
  i = j.find("0x", i);
  size_t e = j.find('"', i);
  return j.substr(i, e - i);
}

// find needle in haystack, return offset or npos
static size_t find_bytes(const uint8_t* h, size_t hn, const uint8_t* n,
                         size_t nn) {
  if (nn > hn) return std::string::npos;
  for (size_t i = 0; i + nn <= hn; ++i)
    if (memcmp(h + i, n, nn) == 0) return i;
  return std::string::npos;
}

// The prover's half of the MAC key. a_v + macs are derived AFTER commitment so
// the prover cannot make two different e's pass the same public mac.
struct Linker { gf2k ap[6]; };

gf2k generate_mac_key(Transcript& t, const f_128& gf) {
  uint8_t buf[f_128::kBytes];
  t.bytes(buf, f_128::kBytes);
  return gf.of_bytes_field(buf).value();
}

void compute_macs(const Fp256Base::Elt x[3], gf2k gmacs[6],
                  uint8_t macs_b[6 * f_128::kBytes], const gf2k ap[6], gf2k av,
                  const f_128& gf) {
  MACReference<f_128> mr;
  for (int i = 0; i < 3; ++i) {
    uint8_t buf[32];
    p256_base.to_bytes_field(buf, x[i]);
    mr.compute(&gmacs[2 * i], av, &ap[2 * i], buf);
    gf.to_bytes_field(&macs_b[2 * i * f_128::kBytes], gmacs[2 * i]);
    gf.to_bytes_field(&macs_b[(2 * i + 1) * f_128::kBytes], gmacs[2 * i + 1]);
  }
}

void update_macs(Dense<Fp256Base>& Ws, Dense<f_128>& Wh, size_t si, size_t hi,
                 const gf2k gmacs[6], gf2k av) {
  auto put = [&](const gf2k& m) {
    for (size_t j = 0; j < f_128::kBits; ++j)
      Ws.v_[si++] = m[j] ? p256_base.one() : p256_base.zero();
    Wh.v_[hi++] = m;
  };
  for (int mi = 0; mi < 6; ++mi) put(gmacs[mi]);
  put(av);
}

struct Result { long prove_ms = 0; size_t proof_kb = 0, circ_kb = 0, ninputs = 0; bool ok = false; };

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

// ===================== Fp256 signature circuit =====================
// Identical to the production mdoc sig circuit (MdocSignature). Public inputs:
// {1, pkX, pkY, htr, mac[0..5], av}; htr is the session-transcript hash.
namespace sigc {
using CB = CompilerBackend<Fp256Base>;
using LC = Logic<Fp256Base, CB>;
using EltW = LC::EltW;
using v128 = LC::v128;
using MS = MdocSignature<LC, Fp256Base, P256>;
using f2_p256 = Fp2<Fp256Base>;
using Elt2 = f2_p256::Elt;
using FftExt = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
using RSFp = ReedSolomonFactory<Fp256Base, FftExt>;
constexpr char kRootX[] = "112649224146410281873500457609690258373018840430489408729223714171582664680802";
constexpr char kRootY[] = "84087994358540907695740461427818660560182168997182378749313018254450460212908";

std::unique_ptr<Circuit<Fp256Base>> make_sig_circuit() {
  QuadCircuit<Fp256Base> Q(p256_base);
  const CB cbk(&Q);
  const LC L(&cbk, p256_base);
  EltW pkX = L.eltw_input(), pkY = L.eltw_input(), htr = L.eltw_input();
  v128 mac_e[2], mac_dx[2], mac_dy[2], av;
  for (auto& m : mac_e) m = L.template vinput<128>();
  for (auto& m : mac_dx) m = L.template vinput<128>();
  for (auto& m : mac_dy) m = L.template vinput<128>();
  av = L.template vinput<128>();
  Q.private_input();
  MS::Witness vw;
  vw.input(L);
  MS ms(L, p256, n256_order);
  ms.assert_signatures(pkX, pkY, htr, mac_e, mac_dx, mac_dy, av, vw);
  return Q.mkcircuit(1);
}

static void push_gf_bits(DenseFiller<Fp256Base>& f, const gf2k& g) {
  for (size_t j = 0; j < 128; ++j) f.push_back(g[j] ? p256_base.one() : p256_base.zero());
}

// pub_only stops after the public inputs (verifier path). Otherwise appends the
// MdocSignatureWitness private witness (its macs must be computed first).
bool fill(Dense<Fp256Base>& W, bool pub_only,
          const Fp256Base::Elt& pkX, const Fp256Base::Elt& pkY,
          const Fp256Base::Elt& htr,
          MdocSignatureWitness<P256, Fp256Scalar>* sw,
          const gf2k macs6[6], gf2k av) {
  DenseFiller<Fp256Base> f(W);
  f.push_back(p256_base.one());
  f.push_back(pkX); f.push_back(pkY); f.push_back(htr);
  for (int i = 0; i < 6; ++i) push_gf_bits(f, macs6[i]);
  push_gf_bits(f, av);
  if (pub_only) return true;
  sw->fill_witness(f);   // e, dpkx, dpky, issuer-sig, device-sig, macs[3]
  return true;
}
}  // namespace sigc

// ===================== GF(2^128) hash circuit =====================
namespace hashc {
using CB = CompilerBackend<f_128>;
using LC = Logic<f_128, CB>;
using v8 = LC::v8;
using v64 = LC::v64;
using v256 = LC::v256;
using BitW = LC::BitW;
using MdocH = MdocHash<LC, f_128>;
using FlatSHA = FlatSHA256Circuit<LC, BitPlucker<LC, kSHAPluckerBits>>;
using SBW = FlatSHA::BlockWitness;
using MacBP = BitPlucker<LC, kMACPluckerBits>;
using MAC = MACGF2<CB, MacBP>;
using MACW = MAC::Witness;
using MACTag = MAC::v128;
using RSGf = LCH14ReedSolomonFactory<f_128>;
using vind = LC::bitvec<kCborIndexBits>;

// BLIND nullifier geometry. The credential commits a COMMITMENT (a 32-byte CBOR
// byte string), not the secret; the holder holds secret+blind off-credential.
constexpr size_t SECB = 3;       // commitment IssuerSignedItem: <=3 SHA blocks (192B)
constexpr size_t SECLEN = 32;    // holder secret: 32 raw bytes (hidden witness)
constexpr size_t BLINDLEN = 32;  // commitment blinding: 32 raw bytes (hidden witness)
constexpr size_t COMLEN = 32;    // commitment C = 32 bytes (CBOR byte string 58 20 ..)
constexpr size_t CTXLEN = 32;    // bind SHA(context), not raw context (length-independent)
constexpr size_t COMMB = 2;      // SHA blocks for secret(32)+blind(32) = 64B opening msg
constexpr size_t NULLB = 2;      // SHA blocks for secret(32)+ctxhash(32) = 64B nullifier msg
// Literal CBOR anchor that uniquely locates the commitment value inside the item:
//   71 "elementIdentifier" 74 "pseudonym_commitment" 6C "elementValue" 58 20
static constexpr uint8_t ANCHOR[] = {
    0x71, 'e', 'l', 'e', 'm', 'e', 'n', 't', 'I', 'd', 'e', 'n', 't', 'i', 'f',
    'i',  'e', 'r', 0x74, 'p', 's', 'e', 'u', 'd', 'o', 'n', 'y', 'm', '_', 'c',
    'o',  'm', 'm', 'i', 't', 'm', 'e', 'n', 't', 0x6C, 'e', 'l', 'e', 'm', 'e',
    'n',  't', 'V', 'a', 'l', 'u', 'e', 0x58, 0x20};
constexpr size_t ANCHORN = sizeof(ANCHOR);  // 54
constexpr size_t EXTN = ANCHORN + COMLEN;   // 86

static v8 vb(const LC& L, uint8_t c) { return L.template vbit<8>(c); }

// Prove the issuer-committed COMMITMENT -> opened by a hidden secret -> public
// nullifier. Uses w.in_ (the signed MSO bytes) for the membership proof of C;
// secret/blind stay private and are bound into the opening and the nullifier SHA.
struct NullWit {
  v8 sec_item[64 * SECB];   // tagged commitment IssuerSignedItem (D8 18 58 .. A4 ..)
  SBW sec_sha[SECB];
  v8 sec_nb;
  vind sec_mso;             // byte index of the item's 32B digest within the MSO
  vind sec_anchor;          // byte offset of ANCHOR within sec_item
  v8 secret[SECLEN];        // holder witnesses (hidden) — NOT in the credential
  v8 blind[BLINDLEN];
  v8 open_pre[64 * COMMB];  // opening preimage: secret ‖ blind ‖ padding
  SBW open_sha[COMMB];
  v8 open_nb;
  v8 null_pre[64 * NULLB];
  SBW null_sha[NULLB];
  v8 null_nb;
  void input(const LC& L) {
    for (auto& b : sec_item) b = L.template vinput<8>();
    for (auto& s : sec_sha) s.input(L);
    sec_nb = L.template vinput<8>();
    sec_mso = L.template vinput<kCborIndexBits>();
    sec_anchor = L.template vinput<kCborIndexBits>();
    for (auto& b : secret) b = L.template vinput<8>();
    for (auto& b : blind) b = L.template vinput<8>();
    for (auto& b : open_pre) b = L.template vinput<8>();
    for (auto& s : open_sha) s.input(L);
    open_nb = L.template vinput<8>();
    for (auto& b : null_pre) b = L.template vinput<8>();
    for (auto& s : null_sha) s.input(L);
    null_nb = L.template vinput<8>();
  }
};

void assert_nullifier(const LC& L, FlatSHA& sha, Routing<LC>& r,
                      const MdocH::Witness& w, const v8 ctx[CTXLEN],
                      const v256& nullifier, const NullWit& nw) {
  const v8 zz = vb(L, 0);
  auto eqc = [&](const v8& a, uint8_t c) { L.vassert_eq(a, vb(L, c)); };

  // (1) Recompute the COSE1(MSO) preimage and its length (compiler dedups this
  //     against assert_valid_hash_mdoc), then range-check the membership index.
  std::vector<v8> pre(64 * kMaxSHABlocks);
  for (size_t i = 0; i < 64 * kMaxSHABlocks; ++i) {
    if (i < kCose1PrefixLen) pre[i] = vb(L, kCose1Prefix[i]);
    else pre[i] = w.in_[i - kCose1PrefixLen];
  }
  v64 len = sha.find_len(kMaxSHABlocks, pre.data(), w.nb_);
  {  // check_index: low3(len)==0, hi(len)==0, sec_mso < mid(len)
    auto low = L.template slice<0, 3>(len);
    auto mid = L.template slice<3, 3 + kCborIndexBits>(len);
    auto hi = L.template slice<3 + kCborIndexBits, 64>(len);
    L.vassert0(low);
    L.vassert0(hi);
    L.vassert_is_bit(nw.sec_mso);
    L.assert1(L.vlt(nw.sec_mso, mid));
  }

  // (2) Membership: a 32B CBOR byte string (58 20 ..) sits at sec_mso in the
  //     MSO, and it equals SHA(sec_item). Bytes are signed by the issuer, so the
  //     prover cannot inject a fake digest. (Mirrors MdocHash's attribute MSO
  //     membership, but with a 3-block item.)
  std::vector<v8> cmp(kMaxMsoLen);
  r.shift(nw.sec_mso, 2 + 32, cmp.data(), kMaxMsoLen, w.in_ + 5 + 2, zz, 3);
  eqc(cmp[0], 0x58);
  eqc(cmp[1], 0x20);
  v256 mm;
  for (size_t j = 0; j < 256; ++j) mm[j] = cmp[2 + (255 - j) / 8][(j % 8)];
  L.vassert_is_bit(mm);
  sha.assert_message_hash(SECB, nw.sec_nb, nw.sec_item, mm, nw.sec_sha);

  // (3) Extraction: shift the literal anchor to the front and assert it; the 32
  //     commitment bytes follow contiguously. The anchor pins the attribute
  //     identity (pseudonym_commitment) and the value type (58 20 = bytes(32)).
  v8 ext[EXTN];
  r.shift(nw.sec_anchor, EXTN, ext, 64 * SECB, nw.sec_item, zz, 3);
  for (size_t j = 0; j < ANCHORN; ++j) eqc(ext[j], ANCHOR[j]);
  // C (32 bytes, big-endian as in the CBOR byte string) -> v256 in SHA bit-order
  // (the same reversal MdocHash uses for `mm`), so we can assert SHA(...) == C.
  v256 cm;
  for (size_t j = 0; j < 256; ++j) cm[j] = ext[ANCHORN + (255 - j) / 8][(j % 8)];
  L.vassert_is_bit(cm);

  // (4) Opening: prove SHA(secret ‖ blind) == C. The issuer only ever saw C
  //     (hiding), so it cannot derive the nullifier; this proves the holder
  //     knows the (secret, blind) behind the issuer-committed C (binding).
  for (size_t j = 0; j < SECLEN; ++j)
    L.assert1(L.eq(8, nw.open_pre[j].data(), nw.secret[j].data()));
  for (size_t j = 0; j < BLINDLEN; ++j)
    L.assert1(L.eq(8, nw.open_pre[SECLEN + j].data(), nw.blind[j].data()));
  {
    constexpr size_t MO = SECLEN + BLINDLEN;  // 64
    eqc(nw.open_pre[MO], 0x80);
    for (size_t j = MO + 1; j < 64 * COMMB - 8; ++j) eqc(nw.open_pre[j], 0);
    uint64_t bl = (uint64_t)MO * 8;
    for (size_t j = 0; j < 8; ++j)
      eqc(nw.open_pre[64 * COMMB - 8 + j], (uint8_t)((bl >> (8 * (7 - j))) & 0xff));
    eqc(nw.open_nb, (uint8_t)COMMB);
    sha.assert_message_hash(COMMB, nw.open_nb, nw.open_pre, cm, nw.open_sha);
  }

  // (5) nullifier = SHA( secret(32) ‖ SHA(context)(32) ), fully bound + padded so
  //     it is deterministic per (secret, context). SAME secret wires as (4).
  for (size_t j = 0; j < SECLEN; ++j)
    L.assert1(L.eq(8, nw.null_pre[j].data(), nw.secret[j].data()));
  for (size_t j = 0; j < CTXLEN; ++j)
    L.assert1(L.eq(8, nw.null_pre[SECLEN + j].data(), ctx[j].data()));
  constexpr size_t MN = SECLEN + CTXLEN;  // 64
  eqc(nw.null_pre[MN], 0x80);
  for (size_t j = MN + 1; j < 64 * NULLB - 8; ++j) eqc(nw.null_pre[j], 0);
  uint64_t bitlen = (uint64_t)MN * 8;
  for (size_t j = 0; j < 8; ++j)
    eqc(nw.null_pre[64 * NULLB - 8 + j], (uint8_t)((bitlen >> (8 * (7 - j))) & 0xff));
  eqc(nw.null_nb, (uint8_t)NULLB);
  sha.assert_message_hash(NULLB, nw.null_nb, nw.null_pre, nullifier, nw.null_sha);
}

std::unique_ptr<Circuit<f_128>> make_hash_circuit(const f_128& Fs, size_t npub) {
  QuadCircuit<f_128> Q(Fs);
  const CB cbk(&Q);
  const LC L(&cbk, Fs);
  MAC mac_check(L);
  FlatSHA sha(L);
  Routing<LC> r(L);

  // ---- public inputs: oa[npub], now[20], ctx[32], nullifier, mac[7] ----
  std::vector<MdocH::OpenedAttribute> oa(npub);
  MdocH mdoc_h(L);
  for (size_t ai = 0; ai < npub; ++ai) oa[ai].input(L);
  v8 now[20];
  for (auto& b : now) b = L.template vinput<8>();
  v8 ctx[CTXLEN];
  for (auto& b : ctx) b = L.template vinput<8>();
  v256 nullifier = L.template vinput<256>();
  MACTag mac[7];
  for (auto& m : mac) m = L.eltw_input();
  Q.private_input();

  // ---- private: e, dpkx, dpky, MdocHash witness, nullifier witness, macs ----
  v256 e = L.template vinput<256>();
  v256 dpkx = L.template vinput<256>();
  v256 dpky = L.template vinput<256>();
  auto w = std::make_unique<MdocH::Witness>(npub);
  w->input(L);
  NullWit nw;
  nw.input(L);
  Q.begin_full_field();
  MACW macw[3];
  for (auto& mw : macw) mw.input(L);

  // ---- assertions ----
  mdoc_h.assert_valid_hash_mdoc(oa.data(), now, e, dpkx, dpky, *w);
  assert_nullifier(L, sha, r, *w, ctx, nullifier, nw);
  mac_check.verify_mac(&mac[0], mac[6], e, macw[0]);
  mac_check.verify_mac(&mac[2], mac[6], dpkx, macw[1]);
  mac_check.verify_mac(&mac[4], mac[6], dpky, macw[2]);

  return Q.mkcircuit(1);
}

// SHA-256 digests are bound to v256 inputs in reversed-byte order (the layout
// FlatSHA's assert_message_hash produces), matching MdocHash's `mm` convention.
static void push_rev_bits(DenseFiller<f_128>& f, const uint8_t* be, const f_128& Fs) {
  uint8_t r[32]; for (size_t i = 0; i < 32; ++i) r[i] = be[31 - i];
  fill_bit_string(f, r, 32, 32, Fs);
}
static void fill_sha(DenseFiller<f_128>& f, BitPluckerEncoder<f_128, kSHAPluckerBits>& enc,
                     const FlatSHA256Witness::BlockWitness& b) {
  for (size_t k = 0; k < 48; ++k) f.push_back(enc.mkpacked_v32(b.outw[k]));
  for (size_t k = 0; k < 64; ++k) { f.push_back(enc.mkpacked_v32(b.oute[k])); f.push_back(enc.mkpacked_v32(b.outa[k])); }
  for (size_t k = 0; k < 8; ++k) f.push_back(enc.mkpacked_v32(b.h1[k]));
}

// Carries the precomputed nullifier host witness (built once in main).
struct NullHost {
  uint8_t item[64 * SECB]; FlatSHA256Witness::BlockWitness item_bw[SECB]; uint8_t item_nb = 0;
  size_t mso_v = 0, anchor_off = 0;
  uint8_t secret[SECLEN]; uint8_t blind[BLINDLEN];
  uint8_t open_pre[64 * COMMB]; FlatSHA256Witness::BlockWitness open_bw[COMMB]; uint8_t open_nb = 0;
  uint8_t npre[64 * NULLB]; FlatSHA256Witness::BlockWitness npre_bw[NULLB]; uint8_t npre_nb = 0;
};

// Fill the hash dense array. macs6/av in the public tail (zeros at commit; real
// for verify). pub_only -> public inputs only.
bool fill(Dense<f_128>& W, bool pub_only, const f_128& Fs, size_t npub,
          const RequestedAttribute* attrs, const uint8_t* now20,
          const uint8_t* ctxh, const uint8_t* nullhash,
          MdocHashWitness<P256, f_128>* hw, const NullHost* nh,
          const gf2k* ap, const gf2k macs6[6], gf2k av) {
  BitPluckerEncoder<f_128, kSHAPluckerBits> enc(Fs);
  DenseFiller<f_128> f(W);
  // ---- public ----
  f.push_back(Fs.one());
  for (size_t ai = 0; ai < npub; ++ai)
    if (fill_attribute(f, attrs[ai], Fs, /*version=*/7) != MDOC_PROVER_SUCCESS) return false;
  fill_bit_string(f, now20, 20, 20, Fs);
  fill_bit_string(f, ctxh, CTXLEN, CTXLEN, Fs);
  push_rev_bits(f, nullhash, Fs);   // SHA output bit-order
  for (int i = 0; i < 6; ++i) f.push_back(macs6[i]);
  f.push_back(av);
  if (pub_only) return true;

  // ---- private ----
  uint8_t buf[32];
  p256_base.to_bytes_field(buf, hw->e_);    fill_bit_string(f, buf, 32, 32, Fs);
  p256_base.to_bytes_field(buf, hw->dpkx_); fill_bit_string(f, buf, 32, 32, Fs);
  p256_base.to_bytes_field(buf, hw->dpky_); fill_bit_string(f, buf, 32, 32, Fs);
  hw->fill_witness(f, /*version=*/7);
  // nullifier witness (commitment item + secret/blind + opening + null SHA)
  for (size_t i = 0; i < 64 * SECB; ++i) f.push_back(nh->item[i], 8, Fs);
  for (size_t b = 0; b < SECB; ++b) fill_sha(f, enc, nh->item_bw[b]);
  f.push_back(nh->item_nb, 8, Fs);
  f.push_back(nh->mso_v, kCborIndexBits, Fs);
  f.push_back(nh->anchor_off, kCborIndexBits, Fs);
  for (size_t j = 0; j < SECLEN; ++j) f.push_back(nh->secret[j], 8, Fs);
  for (size_t j = 0; j < BLINDLEN; ++j) f.push_back(nh->blind[j], 8, Fs);
  for (size_t i = 0; i < 64 * COMMB; ++i) f.push_back(nh->open_pre[i], 8, Fs);
  for (size_t b = 0; b < COMMB; ++b) fill_sha(f, enc, nh->open_bw[b]);
  f.push_back(nh->open_nb, 8, Fs);
  for (size_t i = 0; i < 64 * NULLB; ++i) f.push_back(nh->npre[i], 8, Fs);
  for (size_t b = 0; b < NULLB; ++b) fill_sha(f, enc, nh->npre_bw[b]);
  f.push_back(nh->npre_nb, 8, Fs);
  // mac witnesses (the shared, av-independent key halves)
  for (int i = 0; i < 6; ++i) f.push_back(ap[i]);
  return true;
}
}  // namespace hashc
}  // namespace proofs

int main(int argc, char** argv) {
  using namespace proofs;
  set_log_level(ERROR);
  std::string mdoc_path = argc > 1 ? argv[1] : "playground/fixtures/mdoc-blind.bin";
  std::string issuer_json = argc > 2 ? argv[2] : "playground/fixtures/mdoc-blind-issuer.json";
  std::string transcript_path = argc > 3 ? argv[3] : "playground/fixtures/mdoc-blind-transcript.bin";
  const char* now = argc > 4 ? argv[4] : "2026-06-01T00:00:00Z";
  std::string attr_id = argc > 5 ? argv[5] : "age_over_18";   // public disclosed attr
  std::string attr_hex = argc > 6 ? argv[6] : "f5";           // its CBOR value (true)
  std::string context = argc > 7 ? argv[7] : "context-A";     // nullifier scope

  const f_128 Fs;
  std::string mdoc = rf(mdoc_path);
  std::string tr = rf(transcript_path);
  std::string ij = rf(issuer_json);
  if (mdoc.empty() || tr.empty() || ij.empty()) { printf("ERROR: missing fixture(s)\n"); return 2; }
  const uint8_t* mdoc_b = (const uint8_t*)mdoc.data();
  const uint8_t* tr_b = (const uint8_t*)tr.data();

  // issuer public key + doctype
  Fp256Base::Elt pkX = p256_base.of_untrusted_string(json_hex(ij, "pkx_hex").c_str()).value();
  Fp256Base::Elt pkY = p256_base.of_untrusted_string(json_hex(ij, "pky_hex").c_str()).value();
  std::vector<uint8_t> docType;
  { size_t i = ij.find("\"doctype\""); i = ij.find(':', i); i = ij.find('"', i) + 1;
    size_t e = ij.find('"', i); docType.assign(ij.begin() + i, ij.begin() + e); }

  // public requested attribute(s). attr_id/attr_hex are comma-separated lists, so
  // a single proof can disclose several (e.g. "age_over_18,resident_city" with
  // "f5,69eab980ed8facec8b9c" for true + tstr("Gimpo-si")).
  auto split = [](const std::string& s) {
    std::vector<std::string> out; size_t p = 0, q;
    while ((q = s.find(',', p)) != std::string::npos) { out.push_back(s.substr(p, q - p)); p = q + 1; }
    out.push_back(s.substr(p)); return out;
  };
  std::vector<std::string> ids = split(attr_id), hexes = split(attr_hex);
  if (ids.size() != hexes.size()) { printf("ERROR: attr id/hex count mismatch\n"); return 2; }
  size_t npub = ids.size();
  std::vector<RequestedAttribute> attrs(npub);
  { const char* ns = "org.iso.18013.5.1";
    auto nyb = [](char c){ return (c<='9')?c-'0':(c|32)-'a'+10; };
    for (size_t a = 0; a < npub; ++a) {
      memset(&attrs[a], 0, sizeof(RequestedAttribute));
      memcpy(attrs[a].namespace_id, ns, strlen(ns)); attrs[a].namespace_len = strlen(ns);
      memcpy(attrs[a].id, ids[a].data(), ids[a].size()); attrs[a].id_len = ids[a].size();
      const std::string& h = hexes[a];
      for (size_t i = 0; i + 1 < h.size(); i += 2)
        attrs[a].cbor_value[attrs[a].cbor_value_len++] = (nyb(h[i])<<4)|nyb(h[i+1]);
    } }

  // ---- build the two witnesses (real mdoc parse) ----
  auto hw = std::make_unique<MdocHashWitness<P256, f_128>>(npub, p256, Fs);
  auto sw = std::make_unique<MdocSignatureWitness<P256, Fp256Scalar>>(p256, p256_scalar, Fs);
  uint8_t now20[20]; memset(now20, 0, 20); memcpy(now20, now, std::min<size_t>(20, strlen(now)));
  MdocProverErrorCode eh = hw->compute_witness(mdoc_b, mdoc.size(), tr_b, tr.size(), attrs.data(), npub, 7);
  if (eh != MDOC_PROVER_SUCCESS) { printf("ERROR: hash witness failed (code %d)\n", (int)eh); return 1; }
  MdocProverErrorCode es = sw->compute_witness(pkX, pkY, mdoc_b, mdoc.size(), tr_b, tr.size());
  if (es != MDOC_PROVER_SUCCESS) { printf("ERROR: sig witness failed (code %d)\n", (int)es); return 1; }
  Fp256Base::Elt htr = sw->e2_;                  // session-transcript hash (public)
  Fp256Base::Elt common[3] = {hw->e_, hw->dpkx_, hw->dpky_};

  // ---- holder's secret + blinding (the issuer NEVER saw these) --------------
  // File: secret_hex (64) ‖ blind_hex (64). Default path overridable via
  // HOLDER_SECRET (the demo passes an absolute path).
  std::string hs_path = getenv("HOLDER_SECRET") ? getenv("HOLDER_SECRET")
                                                : "playground/fixtures/mdoc-holder-secret.txt";
  std::string hs = rf(hs_path);
  while (!hs.empty() && (hs.back() == '\n' || hs.back() == '\r')) hs.pop_back();
  if (hs.size() < 2 * (hashc::SECLEN + hashc::BLINDLEN)) {
    printf("ERROR: holder-secret file too short (%s) — run gen-mdoc-blind.mjs\n", hs_path.c_str());
    return 2;
  }
  auto nyb = [](char c) { if (c >= '0' && c <= '9') return c - '0';
                          if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                          if (c >= 'A' && c <= 'F') return c - 'A' + 10; return 0; };
  uint8_t hsecret[hashc::SECLEN], hblind[hashc::BLINDLEN];
  for (size_t i = 0; i < hashc::SECLEN; ++i)
    hsecret[i] = (uint8_t)((nyb(hs[2 * i]) << 4) | nyb(hs[2 * i + 1]));
  for (size_t i = 0; i < hashc::BLINDLEN; ++i)
    hblind[i] = (uint8_t)((nyb(hs[2 * (hashc::SECLEN + i)]) << 4) | nyb(hs[2 * (hashc::SECLEN + i) + 1]));
  if (getenv("EVIL_SECRET")) {
    hsecret[0] ^= 1;  // a secret that does NOT open the committed C
    printf("  [EVIL_SECRET] secret does NOT open committed C -> opening must fail\n");
  }

  // ---- locate the pseudonym_commitment item and build the nullifier witness ----
  const FullAttribute* sec = nullptr;
  for (auto& fa : hw->pm_.attributes_)
    if (fa.id_len == 20 && memcmp(fa.doc + fa.id_ind, "pseudonym_commitment", 20) == 0) sec = &fa;
  if (!sec) { printf("ERROR: pseudonym_commitment not present in mdoc\n"); return 2; }
  hashc::NullHost nh;
  const uint8_t* item = sec->doc + sec->tag_ind;
  size_t item_len = sec->tag_len;
  if (item_len > 64 * hashc::SECB) { printf("ERROR: commitment item %zuB > %zuB\n", item_len, 64 * hashc::SECB); return 2; }
  FlatSHA256Witness::transform_and_witness_message(item_len, item, hashc::SECB, nh.item_nb, nh.item, nh.item_bw);
  size_t anchor = find_bytes(item, item_len, hashc::ANCHOR, hashc::ANCHORN);
  if (anchor == std::string::npos) { printf("ERROR: anchor not found in commitment item\n"); return 2; }
  nh.anchor_off = anchor;
  nh.mso_v = sec->mso.v;
  memcpy(nh.secret, hsecret, hashc::SECLEN);
  memcpy(nh.blind, hblind, hashc::BLINDLEN);

  // opening: open = SHA(secret ‖ blind). Host sanity: it must equal committed C.
  uint8_t omsg[hashc::SECLEN + hashc::BLINDLEN];
  memcpy(omsg, hsecret, hashc::SECLEN);
  memcpy(omsg + hashc::SECLEN, hblind, hashc::BLINDLEN);
  uint8_t openc[32]; ::SHA256(omsg, sizeof omsg, openc);
  if (memcmp(openc, item + anchor + hashc::ANCHORN, 32) != 0 && !getenv("EVIL_SECRET"))
    printf("  WARNING: SHA(secret‖blind) != committed C (holder-secret mismatch) — proof will REJECT\n");
  FlatSHA256Witness::transform_and_witness_message(sizeof omsg, omsg, hashc::COMMB, nh.open_nb, nh.open_pre, nh.open_bw);

  // nullifier = SHA( secret(32) ‖ SHA(context)(32) ) — from the holder's secret
  uint8_t ctxh[32]; ::SHA256((const uint8_t*)context.data(), context.size(), ctxh);
  uint8_t nmsg[hashc::SECLEN + hashc::CTXLEN];
  memcpy(nmsg, hsecret, hashc::SECLEN);
  memcpy(nmsg + hashc::SECLEN, ctxh, hashc::CTXLEN);
  uint8_t nullhash[32]; ::SHA256(nmsg, sizeof nmsg, nullhash);
  if (getenv("EVIL_NULL")) { nullhash[0] ^= 1; printf("  [EVIL_NULL] claiming a forged nullifier for same secret/context\n"); }
  FlatSHA256Witness::transform_and_witness_message(sizeof nmsg, nmsg, hashc::NULLB, nh.npre_nb, nh.npre, nh.npre_bw);

  // ---- sample the prover's MAC key half; compute sig macs over common ----
  SecureRandomEngine rng;
  Linker lk; { MACReference<f_128> mr; mr.sample(lk.ap, 6, &rng); }
  for (int i = 0; i < 3; ++i) {
    uint8_t buf[32]; p256_base.to_bytes_field(buf, common[i]);
    sw->macs_[i].compute_witness(&lk.ap[2 * i], buf);
  }

  // ---- compile/cache both circuits ----
  std::string bindir(argv[0]); size_t sl = bindir.rfind('/');
  std::string cdir = (sl == std::string::npos ? std::string(".") : bindir.substr(0, sl)) + "/../circuits-cache";
  mkdir(cdir.c_str(), 0755);

  printf("mdoc nullifier: two-circuit split (Fp256 sig + GF(2^128) hash), %zu public attr — present + verify\n", npub);
  Result rs, rh;
  auto tb0 = std::chrono::steady_clock::now();
  auto Csig = get_circuit<Fp256Base>(p256_base, P256_ID, cdir + "/mdoc-sig.bin",
      [] { return sigc::make_sig_circuit(); }, rs.circ_kb);
  char geo[64]; snprintf(geo, sizeof geo, "%zua-secb%zu-cb%zu-nb%zu", npub, hashc::SECB, hashc::COMMB, hashc::NULLB);
  auto Chash = get_circuit<f_128>(Fs, GF2_128_ID, cdir + "/mdoc-nullblind-hash-" + geo + ".bin",
      [&] { return hashc::make_hash_circuit(Fs, npub); }, rh.circ_kb);
  long build_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-tb0).count();
  printf("  circuits ready in %ld ms\n", build_ms);
  rs.ninputs = Csig->ninputs; rh.ninputs = Chash->ninputs;

  const size_t si = 4, hi = Chash->npub_in - 7;   // sig macs follow {1,pkX,pkY,htr}; hash macs are last 7
  const gf2k zero6[6] = {Fs.zero(), Fs.zero(), Fs.zero(), Fs.zero(), Fs.zero(), Fs.zero()};

  // RS factories
  const sigc::f2_p256 p256_2(p256_base);
  const sigc::Elt2 omega = p256_2.of_string(sigc::kRootX, sigc::kRootY);
  const sigc::FftExt fft(p256_base, p256_2, omega, 1ull << 31);
  const sigc::RSFp rsf_s(fft, p256_base);
  const hashc::RSGf rsf_h(Fs);

  // ======================= PROVER =======================
  auto W_sig = Dense<Fp256Base>(1, Csig->ninputs);
  auto W_hash = Dense<f_128>(1, Chash->ninputs);
  if (!sigc::fill(W_sig, false, pkX, pkY, htr, sw.get(), zero6, Fs.zero())) { printf("sig fill failed\n"); return 1; }
  if (!hashc::fill(W_hash, false, Fs, npub, attrs.data(), now20, ctxh, nullhash, hw.get(), &nh, lk.ap, zero6, Fs.zero())) { printf("hash fill failed\n"); return 1; }

  Transcript tp(tr_b, tr.size(), kVer);   // random oracle seeded by the session transcript
  ZkProof<f_128> h_zk(*Chash, kRate, kNreq);
  ZkProof<Fp256Base> s_zk(*Csig, kRate, kNreq);
  ZkProver<f_128, hashc::RSGf> hash_p(*Chash, Fs, rsf_h);
  ZkProver<Fp256Base, sigc::RSFp> sig_p(*Csig, p256_base, rsf_s);
  auto t0 = std::chrono::steady_clock::now();
  hash_p.commit(h_zk, W_hash, tp, rng);
  sig_p.commit(s_zk, W_sig, tp, rng);

  gf2k av = generate_mac_key(tp, Fs), gmacs[6];
  uint8_t macs_b[6 * f_128::kBytes];
  compute_macs(common, gmacs, macs_b, lk.ap, av, Fs);
  update_macs(W_sig, W_hash, si, hi, gmacs, av);

  bool ph = hash_p.prove(h_zk, W_hash, tp);
  bool psg = sig_p.prove(s_zk, W_sig, tp);
  long prove_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();
  if (!ph || !psg) {
    // The witness does not satisfy the circuit (e.g. EVIL_NULL: a forged
    // nullifier cannot satisfy nullifier == SHA(secret ‖ SHA(context))).
    printf("mdoc nullifier: PROVE REJECTED (unsatisfiable witness%s) — hash:%s sig:%s\n",
           getenv("EVIL_NULL") ? ", forged nullifier" : "",
           ph ? "ok" : "fail", psg ? "ok" : "fail");
    return 1;
  }

  std::vector<uint8_t> hb, sb;
  h_zk.write(hb, Fs); s_zk.write(sb, p256_base);
  rh.proof_kb = hb.size() / 1024; rs.proof_kb = sb.size() / 1024;
  std::vector<uint8_t> bundle(macs_b, macs_b + 6 * f_128::kBytes);
  bundle.insert(bundle.end(), hb.begin(), hb.end());
  bundle.insert(bundle.end(), sb.begin(), sb.end());

  bool tamper = getenv("TAMPER") != nullptr;
  if (tamper) { bundle[0] ^= 1; printf("  [TAMPER] flipped 1 bit of mac_e in the bundle\n"); }

  // ======================= VERIFIER =======================
  gf2k gmacs2[6];
  for (int i = 0; i < 6; ++i) gmacs2[i] = Fs.of_bytes_field(bundle.data() + i * f_128::kBytes).value();
  std::vector<uint8_t> rest(bundle.begin() + 6 * f_128::kBytes, bundle.end());
  ReadBuffer rb(rest);
  ZkProof<f_128> pr_h(*Chash, kRate, kNreq);
  ZkProof<Fp256Base> pr_s(*Csig, kRate, kNreq);
  if (!pr_h.read(rb, Fs) || !pr_s.read(rb, p256_base)) { printf("proof read failed\n"); return 1; }

  auto tv0 = std::chrono::steady_clock::now();
  Transcript tv(tr_b, tr.size(), kVer);
  ZkVerifier<f_128, hashc::RSGf> hash_v(*Chash, rsf_h, kRate, kNreq, Fs);
  ZkVerifier<Fp256Base, sigc::RSFp> sig_v(*Csig, rsf_s, kRate, kNreq, p256_base);
  hash_v.recv_commitment(pr_h, tv);
  sig_v.recv_commitment(pr_s, tv);
  gf2k av2 = generate_mac_key(tv, Fs);

  auto pub_sig = Dense<Fp256Base>(1, Csig->npub_in);
  auto pub_hash = Dense<f_128>(1, Chash->npub_in);
  sigc::fill(pub_sig, true, pkX, pkY, htr, nullptr, gmacs2, av2);
  hashc::fill(pub_hash, true, Fs, npub, attrs.data(), now20, ctxh, nullhash, nullptr, nullptr, nullptr, gmacs2, av2);
  bool vh = hash_v.verify(pr_h, pub_hash, tv);
  bool vsg = sig_v.verify(pr_s, pub_sig, tv);
  long verify_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - tv0).count();

  bool sok = psg && vsg, hok = ph && vh;
  printf("  sig  (Fp256)   : ninputs=%zu circuit=%zu KB  proof=%zu KB  %s\n",
         rs.ninputs, rs.circ_kb, rs.proof_kb, sok ? "ACCEPT" : "REJECT");
  printf("  hash (GF2^128) : ninputs=%zu circuit=%zu KB  proof=%zu KB  %s\n",
         rh.ninputs, rh.circ_kb, rh.proof_kb, hok ? "ACCEPT" : "REJECT");
  printf("  nullifier      : ");
  for (int i = 0; i < 32; ++i) printf("%02x", nullhash[i]);
  printf("   (context=\"%s\")\n", context.c_str());
  if (tamper) {
    bool pass = !sok && !hok;
    printf("  TOTAL [TAMPER] : both rejected? %s  -> MAC link is enforced: %s\n",
           (!sok && !hok) ? "yes" : "no", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
  }
  printf("  TOTAL          : prove=%ld ms  verify=%ld ms  bundle=%zu KB -> %s\n",
         prove_ms, verify_ms, bundle.size() / 1024,
         (sok && hok) ? "ACCEPT (real mdoc, two circuits, soundly linked, pseudonym nullifier)" : "REJECT");
  return (sok && hok) ? 0 : 1;
}
