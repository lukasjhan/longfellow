// Real mdoc (ISO 18013-5) ZK presentation as TWO linked circuits, PLUS
// PRIVACY-PRESERVING REVOCATION — the mdoc counterpart of sdjwt_revoc_split.cc.
//
// Based on mdoc_null_split.cc; the pseudonym nullifier block is replaced by a
// revocation block (signed-span non-membership) that proves the credential is
// NOT revoked without revealing which credential it is.
//
//   * sig  circuit over Fp256:    issuer ECDSA over the MSO hash e + device ECDSA
//                                 over the transcript hash + CRA ECDSA over e_span.
//   * hash circuit over GF(2^128): SHA(MSO) + validFrom/Until + deviceKey +
//                                 valueDigests membership + public attributes
//                                 (MdocHash::assert_valid_hash_mdoc, unchanged),
//                                 PLUS a revocation block:
//        - rev_id = the MSO valueDigests entry of a hidden, issuer-committed
//          `revocation_id` IssuerSignedItem (= SHA(item)); proven to be in the
//          signed MSO (membership) and bound to that element by a literal CBOR
//          anchor (elementIdentifier "revocation_id"). rev_id is never revealed,
//        - a CRA (revocation authority) signs the open gaps `epoch ‖ l ‖ r`
//          between adjacent revoked ids; the circuit proves SHA(epoch‖l‖r)=e_span,
//          pins epoch (freshness), and asserts l < rev_id < r ⇒ NOT revoked.
//
// Method = longfellow's own MdocRevocationSpan (lib/circuits/tests/mdoc/
// mdoc_revocation.h). The circuits are MAC-linked over (e, dpkx, dpky, e_span):
// one shared committed key half a_p[8], a_v from the post-commit transcript, the
// macs public in BOTH. Bundle = [8 macs][hash proof][sig proof]. Constant-size
// proof regardless of the revocation-list size.

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
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
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
struct Linker { gf2k ap[8]; };  // 4 MAC-linked values (e, dpkx, dpky, e_span) × 2

gf2k generate_mac_key(Transcript& t, const f_128& gf) {
  uint8_t buf[f_128::kBytes];
  t.bytes(buf, f_128::kBytes);
  return gf.of_bytes_field(buf).value();
}

void compute_macs(const Fp256Base::Elt x[4], gf2k gmacs[8],
                  uint8_t macs_b[8 * f_128::kBytes], const gf2k ap[8], gf2k av,
                  const f_128& gf) {
  MACReference<f_128> mr;
  for (int i = 0; i < 4; ++i) {
    uint8_t buf[32];
    p256_base.to_bytes_field(buf, x[i]);
    mr.compute(&gmacs[2 * i], av, &ap[2 * i], buf);
    gf.to_bytes_field(&macs_b[2 * i * f_128::kBytes], gmacs[2 * i]);
    gf.to_bytes_field(&macs_b[(2 * i + 1) * f_128::kBytes], gmacs[2 * i + 1]);
  }
}

void update_macs(Dense<Fp256Base>& Ws, Dense<f_128>& Wh, size_t si, size_t hi,
                 const gf2k gmacs[8], gf2k av) {
  auto put = [&](const gf2k& m) {
    for (size_t j = 0; j < f_128::kBits; ++j)
      Ws.v_[si++] = m[j] ? p256_base.one() : p256_base.zero();
    Wh.v_[hi++] = m;
  };
  for (int mi = 0; mi < 8; ++mi) put(gmacs[mi]);
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
using Ecdsa = VerifyCircuit<LC, Fp256Base, P256>;   // extra CRA span sig
using EcdsaW = Ecdsa::Witness;
using EcdsaHostW = VerifyWitness3<P256, Fp256Scalar>;
using MacBP = BitPlucker<LC, kMACPluckerBits>;
using MACc = MAC<LC, MacBP>;                         // Fp256 MAC for e_span link
using MACcW = MACc::Witness;
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
  EltW craPkX = L.eltw_input(), craPkY = L.eltw_input();  // CRA (revocation authority) pubkey
  v128 mac_e[2], mac_dx[2], mac_dy[2], mac_es[2], av;
  for (auto& m : mac_e) m = L.template vinput<128>();
  for (auto& m : mac_dx) m = L.template vinput<128>();
  for (auto& m : mac_dy) m = L.template vinput<128>();
  for (auto& m : mac_es) m = L.template vinput<128>();
  av = L.template vinput<128>();
  Q.private_input();
  MS::Witness vw;
  vw.input(L);
  EltW e_span = L.eltw_input();            // SHA(epoch‖l‖r), MAC-linked to hash circuit
  EcdsaW span_sig; span_sig.input(L);
  MACcW span_macw; span_macw.input(L);
  MS ms(L, p256, n256_order);
  ms.assert_signatures(pkX, pkY, htr, mac_e, mac_dx, mac_dy, av, vw);
  // CRA signed the span (epoch‖l‖r) -> e_span; bind e_span across circuits by MAC.
  Ecdsa ecc(L, p256, n256_order);
  ecc.verify_signature3(craPkX, craPkY, e_span, span_sig);
  MACc macc(L);
  macc.verify_mac(e_span, mac_es, av, span_macw, n256_order);
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
          const Fp256Base::Elt& craPkX, const Fp256Base::Elt& craPkY,
          const Fp256Base::Elt& e_span,
          MdocSignatureWitness<P256, Fp256Scalar>* sw,
          EcdsaHostW* span_sw, MacWitness<Fp256Base>* espan_mw,
          const gf2k macs8[8], gf2k av) {
  DenseFiller<Fp256Base> f(W);
  f.push_back(p256_base.one());
  f.push_back(pkX); f.push_back(pkY); f.push_back(htr);
  f.push_back(craPkX); f.push_back(craPkY);
  for (int i = 0; i < 8; ++i) push_gf_bits(f, macs8[i]);
  push_gf_bits(f, av);
  if (pub_only) return true;
  sw->fill_witness(f);   // e, dpkx, dpky, issuer-sig, device-sig, macs[3]
  f.push_back(e_span);   // appended e_span witness + CRA span sig + e_span MAC
  span_sw->fill_witness(f);
  espan_mw->fill_witness(f);
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

// revocation geometry (mirrors sdjwt_revoc_split, sized for mdoc's CBOR item).
constexpr size_t SECB = 3;     // revocation_id IssuerSignedItem: <=3 SHA blocks (192B)
constexpr size_t SPANB = 2;    // SHA blocks for the 72B span (epoch‖l‖r)
// Literal CBOR anchor binding the item identity to the `revocation_id` element:
//   71 "elementIdentifier" 6D "revocation_id"
static constexpr uint8_t ANCHOR[] = {
    0x71, 'e', 'l', 'e', 'm', 'e', 'n', 't', 'I', 'd', 'e', 'n', 't', 'i', 'f',
    'i',  'e', 'r', 0x6D, 'r', 'e', 'v', 'o', 'c', 'a', 't', 'i', 'o', 'n', '_',
    'i',  'd'};
constexpr size_t ANCHORN = sizeof(ANCHOR);  // 32

static v8 vb(const LC& L, uint8_t c) { return L.template vbit<8>(c); }

// Prove the hidden, issuer-committed pseudonym_secret -> public nullifier.
// Uses w.in_ (the signed MSO bytes) for the membership proof; the secret value
// stays private and is bound only into the nullifier SHA.
struct RevWit {
  v8 sec_item[64 * SECB];   // tagged revocation_id IssuerSignedItem (D8 18 58 .. A4 ..)
  SBW sec_sha[SECB];
  v8 sec_nb;
  vind sec_mso;             // byte index of the item's 32B digest within the MSO
  vind sec_anchor;          // byte offset of ANCHOR within sec_item
  v8 span_pre[64 * SPANB];  // CRA-signed span: epoch ‖ l ‖ r
  v256 span_ebits;          // = SHA(span), MAC-linked to the sig circuit's e_span
  SBW span_sha[SPANB];
  v8 span_nb;
  void input(const LC& L) {
    for (auto& b : sec_item) b = L.template vinput<8>();
    for (auto& s : sec_sha) s.input(L);
    sec_nb = L.template vinput<8>();
    sec_mso = L.template vinput<kCborIndexBits>();
    sec_anchor = L.template vinput<kCborIndexBits>();
    for (auto& b : span_pre) b = L.template vinput<8>();
    span_ebits = L.template vinput<256>();
    for (auto& s : span_sha) s.input(L);
    span_nb = L.template vinput<8>();
  }
};

void assert_revocation(const LC& L, FlatSHA& sha, Routing<LC>& r,
                       const MdocH::Witness& w, const v8 epoch_pub[8],
                       const RevWit& nw) {
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

  // (2) Membership: rev_id = mm = SHA(sec_item) appears as a 32B CBOR byte string
  //     (58 20 ..) at sec_mso in the signed MSO valueDigests. Issuer-committed, so
  //     the prover cannot inject a fake rev_id. (Same as MdocHash's attribute
  //     membership, with a 3-block item.) `mm` (a v256) IS the revocation id.
  std::vector<v8> cmp(kMaxMsoLen);
  r.shift(nw.sec_mso, 2 + 32, cmp.data(), kMaxMsoLen, w.in_ + 5 + 2, zz, 3);
  eqc(cmp[0], 0x58);
  eqc(cmp[1], 0x20);
  v256 mm;
  for (size_t j = 0; j < 256; ++j) mm[j] = cmp[2 + (255 - j) / 8][(j % 8)];
  L.vassert_is_bit(mm);
  sha.assert_message_hash(SECB, nw.sec_nb, nw.sec_item, mm, nw.sec_sha);

  // (3) Anchor: bind that this item is the `revocation_id` element (identity), so
  //     rev_id is the digest of that specific claim and not some other item.
  v8 ext[ANCHORN];
  r.shift(nw.sec_anchor, ANCHORN, ext, 64 * SECB, nw.sec_item, zz, 3);
  for (size_t j = 0; j < ANCHORN; ++j) eqc(ext[j], ANCHOR[j]);

  // (4) span: e_span = SHA(epoch‖l‖r) (its CRA signature is checked in the sig
  //     circuit via the e_span MAC); pin epoch for freshness; then prove
  //     l < rev_id < r — rev_id between two adjacent revoked ids ⇒ NOT revoked.
  eqc(nw.span_nb, (uint8_t)SPANB);
  for (size_t j = 0; j < 8; ++j) L.vassert_eq(nw.span_pre[j], epoch_pub[j]);
  sha.assert_message_hash(SPANB, nw.span_nb, nw.span_pre, nw.span_ebits, nw.span_sha);
  v256 lbits, rbits;
  for (size_t i = 0; i < 256; ++i) {
    lbits[i] = nw.span_pre[8 + i / 8][i % 8];
    rbits[i] = nw.span_pre[40 + i / 8][i % 8];
  }
  L.assert1(L.vlt(lbits, mm));
  L.assert1(L.vlt(mm, rbits));
}

std::unique_ptr<Circuit<f_128>> make_hash_circuit(const f_128& Fs, size_t npub) {
  QuadCircuit<f_128> Q(Fs);
  const CB cbk(&Q);
  const LC L(&cbk, Fs);
  MAC mac_check(L);
  FlatSHA sha(L);
  Routing<LC> r(L);

  // ---- public inputs: oa[npub], now[20], epoch_pub[8], mac[9] ----
  std::vector<MdocH::OpenedAttribute> oa(npub);
  MdocH mdoc_h(L);
  for (size_t ai = 0; ai < npub; ++ai) oa[ai].input(L);
  v8 now[20];
  for (auto& b : now) b = L.template vinput<8>();
  v8 epoch_pub[8];     // revocation epoch (public, freshness pin)
  for (auto& b : epoch_pub) b = L.template vinput<8>();
  MACTag mac[9];       // 4 MAC-linked values (e, dpkx, dpky, e_span) + av
  for (auto& m : mac) m = L.eltw_input();
  Q.private_input();

  // ---- private: e, dpkx, dpky, MdocHash witness, revocation witness, macs ----
  v256 e = L.template vinput<256>();
  v256 dpkx = L.template vinput<256>();
  v256 dpky = L.template vinput<256>();
  auto w = std::make_unique<MdocH::Witness>(npub);
  w->input(L);
  RevWit nw;
  nw.input(L);
  Q.begin_full_field();
  MACW macw[4];
  for (auto& mw : macw) mw.input(L);

  // ---- assertions ----
  mdoc_h.assert_valid_hash_mdoc(oa.data(), now, e, dpkx, dpky, *w);
  assert_revocation(L, sha, r, *w, epoch_pub, nw);
  mac_check.verify_mac(&mac[0], mac[8], e, macw[0]);
  mac_check.verify_mac(&mac[2], mac[8], dpkx, macw[1]);
  mac_check.verify_mac(&mac[4], mac[8], dpky, macw[2]);
  mac_check.verify_mac(&mac[6], mac[8], nw.span_ebits, macw[3]);

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

// Carries the precomputed revocation host witness (built once in main).
struct RevHost {
  uint8_t item[64 * SECB]; FlatSHA256Witness::BlockWitness item_bw[SECB]; uint8_t item_nb = 0;
  size_t mso_v = 0, anchor_off = 0;
  uint8_t span[64 * SPANB]; FlatSHA256Witness::BlockWitness span_bw[SPANB]; uint8_t span_nb = 0;
  uint8_t span_dg[32] = {0};   // SHA(span) = e_span (bound as span_ebits)
};

// Fill the hash dense array. macs6/av in the public tail (zeros at commit; real
// for verify). pub_only -> public inputs only.
bool fill(Dense<f_128>& W, bool pub_only, const f_128& Fs, size_t npub,
          const RequestedAttribute* attrs, const uint8_t* now20, uint64_t epoch,
          MdocHashWitness<P256, f_128>* hw, const RevHost* nh,
          const gf2k* ap, const gf2k macs8[8], gf2k av) {
  BitPluckerEncoder<f_128, kSHAPluckerBits> enc(Fs);
  DenseFiller<f_128> f(W);
  // ---- public ----
  f.push_back(Fs.one());
  for (size_t ai = 0; ai < npub; ++ai)
    if (fill_attribute(f, attrs[ai], Fs, /*version=*/7) != MDOC_PROVER_SUCCESS) return false;
  fill_bit_string(f, now20, 20, 20, Fs);
  for (int i = 0; i < 8; ++i) f.push_back((uint8_t)((epoch >> (8 * i)) & 0xff), 8, Fs);
  for (int i = 0; i < 8; ++i) f.push_back(macs8[i]);
  f.push_back(av);
  if (pub_only) return true;

  // ---- private ----
  uint8_t buf[32];
  p256_base.to_bytes_field(buf, hw->e_);    fill_bit_string(f, buf, 32, 32, Fs);
  p256_base.to_bytes_field(buf, hw->dpkx_); fill_bit_string(f, buf, 32, 32, Fs);
  p256_base.to_bytes_field(buf, hw->dpky_); fill_bit_string(f, buf, 32, 32, Fs);
  hw->fill_witness(f, /*version=*/7);
  // revocation witness: revocation_id item membership + CRA-signed span
  for (size_t i = 0; i < 64 * SECB; ++i) f.push_back(nh->item[i], 8, Fs);
  for (size_t b = 0; b < SECB; ++b) fill_sha(f, enc, nh->item_bw[b]);
  f.push_back(nh->item_nb, 8, Fs);
  f.push_back(nh->mso_v, kCborIndexBits, Fs);
  f.push_back(nh->anchor_off, kCborIndexBits, Fs);
  for (size_t i = 0; i < 64 * SPANB; ++i) f.push_back(nh->span[i], 8, Fs);
  push_rev_bits(f, nh->span_dg, Fs);   // span_ebits, SHA output bit-order
  for (size_t b = 0; b < SPANB; ++b) fill_sha(f, enc, nh->span_bw[b]);
  f.push_back(nh->span_nb, 8, Fs);
  // mac witnesses (the shared, av-independent key halves)
  for (int i = 0; i < 8; ++i) f.push_back(ap[i]);
  return true;
}
}  // namespace hashc
}  // namespace proofs

// Generate a fresh CRA (revocation authority) P-256 key and ECDSA-sign the 32-byte
// span digest. If bad_key, sign with a DIFFERENT key (so verification must fail).
// Outputs the public key (X,Y) and signature (r,s) as 32-byte big-endian values.
static bool cra_keygen_sign(const uint8_t span_dg[32], bool bad_key,
                            uint8_t pkx[32], uint8_t pky[32],
                            uint8_t sr[32], uint8_t ss[32]) {
  EC_KEY* k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!k || !EC_KEY_generate_key(k)) return false;
  const EC_GROUP* g = EC_KEY_get0_group(k);
  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();
  EC_POINT_get_affine_coordinates(g, EC_KEY_get0_public_key(k), x, y, nullptr);
  BN_bn2binpad(x, pkx, 32);
  BN_bn2binpad(y, pky, 32);
  EC_KEY* signer = k;
  EC_KEY* k2 = nullptr;
  if (bad_key) {
    k2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(k2);
    signer = k2;  // sign with a key that is NOT the advertised CRA key
  }
  ECDSA_SIG* sig = ECDSA_do_sign(span_dg, 32, signer);
  bool ok = false;
  if (sig) {
    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);
    BN_bn2binpad(r, sr, 32);
    BN_bn2binpad(s, ss, 32);
    ECDSA_SIG_free(sig);
    ok = true;
  }
  BN_free(x);
  BN_free(y);
  EC_KEY_free(k);
  if (k2) EC_KEY_free(k2);
  return ok;
}

int main(int argc, char** argv) {
  using namespace proofs;
  set_log_level(ERROR);
  std::string mdoc_path = argc > 1 ? argv[1] : "playground/fixtures/mdoc.bin";
  std::string issuer_json = argc > 2 ? argv[2] : "playground/fixtures/mdoc-issuer.json";
  std::string transcript_path = argc > 3 ? argv[3] : "playground/fixtures/mdoc-transcript.bin";
  const char* now = argc > 4 ? argv[4] : "2026-06-01T00:00:00Z";
  std::string attr_id = argc > 5 ? argv[5] : "age_over_18";   // public disclosed attr
  std::string attr_hex = argc > 6 ? argv[6] : "f5";           // its CBOR value (true)
  uint64_t epoch = argc > 7 ? strtoull(argv[7], nullptr, 10) : 1;  // revocation list epoch (freshness)

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

  // public requested attribute (the disclosed one, e.g. age_over_18 = f5)
  std::vector<RequestedAttribute> attrs(1);
  memset(&attrs[0], 0, sizeof(RequestedAttribute));
  { const char* ns = "org.iso.18013.5.1";
    memcpy(attrs[0].namespace_id, ns, strlen(ns)); attrs[0].namespace_len = strlen(ns);
    memcpy(attrs[0].id, attr_id.data(), attr_id.size()); attrs[0].id_len = attr_id.size();
    for (size_t i = 0; i + 1 < attr_hex.size(); i += 2) {
      auto nyb = [](char c){ return (c<='9')?c-'0':(c|32)-'a'+10; };
      attrs[0].cbor_value[attrs[0].cbor_value_len++] = (nyb(attr_hex[i])<<4)|nyb(attr_hex[i+1]); } }
  size_t npub = attrs.size();

  // ---- build the two witnesses (real mdoc parse) ----
  auto hw = std::make_unique<MdocHashWitness<P256, f_128>>(npub, p256, Fs);
  auto sw = std::make_unique<MdocSignatureWitness<P256, Fp256Scalar>>(p256, p256_scalar, Fs);
  uint8_t now20[20]; memset(now20, 0, 20); memcpy(now20, now, std::min<size_t>(20, strlen(now)));
  MdocProverErrorCode eh = hw->compute_witness(mdoc_b, mdoc.size(), tr_b, tr.size(), attrs.data(), npub, 7);
  if (eh != MDOC_PROVER_SUCCESS) { printf("ERROR: hash witness failed (code %d)\n", (int)eh); return 1; }
  MdocProverErrorCode es = sw->compute_witness(pkX, pkY, mdoc_b, mdoc.size(), tr_b, tr.size());
  if (es != MDOC_PROVER_SUCCESS) { printf("ERROR: sig witness failed (code %d)\n", (int)es); return 1; }
  Fp256Base::Elt htr = sw->e2_;                  // session-transcript hash (public)
  auto nat_be = [](const uint8_t* be) {
    uint8_t t[32]; for (int i = 0; i < 32; ++i) t[i] = be[31 - i];
    return P256Nat::of_bytes(t);
  };

  // ---- locate the revocation_id item; rev_id = SHA(item) (= its valueDigests entry) ----
  const FullAttribute* sec = nullptr;
  for (auto& fa : hw->pm_.attributes_)
    if (fa.id_len == 13 && memcmp(fa.doc + fa.id_ind, "revocation_id", 13) == 0) sec = &fa;
  if (!sec) { printf("ERROR: revocation_id not present in mdoc\n"); return 2; }
  hashc::RevHost nh;
  const uint8_t* item = sec->doc + sec->tag_ind;
  size_t item_len = sec->tag_len;
  if (item_len > 64 * hashc::SECB) { printf("ERROR: revocation_id item %zuB > %zuB\n", item_len, 64 * hashc::SECB); return 2; }
  FlatSHA256Witness::transform_and_witness_message(item_len, item, hashc::SECB, nh.item_nb, nh.item, nh.item_bw);
  size_t anchor = find_bytes(item, item_len, hashc::ANCHOR, hashc::ANCHORN);
  if (anchor == std::string::npos) { printf("ERROR: anchor not found in revocation_id item\n"); return 2; }
  nh.anchor_off = anchor;
  nh.mso_v = sec->mso.v;
  uint8_t rev_dg[32]; ::SHA256(item, item_len, rev_dg);  // rev_id = SHA(item), big-endian int N

  // ---- revocation flags; build a CRA-signed span (epoch ‖ l ‖ r) with l < N < r ----
  bool revoked = getenv("REVOKED") != nullptr;   // simulate: the holder's id IS revoked
  bool badsig  = getenv("BADSIG")  != nullptr;   // simulate: span signed by a non-CRA key
  bool stale   = getenv("STALE")   != nullptr;   // simulate: span from a previous epoch
  uint64_t epoch_span = epoch + (stale ? 1 : 0); // epoch the CRA actually signed
  uint8_t l_le[32], r_le[32];
  {
    BIGNUM* N = BN_bin2bn(rev_dg, 32, nullptr);
    BIGNUM* l = BN_dup(N);
    BIGNUM* r = BN_dup(N);
    BN_add_word(r, 1);                  // r = N + 1
    if (!revoked) BN_sub_word(l, 1);    // l = N - 1 (gap brackets N); REVOKED -> l = N
    uint8_t l_be[32], r_be[32];
    BN_bn2binpad(l, l_be, 32);
    BN_bn2binpad(r, r_be, 32);
    for (int i = 0; i < 32; ++i) { l_le[i] = l_be[31 - i]; r_le[i] = r_be[31 - i]; }
    BN_free(N); BN_free(l); BN_free(r);
  }
  uint8_t spanmsg[72] = {0};
  for (int i = 0; i < 8; ++i) spanmsg[i] = (uint8_t)((epoch_span >> (8 * i)) & 0xff);
  memcpy(spanmsg + 8, l_le, 32);
  memcpy(spanmsg + 40, r_le, 32);
  ::SHA256(spanmsg, 72, nh.span_dg);
  FlatSHA256Witness::transform_and_witness_message(72, spanmsg, hashc::SPANB, nh.span_nb, nh.span, nh.span_bw);
  uint8_t craPkx[32], craPky[32], span_r[32], span_s[32];
  if (!cra_keygen_sign(nh.span_dg, badsig, craPkx, craPky, span_r, span_s)) { printf("CRA keygen/sign failed\n"); return 1; }
  if (revoked) printf("  [REVOKED] holder's rev_id is on the revocation list (no valid gap)\n");
  if (badsig)  printf("  [BADSIG] span signed by a key other than the advertised CRA key\n");
  if (stale)   printf("  [STALE] span signed for epoch %llu but verifier pins epoch %llu\n",
                      (unsigned long long)epoch_span, (unsigned long long)epoch);

  // CRA pubkey + e_span as Fp256 field elements (mirrors how `e` is derived).
  Fp256Base::Elt craPkX = p256_base.to_montgomery(nat_be(craPkx));
  Fp256Base::Elt craPkY = p256_base.to_montgomery(nat_be(craPky));
  P256Nat espan_nat = nat_be(nh.span_dg);
  Fp256Base::Elt e_span = p256_base.to_montgomery(espan_nat);
  P256Nat span_r_nat = nat_be(span_r), span_s_nat = nat_be(span_s);
  Fp256Base::Elt common[4] = {hw->e_, hw->dpkx_, hw->dpky_, e_span};

  // ---- sample the prover's MAC key half; compute the 4 sig-side mac witnesses ----
  SecureRandomEngine rng;
  Linker lk; { MACReference<f_128> mr; mr.sample(lk.ap, 8, &rng); }
  for (int i = 0; i < 3; ++i) {
    uint8_t buf[32]; p256_base.to_bytes_field(buf, common[i]);
    sw->macs_[i].compute_witness(&lk.ap[2 * i], buf);
  }
  sigc::EcdsaHostW span_sw(p256_scalar, p256);
  if (!span_sw.compute_witness(craPkX, craPkY, espan_nat, span_r_nat, span_s_nat)) { printf("span sig witness invalid\n"); return 1; }
  MacWitness<Fp256Base> espan_mw(p256_base, Fs);
  { uint8_t buf[32]; p256_base.to_bytes_field(buf, e_span); espan_mw.compute_witness(&lk.ap[6], buf); }

  // ---- compile/cache both circuits ----
  std::string bindir(argv[0]); size_t sl = bindir.rfind('/');
  std::string cdir = (sl == std::string::npos ? std::string(".") : bindir.substr(0, sl)) + "/../circuits-cache";
  mkdir(cdir.c_str(), 0755);

  printf("mdoc revocation: two-circuit split (Fp256 sig + GF(2^128) hash), %zu public attr — present + verify (not-revoked)\n", npub);
  Result rs, rh;
  auto tb0 = std::chrono::steady_clock::now();
  auto Csig = get_circuit<Fp256Base>(p256_base, P256_ID, cdir + "/mdoc-revoc-sig.bin",
      [] { return sigc::make_sig_circuit(); }, rs.circ_kb);
  char geo[64]; snprintf(geo, sizeof geo, "%zua-secb%zu-span%zu", npub, hashc::SECB, hashc::SPANB);
  auto Chash = get_circuit<f_128>(Fs, GF2_128_ID, cdir + "/mdoc-revoc-hash-" + geo + ".bin",
      [&] { return hashc::make_hash_circuit(Fs, npub); }, rh.circ_kb);
  long build_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-tb0).count();
  printf("  circuits ready in %ld ms\n", build_ms);
  rs.ninputs = Csig->ninputs; rh.ninputs = Chash->ninputs;

  const size_t si = 6, hi = Chash->npub_in - 9;   // sig macs follow {1,pkX,pkY,htr,craPkX,craPkY}; hash macs last 9
  const gf2k zero8[8] = {Fs.zero(), Fs.zero(), Fs.zero(), Fs.zero(),
                         Fs.zero(), Fs.zero(), Fs.zero(), Fs.zero()};

  // RS factories
  const sigc::f2_p256 p256_2(p256_base);
  const sigc::Elt2 omega = p256_2.of_string(sigc::kRootX, sigc::kRootY);
  const sigc::FftExt fft(p256_base, p256_2, omega, 1ull << 31);
  const sigc::RSFp rsf_s(fft, p256_base);
  const hashc::RSGf rsf_h(Fs);

  // ======================= PROVER =======================
  auto W_sig = Dense<Fp256Base>(1, Csig->ninputs);
  auto W_hash = Dense<f_128>(1, Chash->ninputs);
  if (!sigc::fill(W_sig, false, pkX, pkY, htr, craPkX, craPkY, e_span, sw.get(), &span_sw, &espan_mw, zero8, Fs.zero())) { printf("sig fill failed\n"); return 1; }
  if (!hashc::fill(W_hash, false, Fs, npub, attrs.data(), now20, epoch, hw.get(), &nh, lk.ap, zero8, Fs.zero())) { printf("hash fill failed\n"); return 1; }

  Transcript tp(tr_b, tr.size(), kVer);   // random oracle seeded by the session transcript
  ZkProof<f_128> h_zk(*Chash, kRate, kNreq);
  ZkProof<Fp256Base> s_zk(*Csig, kRate, kNreq);
  ZkProver<f_128, hashc::RSGf> hash_p(*Chash, Fs, rsf_h);
  ZkProver<Fp256Base, sigc::RSFp> sig_p(*Csig, p256_base, rsf_s);
  auto t0 = std::chrono::steady_clock::now();
  hash_p.commit(h_zk, W_hash, tp, rng);
  sig_p.commit(s_zk, W_sig, tp, rng);

  gf2k av = generate_mac_key(tp, Fs), gmacs[8];
  uint8_t macs_b[8 * f_128::kBytes];
  compute_macs(common, gmacs, macs_b, lk.ap, av, Fs);
  update_macs(W_sig, W_hash, si, hi, gmacs, av);

  bool ph = hash_p.prove(h_zk, W_hash, tp);
  bool psg = sig_p.prove(s_zk, W_sig, tp);
  long prove_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();
  if (!ph || !psg) {
    // The witness does not satisfy the circuit: a revoked credential (no gap
    // brackets rev_id), a non-CRA span signature, or a stale epoch all make
    // proving itself impossible — the strongest form of rejection.
    const char* tag = revoked ? "REVOKED" : (badsig ? "BADSIG" : (stale ? "STALE" : "?"));
    printf("mdoc revocation: PROVE REJECTED [%s] (unsatisfiable witness) — hash:%s sig:%s\n",
           tag, ph ? "ok" : "fail", psg ? "ok" : "fail");
    return 1;
  }

  std::vector<uint8_t> hb, sb;
  h_zk.write(hb, Fs); s_zk.write(sb, p256_base);
  rh.proof_kb = hb.size() / 1024; rs.proof_kb = sb.size() / 1024;
  std::vector<uint8_t> bundle(macs_b, macs_b + 8 * f_128::kBytes);
  bundle.insert(bundle.end(), hb.begin(), hb.end());
  bundle.insert(bundle.end(), sb.begin(), sb.end());

  bool tamper = getenv("TAMPER") != nullptr;
  if (tamper) { bundle[0] ^= 1; printf("  [TAMPER] flipped 1 bit of mac_e in the bundle\n"); }

  // ======================= VERIFIER =======================
  gf2k gmacs2[8];
  for (int i = 0; i < 8; ++i) gmacs2[i] = Fs.of_bytes_field(bundle.data() + i * f_128::kBytes).value();
  std::vector<uint8_t> rest(bundle.begin() + 8 * f_128::kBytes, bundle.end());
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
  sigc::fill(pub_sig, true, pkX, pkY, htr, craPkX, craPkY, e_span, nullptr, nullptr, nullptr, gmacs2, av2);
  hashc::fill(pub_hash, true, Fs, npub, attrs.data(), now20, epoch, nullptr, nullptr, nullptr, gmacs2, av2);
  bool vh = hash_v.verify(pr_h, pub_hash, tv);
  bool vsg = sig_v.verify(pr_s, pub_sig, tv);
  long verify_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - tv0).count();

  bool sok = psg && vsg, hok = ph && vh;
  printf("  sig  (Fp256)   : ninputs=%zu circuit=%zu KB  proof=%zu KB  %s\n",
         rs.ninputs, rs.circ_kb, rs.proof_kb, sok ? "ACCEPT" : "REJECT");
  printf("  hash (GF2^128) : ninputs=%zu circuit=%zu KB  proof=%zu KB  %s\n",
         rh.ninputs, rh.circ_kb, rh.proof_kb, hok ? "ACCEPT" : "REJECT");
  printf("  rev_id (SHA)   : ");
  for (int i = 0; i < 32; ++i) printf("%02x", rev_dg[i]);
  printf("   (epoch=%llu)\n", (unsigned long long)epoch);
  if (tamper) {
    bool pass = !sok && !hok;
    printf("  TOTAL [TAMPER] : both rejected? %s  -> MAC link is enforced: %s\n",
           (!sok && !hok) ? "yes" : "no", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
  }
  printf("  TOTAL          : prove=%ld ms  verify=%ld ms  bundle=%zu KB -> %s\n",
         prove_ms, verify_ms, bundle.size() / 1024,
         (sok && hok) ? "ACCEPT (real mdoc NOT revoked; two circuits, soundly linked)" : "REJECT");
  return (sok && hok) ? 0 : 1;
}
