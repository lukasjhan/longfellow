// M7 step 3: the FULL two-circuit + MAC split, end to end.
//
// Present + verify a SD-JWT-VC ZK proof as TWO linked circuits (the mdoc design):
//   * sig  circuit over Fp256:   ECDSA issuer sig over e  +  ECDSA holder KB sig
//                                over e2 with the device key dpk.
//   * hash circuit over GF(2^128): SHA + exp + vct + cnf + sd_hash binding +
//                                N×(_sd membership + structural + consent).
// The two circuits are linked by MACs over the common values e / dpkx / dpky:
// one shared MAC key (a_p[6], av) is used by BOTH, the macs are public inputs in
// BOTH, so a prover cannot use a different e/dpk in one circuit than the other.
// e2 is a public input fed to both. The proof bundle is [6 macs][av][sig][hash].
//
// This is the apples-to-apples counterpart of the monolithic sdjwt_full.cc; it
// shows the split's prove-time / size win while preserving the exact semantics.

#include <cstdint>
#include <cstdio>
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

// One shared MAC key + macs over the three common 32-byte (little-endian) values.
struct Linker {
  gf2k ap[6], av, macs[6];
  void init(SecureRandomEngine& rng, const f_128& gf,
            const uint8_t e[32], const uint8_t dx[32], const uint8_t dy[32]) {
    MACReference<f_128> mr;
    mr.sample(ap, 6, &rng);
    uint8_t avb[16]; rng.bytes(avb, 16); av = gf.of_bytes_field(avb).value();
    uint8_t e_[32], dx_[32], dy_[32];
    memcpy(e_, e, 32); memcpy(dx_, dx, 32); memcpy(dy_, dy, 32);
    mr.compute(&macs[0], av, &ap[0], e_);
    mr.compute(&macs[2], av, &ap[2], dx_);
    mr.compute(&macs[4], av, &ap[4], dy_);
  }
};

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

// ===================== Fp256 signature circuit =====================
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

std::unique_ptr<Circuit<Fp256Base>> make_sig_circuit() {
  QuadCircuit<Fp256Base> Q(p256_base);
  const CB cbk(&Q);
  const LC L(&cbk, p256_base);
  EltW pkX = L.eltw_input(), pkY = L.eltw_input(), e2 = L.eltw_input();
  v128 mac_e[2], mac_dx[2], mac_dy[2], av;
  for (auto& m : mac_e) m = L.template vinput<128>();
  for (auto& m : mac_dx) m = L.template vinput<128>();
  for (auto& m : mac_dy) m = L.template vinput<128>();
  av = L.template vinput<128>();
  Q.private_input();
  MS::Witness vw;
  vw.input(L);
  MS ms(L, p256, n256_order);
  ms.assert_signatures(pkX, pkY, e2, mac_e, mac_dx, mac_dy, av, vw);
  return Q.mkcircuit(1);
}

static void push_gf_bits(DenseFiller<Fp256Base>& f, const gf2k& g) {
  for (size_t j = 0; j < 128; ++j) f.push_back(g[j] ? p256_base.one() : p256_base.zero());
}

// returns the three little-endian 32-byte values that the MAC covers, so the
// orchestrator can build the (shared) Linker over the exact same bytes.
struct Parsed {
  Fp256Base::Elt pkX, pkY, e_, e2, dpkx, dpky;
  Nat e_nat, e2_nat, ir, is, kr, ks, nx, ny;
  uint8_t e_le[32], dx_le[32], dy_le[32];
};

bool parse(const std::string& compact, const std::string& jwk, Parsed& v) {
  std::string jwt = compact.substr(0, compact.find('~'));
  size_t d1 = jwt.find('.'), d2 = jwt.find('.', d1 + 1);
  std::string msg = jwt.substr(0, d2);
  std::string payload = b64d(jwt.substr(d1 + 1, d2 - d1 - 1));
  uint8_t h[32]; ::SHA256((const uint8_t*)msg.data(), msg.size(), h);
  std::string isig = b64d(jwt.substr(d2 + 1));
  std::string kbjwt = compact.substr(compact.rfind('~') + 1);
  size_t k1 = kbjwt.find('.'), k2 = kbjwt.find('.', k1 + 1);
  std::string kbmsg = kbjwt.substr(0, k2);
  uint8_t h2[32]; ::SHA256((const uint8_t*)kbmsg.data(), kbmsg.size(), h2);
  std::string ksig = b64d(kbjwt.substr(k2 + 1));
  size_t cnf = payload.find("\"cnf\"");
  std::string cx = b64d(payload.substr(payload.find("\"x\":\"", cnf) + 5, 43));
  std::string cy = b64d(payload.substr(payload.find("\"y\":\"", cnf) + 5, 43));
  std::string j = rf(jwk);
  auto hx = [&](const char* k){ size_t i=j.find(k); i=j.find("0x",i); return j.substr(i, j.find('"',i)-i); };
  v.pkX = p256_base.of_untrusted_string(hx("x_hex").c_str()).value();
  v.pkY = p256_base.of_untrusted_string(hx("y_hex").c_str()).value();
  v.e_nat = nat_be(h); v.e2_nat = nat_be(h2);
  v.e_ = p256_base.to_montgomery(v.e_nat); v.e2 = p256_base.to_montgomery(v.e2_nat);
  v.ir = nat_be((const uint8_t*)isig.data()); v.is = nat_be((const uint8_t*)isig.data() + 32);
  v.kr = nat_be((const uint8_t*)ksig.data()); v.ks = nat_be((const uint8_t*)ksig.data() + 32);
  v.nx = nat_be((const uint8_t*)cx.data()); v.ny = nat_be((const uint8_t*)cy.data());
  v.dpkx = p256_base.to_montgomery(v.nx); v.dpky = p256_base.to_montgomery(v.ny);
  // little-endian 32-byte forms (== to_bytes_field of the field elements)
  p256_base.to_bytes_field(v.e_le, v.e_);
  p256_base.to_bytes_field(v.dx_le, v.dpkx);
  p256_base.to_bytes_field(v.dy_le, v.dpky);
  return isig.size() >= 64 && ksig.size() >= 64;
}

bool run(const Circuit<Fp256Base>& C, const Parsed& v, const Linker& lk, Result& res) {
  const f_128 gf;
  auto W = Dense<Fp256Base>(1, C.ninputs);
  auto pub = Dense<Fp256Base>(1, C.npub_in);
  uint8_t buf[32]; Fp256Base::Elt vals[3] = {v.e_, v.dpkx, v.dpky};
  auto fill_common_pub = [&](DenseFiller<Fp256Base>& f) {
    f.push_back(p256_base.one()); f.push_back(v.pkX); f.push_back(v.pkY); f.push_back(v.e2);
    for (int i = 0; i < 6; ++i) push_gf_bits(f, lk.macs[i]);
    push_gf_bits(f, lk.av);
  };
  { DenseFiller<Fp256Base> f(W);
    fill_common_pub(f);
    f.push_back(v.e_); f.push_back(v.dpkx); f.push_back(v.dpky);
    EcdsaHostW isigw(p256_scalar, p256), ksigw(p256_scalar, p256);
    if (!isigw.compute_witness(v.pkX, v.pkY, v.e_nat, v.ir, v.is)) return false;
    if (!ksigw.compute_witness(v.dpkx, v.dpky, v.e2_nat, v.kr, v.ks)) return false;
    isigw.fill_witness(f); ksigw.fill_witness(f);
    for (int i = 0; i < 3; ++i) {
      p256_base.to_bytes_field(buf, vals[i]);
      MacWitness<Fp256Base> mw(p256_base, gf);
      mw.compute_witness(&lk.ap[2*i], buf);  // SHARED key
      mw.fill_witness(f);
    }
  }
  { DenseFiller<Fp256Base> f(pub); fill_common_pub(f); }

  const f2_p256 p256_2(p256_base);
  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExt fft(p256_base, p256_2, omega, 1ull << 31);
  const RSFp rsf(fft, p256_base);
  SecureRandomEngine rng;
  ZkProof<Fp256Base> zkp(C, kRate, kNreq);
  Transcript tp((const uint8_t*)"sig", 3, kVer);
  ZkProver<Fp256Base, RSFp> prover(C, p256_base, rsf);
  auto t0 = std::chrono::steady_clock::now();
  prover.commit(zkp, W, tp, rng);
  bool pok = prover.prove(zkp, W, tp);
  res.prove_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();
  std::vector<uint8_t> pb; zkp.write(pb, p256_base);
  res.proof_kb = pb.size() / 1024; res.ninputs = C.ninputs;
  ZkProof<Fp256Base> pr(C, kRate, kNreq); ReadBuffer rb(pb); pr.read(rb, p256_base);
  ZkVerifier<Fp256Base, RSFp> ver(C, rsf, kRate, kNreq, p256_base);
  Transcript tv((const uint8_t*)"sig", 3, kVer); ver.recv_commitment(pr, tv);
  bool vok = ver.verify(pr, pub, tv);
  res.ok = pok && vok;
  return res.ok;
}
}  // namespace sigc

// ===================== GF(2^128) hash circuit =====================
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

constexpr size_t kMaxSHA = 13;
constexpr size_t PRE = 64 * kMaxSHA;
constexpr size_t DECP = 64 * (kMaxSHA - 2);
constexpr size_t LOGM = 11;
constexpr size_t MAXVCT = 80;
constexpr size_t MAXB = 2;
constexpr size_t MAXDD = (64 * MAXB * 6) / 8;
constexpr size_t MAXPAT = 96;
constexpr size_t KBB = 4;
constexpr size_t DECKB = 64 * KBB;
constexpr size_t PB = 18;
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

struct Slot {
  v8 pattern[MAXPAT]; v8 patlen;
  v8 disc_pre[64 * MAXB]; v256 disc_ebits; SBW disc_sha[MAXB]; v8 disc_nb;
  LC::bitvec<8> disc_len, disc_shift; LC::bitvec<LOGM> sd_idx;
};
struct Inputs {
  v8 now[10]; v8 vct_pat[MAXVCT]; v8 vct_len; v256 e2;
  std::vector<Slot> slot; MACTag mac[7];
  v256 e, dpkx, dpky;
  v8 preimage[PRE]; SBW sha[kMaxSHA]; v8 nb;
  LC::bitvec<LOGM> payload_ind, payload_len, exp_idx, vct_idx, cnf_x_idx, cnf_y_idx;
  v8 kb_pre[DECKB]; SBW kb_sha[KBB]; v8 kb_nb;
  LC::bitvec<LOGM> kb_pl_ind, kb_pl_len, sd_hash_idx;
  v8 presented[PRES]; SBW pres_sha[PB]; v8 pres_nb; v256 pres_hash_bits;
  std::vector<LC::bitvec<LOGM>> disc_in_pres;
  MACW macw[3];
};

void declare_inputs(const LC& L, QuadCircuit<f_128>& Q, Inputs& in, size_t nattr) {
  in.slot.resize(nattr); in.disc_in_pres.resize(nattr);
  for (auto& b : in.now) b = L.template vinput<8>();
  for (auto& b : in.vct_pat) b = L.template vinput<8>();
  in.vct_len = L.template vinput<8>();
  in.e2 = L.template vinput<256>();
  for (size_t s = 0; s < nattr; ++s) {
    for (auto& b : in.slot[s].pattern) b = L.template vinput<8>();
    in.slot[s].patlen = L.template vinput<8>();
  }
  for (auto& m : in.mac) m = L.eltw_input();
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
  Q.begin_full_field();
  for (auto& w : in.macw) w.input(L);
}

void assert_logic(const LC& L, const Inputs& in) {
  size_t nattr = in.slot.size();
  v8 zero = vb(L, 0);
  Routing<LC> r(L); FlatSHA sha(L); MAC mac_check(L); Base64Decoder<LC> b64(L);

  sha.assert_message_hash(kMaxSHA, in.nb, in.preimage, in.e, in.sha);
  v8 shbuf[DECP];
  r.shift(in.payload_ind, DECP, shbuf, PRE, in.preimage, zero, 3);
  v8 dec[DECP];
  LC::bitvec<LOGM> plen(in.payload_len);
  b64.base64_rawurl_decode_len(shbuf, dec, DECP, plen);

  v8 ed[10];
  r.shift(in.exp_idx, 10, ed, DECP, dec, zero, 3);
  L.assert1(leq_bytes(L, in.now, ed, 10));

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

  mac_check.verify_mac(&in.mac[0], in.mac[6], in.e, in.macw[0]);
  mac_check.verify_mac(&in.mac[2], in.mac[6], in.dpkx, in.macw[1]);
  mac_check.verify_mac(&in.mac[4], in.mac[6], in.dpky, in.macw[2]);
}

std::unique_ptr<Circuit<f_128>> make_hash_circuit(const f_128& Fs, size_t nattr) {
  QuadCircuit<f_128> Q(Fs);
  const CB cbk(&Q);
  const LC L(&cbk, Fs);
  Inputs in;
  declare_inputs(L, Q, in, nattr);
  assert_logic(L, in);
  return Q.mkcircuit(1);
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

bool run(const Circuit<f_128>& C, const f_128& Fs, const std::string& compact,
         const char* now, const std::vector<std::string>& claims,
         const std::string& vct, const Linker& lk, Result& res) {
  size_t nattr = claims.size();
  std::string jwt = compact.substr(0, compact.find('~'));
  size_t d1 = jwt.find('.'), d2 = jwt.find('.', d1 + 1);
  std::string msg = jwt.substr(0, d2);
  std::string payload_b64 = jwt.substr(d1 + 1, d2 - d1 - 1);
  std::string payload = b64d(payload_b64);
  size_t exp_idx = payload.find("\"exp\":") + 6;
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

  auto W = Dense<f_128>(1, C.ninputs);
  auto pub = Dense<f_128>(1, C.npub_in);
  BitPluckerEncoder<f_128, 4> enc(Fs);
  auto fillpub = [&](DenseFiller<f_128>& f) {
    f.push_back(Fs.one());
    for (int i = 0; i < 10; ++i) f.push_back((uint8_t)now[i], 8, Fs);
    for (size_t i = 0; i < MAXVCT; ++i) f.push_back(i < vct_pat.size() ? (uint8_t)vct_pat[i] : 0, 8, Fs);
    f.push_back((uint8_t)vct_pat.size(), 8, Fs);
    push_rev_bits(f, kbdig, Fs);
    for (size_t s = 0; s < nattr; ++s) {
      std::string dj = b64d(chosen[s]);
      size_t salt_len = dj.find("\",\"") - 2;
      std::string pat = dj.substr(2 + salt_len);
      for (size_t i = 0; i < MAXPAT; ++i) f.push_back(i < pat.size() ? (uint8_t)pat[i] : 0, 8, Fs);
      f.push_back((uint8_t)pat.size(), 8, Fs);
    }
    for (int i = 0; i < 6; ++i) f.push_back(lk.macs[i]);
    f.push_back(lk.av);
  };
  { DenseFiller<f_128> f(W);
    fillpub(f);
    push_rev_bits(f, edig, Fs);
    push_rev_bits(f, (const uint8_t*)cx_raw.data(), Fs);
    push_rev_bits(f, (const uint8_t*)cy_raw.data(), Fs);
    for (size_t i = 0; i < PRE; ++i) f.push_back(in_pre[i], 8, Fs);
    for (size_t b = 0; b < kMaxSHA; ++b) fill_sha(f, enc, bw[b]);
    f.push_back(numb, 8, Fs);
    f.push_back(d1 + 1, LOGM, Fs); f.push_back(payload_b64.size(), LOGM, Fs);
    f.push_back(exp_idx, LOGM, Fs); f.push_back(vct_idx, LOGM, Fs);
    f.push_back(xi, LOGM, Fs); f.push_back(yi, LOGM, Fs);
    for (size_t i = 0; i < DECKB; ++i) f.push_back(kb_in[i], 8, Fs);
    for (size_t b = 0; b < KBB; ++b) fill_sha(f, enc, kb_bw[b]);
    f.push_back(kb_numb, 8, Fs);
    f.push_back(kd1 + 1, LOGM, Fs); f.push_back(kb_pl_b64.size(), LOGM, Fs); f.push_back(sdh_pos, LOGM, Fs);
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
    for (int i = 0; i < 6; ++i) f.push_back(lk.ap[i]);  // SHARED key
  }
  { DenseFiller<f_128> f(pub); fillpub(f); }

  const RSGf rsf(Fs);
  SecureRandomEngine rng;
  ZkProof<f_128> zkp(C, kRate, kNreq);
  Transcript tp((const uint8_t*)"hash", 4, kVer);
  ZkProver<f_128, RSGf> prover(C, Fs, rsf);
  auto t0 = std::chrono::steady_clock::now();
  prover.commit(zkp, W, tp, rng);
  bool pok = prover.prove(zkp, W, tp);
  res.prove_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();
  std::vector<uint8_t> pb; zkp.write(pb, Fs);
  res.proof_kb = pb.size() / 1024; res.ninputs = C.ninputs;
  ZkProof<f_128> pr(C, kRate, kNreq); ReadBuffer rb(pb); pr.read(rb, Fs);
  ZkVerifier<f_128, RSGf> ver(C, rsf, kRate, kNreq, Fs);
  Transcript tv((const uint8_t*)"hash", 4, kVer); ver.recv_commitment(pr, tv);
  bool vok = ver.verify(pr, pub, tv);
  res.ok = pok && vok;
  return res.ok;
}
}  // namespace hashc
}  // namespace proofs

int main(int argc, char** argv) {
  using namespace proofs;
  set_log_level(ERROR);
  std::string fixture = argc > 1 ? argv[1] : "playground/fixtures/sdjwt.txt";
  std::string jwk = argc > 2 ? argv[2] : "playground/fixtures/issuer-jwk.json";
  const char* now = argc > 3 ? argv[3] : "1700000000";
  std::vector<std::string> claims;
  if (argc > 4) { std::string cs = argv[4]; size_t p = 0, q;
    while ((q = cs.find(',', p)) != std::string::npos) { claims.push_back(cs.substr(p, q - p)); p = q + 1; }
    claims.push_back(cs.substr(p)); }
  else claims = {"given_name", "age_over_18", "height"};
  std::string vct = argc > 5 ? argv[5] : "https://credentials.example/pid";
  size_t nattr = claims.size();

  std::string compact = rf(fixture);
  const f_128 Fs;

  // ---- parse + build the shared MAC link over e/dpkx/dpky ----
  sigc::Parsed v;
  if (!sigc::parse(compact, jwk, v)) { printf("parse/sig material invalid\n"); return 1; }
  SecureRandomEngine rng;
  Linker lk;
  lk.init(rng, Fs, v.e_le, v.dx_le, v.dy_le);

  // ---- compile/cache both circuits ----
  std::string bindir(argv[0]);
  size_t sl = bindir.rfind('/');
  std::string cdir = (sl == std::string::npos ? std::string(".") : bindir.substr(0, sl)) + "/../circuits-cache";
  mkdir(cdir.c_str(), 0755);

  printf("M7-3: two-circuit split (Fp256 sig + GF(2^128) hash), %zu attrs — present + verify\n", nattr);
  Result rs, rh;
  auto tb0 = std::chrono::steady_clock::now();
  auto Csig = get_circuit<Fp256Base>(p256_base, P256_ID, cdir + "/sdjwt-sig.bin",
      [] { return sigc::make_sig_circuit(); }, rs.circ_kb);
  auto Chash = get_circuit<f_128>(Fs, GF2_128_ID, cdir + "/sdjwt-hash-" + std::to_string(nattr) + "attr.bin",
      [&] { return hashc::make_hash_circuit(Fs, nattr); }, rh.circ_kb);
  long build_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-tb0).count();
  printf("  circuits ready in %ld ms\n", build_ms);

  // ---- prove + verify BOTH, linked by the shared macs ----
  bool sok = sigc::run(*Csig, v, lk, rs);
  bool hok = hashc::run(*Chash, Fs, compact, now, claims, vct, lk, rh);

  size_t bundle = 6 * 16 + 16 + rs.proof_kb * 1024 + rh.proof_kb * 1024;  // macs+av+both proofs
  printf("  sig  (Fp256)   : ninputs=%zu circuit=%zu KB  prove=%ld ms  proof=%zu KB  %s\n",
         rs.ninputs, rs.circ_kb, rs.prove_ms, rs.proof_kb, rs.ok ? "ACCEPT" : "REJECT");
  printf("  hash (GF2^128) : ninputs=%zu circuit=%zu KB  prove=%ld ms  proof=%zu KB  %s\n",
         rh.ninputs, rh.circ_kb, rh.prove_ms, rh.proof_kb, rh.ok ? "ACCEPT" : "REJECT");
  printf("  TOTAL          : prove=%ld ms  bundle≈%zu KB  link=MAC(e,dpkx,dpky)+e2  -> %s\n",
         rs.prove_ms + rh.prove_ms, bundle / 1024,
         (sok && hok) ? "ACCEPT ✅ (both circuits, linked)" : "REJECT ❌");
  return (sok && hok) ? 0 : 1;
}
