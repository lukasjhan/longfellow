// M7 step 2 (full): SD-JWT-VC hash circuit over GF(2^128) — the FULL Approach-C
// logic ported from the monolithic Fp256 circuit (sdjwt_full.cc):
//   SHA(header.payload)==e  +  exp  +  vct  +  cnf/dpk binding
//   +  sd_hash binding (KB SHA + presented SHA + sd_hash==SHA(presented))
//   +  N × (_sd membership + structural pattern + consent⊆presented)
// ECDSA is NOT here (it lives in the Fp256 sig circuit); instead e/dpkx/dpky are
// MAC-linked (MACGF2) to that circuit. e2 (KB hash) is a public input that the
// verifier feeds to both circuits. This is the GF(2^128) half of the 2-circuit
// split; mirrors lib/circuits/mdoc/mdoc_generate_circuit.cc's hash circuit.

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

#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/routing.h"
#include "circuits/mac/mac_circuit.h"
#include "circuits/mac/mac_reference.h"
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
namespace {

using f_128 = GF2_128<>;
using gf2k = f_128::Elt;
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
using MACTag = MAC::v128;  // native gf2k EltW
using RSGf = LCH14ReedSolomonFactory<f_128>;

constexpr size_t kMaxSHA = 13;          // SHA blocks for header.payload
constexpr size_t PRE = 64 * kMaxSHA;
constexpr size_t DECP = 64 * (kMaxSHA - 2);  // decoded-payload buffer
constexpr size_t LOGM = 11;
constexpr size_t MAXVCT = 80;           // max `"vct":"<type>"` pattern
constexpr size_t MAXB = 2;              // SHA blocks per disclosure
constexpr size_t MAXDD = (64 * MAXB * 6) / 8;
constexpr size_t MAXPAT = 96;          // max disclosure suffix pattern
constexpr size_t KBB = 4;              // SHA blocks for KB header.payload (~212B)
constexpr size_t DECKB = 64 * KBB;     // KB payload decode buffer
constexpr size_t PB = 18;              // SHA blocks for the presented SD-JWT
constexpr size_t PRES = 64 * PB;       // presented bytes
constexpr size_t kRate = 7, kNreq = 132, kVer = 7;

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

// Assert v256 `bits` (sha-bench order: digest big-endian byte j at 8*(31-j)+c)
// equals the 32 raw bytes `out[0..31]` (big-endian).
void assert_bits_eq_bytes(const LC& L, const v256& bits, const v8* out) {
  for (size_t j = 0; j < 32; ++j) {
    v8 tb;
    for (size_t c = 0; c < 8; ++c) tb[c] = bits[8 * (31 - j) + c];
    L.assert1(L.eq(8, out[j].data(), tb.data()));
  }
}

// =================== per-disclosure inputs ===================
struct Slot {
  v8 pattern[MAXPAT];                // public: requested `","<claim>",<value>]`
  v8 patlen;
  v8 disc_pre[64 * MAXB];            // private
  v256 disc_ebits;
  SBW disc_sha[MAXB];
  v8 disc_nb;
  LC::bitvec<8> disc_len, disc_shift;
  LC::bitvec<LOGM> sd_idx;
};

struct Inputs {
  // ---- public ----
  v8 now[10];
  v8 vct_pat[MAXVCT];
  v8 vct_len;
  v256 e2;                           // KB header.payload hash (verifier-supplied)
  std::vector<Slot> slot;            // pattern/patlen are public; rest private
  MACTag mac[7];                     // mac_e[2], mac_dpkx[2], mac_dpky[2], av
  // ---- private: front-end ----
  v256 e, dpkx, dpky;                // MAC-linked to the sig circuit
  v8 preimage[PRE];
  SBW sha[kMaxSHA];
  v8 nb;
  LC::bitvec<LOGM> payload_ind, payload_len, exp_idx, vct_idx, cnf_x_idx, cnf_y_idx;
  // ---- private: sd_hash binding ----
  v8 kb_pre[DECKB];
  SBW kb_sha[KBB];
  v8 kb_nb;
  LC::bitvec<LOGM> kb_pl_ind, kb_pl_len, sd_hash_idx;
  v8 presented[PRES];
  SBW pres_sha[PB];
  v8 pres_nb;
  v256 pres_hash_bits;
  std::vector<LC::bitvec<LOGM>> disc_in_pres;
  // ---- after begin_full_field ----
  MACW macw[3];
};

void declare_inputs(const LC& L, QuadCircuit<f_128>& Q, Inputs& in, size_t nattr) {
  in.slot.resize(nattr);
  in.disc_in_pres.resize(nattr);
  // public
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
  in.e = L.template vinput<256>();
  in.dpkx = L.template vinput<256>();
  in.dpky = L.template vinput<256>();
  for (auto& b : in.preimage) b = L.template vinput<8>();
  for (auto& s : in.sha) s.input(L);
  in.nb = L.template vinput<8>();
  in.payload_ind = L.template vinput<LOGM>();
  in.payload_len = L.template vinput<LOGM>();
  in.exp_idx = L.template vinput<LOGM>();
  in.vct_idx = L.template vinput<LOGM>();
  in.cnf_x_idx = L.template vinput<LOGM>();
  in.cnf_y_idx = L.template vinput<LOGM>();
  // sd_hash binding
  for (auto& b : in.kb_pre) b = L.template vinput<8>();
  for (auto& s : in.kb_sha) s.input(L);
  in.kb_nb = L.template vinput<8>();
  in.kb_pl_ind = L.template vinput<LOGM>();
  in.kb_pl_len = L.template vinput<LOGM>();
  in.sd_hash_idx = L.template vinput<LOGM>();
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
    sl.disc_len = L.template vinput<8>();
    sl.disc_shift = L.template vinput<8>();
    sl.sd_idx = L.template vinput<LOGM>();
  }

  Q.begin_full_field();
  for (auto& w : in.macw) w.input(L);
}

void assert_logic(const LC& L, const Inputs& in) {
  size_t nattr = in.slot.size();
  v8 zero = vb(L, 0);
  Routing<LC> r(L);
  FlatSHA sha(L);
  MAC mac_check(L);
  Base64Decoder<LC> b64(L);

  // front-end: SHA(header.payload) == e, then base64-decode the payload
  sha.assert_message_hash(kMaxSHA, in.nb, in.preimage, in.e, in.sha);
  v8 shbuf[DECP];
  r.shift(in.payload_ind, DECP, shbuf, PRE, in.preimage, zero, 3);
  v8 dec[DECP];
  LC::bitvec<LOGM> plen(in.payload_len);
  b64.base64_rawurl_decode_len(shbuf, dec, DECP, plen);

  // exp
  v8 ed[10];
  r.shift(in.exp_idx, 10, ed, DECP, dec, zero, 3);
  L.assert1(leq_bytes(L, in.now, ed, 10));

  // vct
  v8 vs[MAXVCT];
  r.shift(in.vct_idx, MAXVCT, vs, DECP, dec, zero, 3);
  for (size_t j = 0; j < MAXVCT; ++j)
    L.assert_implies(L.vlt(j, in.vct_len), L.eq(8, vs[j].data(), in.vct_pat[j].data()));

  // dpk == cnf.{x,y} in the signed payload
  auto check_coord = [&](const LC::bitvec<LOGM>& idx, const v256& bits) {
    v8 cc[43];
    r.shift(idx, 43, cc, DECP, dec, zero, 3);
    v8 out[33];
    b64.base64_rawurl_decode(cc, out, 43);
    assert_bits_eq_bytes(L, bits, out);
  };
  check_coord(in.cnf_x_idx, in.dpkx);
  check_coord(in.cnf_y_idx, in.dpky);

  // sd_hash binding (Method A):
  // 1) KB header.payload hashes to e2 (the value the holder signed).
  sha.assert_message_hash(KBB, in.kb_nb, in.kb_pre, in.e2, in.kb_sha);
  // 2) decode KB payload, pull out sd_hash (43 base64url chars -> 32 bytes).
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

  // per-disclosure: membership + structural + consent
  for (size_t s = 0; s < nattr; ++s) {
    const Slot& sl = in.slot[s];

    // SHA(disclosure) == disc_ebits
    sha.assert_message_hash(MAXB, sl.disc_nb, sl.disc_pre, sl.disc_ebits, sl.disc_sha);

    // membership: base64decode(_sd entry @ sd_idx) == disc_ebits
    v8 entry[43];
    r.shift(sl.sd_idx, 43, entry, DECP, dec, zero, 3);
    v8 out[33];
    b64.base64_rawurl_decode(entry, out, 43);
    assert_bits_eq_bytes(L, sl.disc_ebits, out);

    // structural: decode disclosure, prefix `["` + suffix == public pattern
    v8 dd[MAXDD];
    LC::bitvec<8> dlen(sl.disc_len);
    b64.base64_rawurl_decode_len(sl.disc_pre, dd, 64 * MAXB, dlen);
    L.assert1(L.eq(8, dd[0].data(), vb(L, '[').data()));
    L.assert1(L.eq(8, dd[1].data(), vb(L, '"').data()));
    v8 S[MAXPAT];
    r.shift(sl.disc_shift, MAXPAT, S, MAXDD, dd, zero, 3);
    for (size_t j = 0; j < MAXPAT; ++j)
      L.assert_implies(L.vlt(j, sl.patlen), L.eq(8, S[j].data(), sl.pattern[j].data()));

    // consent: this disclosure appears in `presented` (whose hash == sd_hash)
    v8 ps[64 * MAXB];
    r.shift(in.disc_in_pres[s], 64 * MAXB, ps, PRES, in.presented, zero, 3);
    for (size_t j = 0; j < 64 * MAXB; ++j)
      L.assert_implies(L.vlt(j, sl.disc_len), L.eq(8, ps[j].data(), sl.disc_pre[j].data()));
  }

  // MACs linking e, dpkx, dpky to the signature circuit
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
  return Q.mkcircuit(/*nc=*/1);
}

// =================== host helpers ===================
int b64v(char c){if(c>='A'&&c<='Z')return c-'A';if(c>='a'&&c<='z')return c-'a'+26;if(c>='0'&&c<='9')return c-'0'+52;if(c=='-')return 62;if(c=='_')return 63;return -1;}
std::string b64d(const std::string& s){std::string o;int v=0,b=0;for(char c:s){int d=b64v(c);if(d<0)continue;v=(v<<6)|d;b+=6;if(b>=8){o+=char((v>>(b-8))&0xff);b-=8;}}return o;}
std::string b64e(const uint8_t* d, size_t n){static const char* T="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";std::string o;int v=0,b=0;for(size_t i=0;i<n;++i){v=(v<<8)|d[i];b+=8;while(b>=6){o+=T[(v>>(b-6))&63];b-=6;}}if(b>0)o+=T[(v<<(6-b))&63];return o;}
std::string rf(const std::string&p){std::ifstream f(p,std::ios::binary);std::string s((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back();return s;}

// push a 256-bit value (big-endian 32-byte `be`) in sha-bench bit order: the
// reversed (little-endian) bytes, LSB-first within byte. Works for both the SHA
// digest assertion and the MAC (to_bytes_field little-endian) convention.
void push_rev_bits(DenseFiller<f_128>& f, const uint8_t* be, const f_128& Fs) {
  uint8_t r[32];
  for (size_t i = 0; i < 32; ++i) r[i] = be[31 - i];
  fill_bit_string(f, r, 32, 32, Fs);
}

void fill_sha(DenseFiller<f_128>& f, BitPluckerEncoder<f_128, 4>& enc,
              const FlatSHA256Witness::BlockWitness& b) {
  for (size_t k = 0; k < 48; ++k) f.push_back(enc.mkpacked_v32(b.outw[k]));
  for (size_t k = 0; k < 64; ++k) {
    f.push_back(enc.mkpacked_v32(b.oute[k]));
    f.push_back(enc.mkpacked_v32(b.outa[k]));
  }
  for (size_t k = 0; k < 8; ++k) f.push_back(enc.mkpacked_v32(b.h1[k]));
}

struct Concrete {
  std::string compact;
  const char* now;
  std::vector<std::string> claims;
  std::string vct;
  // MAC material (filled once, shared by W)
  gf2k ap[6], av, macs[6];
};

}  // namespace
}  // namespace proofs

int main(int argc, char** argv) {
  using namespace proofs;
  set_log_level(ERROR);
  const f_128 Fs;
  std::string fixture = argc > 1 ? argv[1] : "playground/fixtures/sdjwt.txt";

  Concrete c;
  c.compact = rf(fixture);
  c.now = argc > 2 ? argv[2] : "1700000000";
  if (argc > 3) {
    std::string cs = argv[3]; size_t p = 0, q;
    while ((q = cs.find(',', p)) != std::string::npos) { c.claims.push_back(cs.substr(p, q - p)); p = q + 1; }
    c.claims.push_back(cs.substr(p));
  } else {
    c.claims = {"given_name", "age_over_18", "height"};
  }
  c.vct = argc > 4 ? argv[4] : "https://credentials.example/pid";
  size_t nattr = c.claims.size();

  // ---- gather host data ----
  std::string jwt = c.compact.substr(0, c.compact.find('~'));
  size_t d1 = jwt.find('.'), d2 = jwt.find('.', d1 + 1);
  std::string msg = jwt.substr(0, d2);
  std::string payload_b64 = jwt.substr(d1 + 1, d2 - d1 - 1);
  std::string payload = b64d(payload_b64);
  size_t exp_idx = payload.find("\"exp\":") + 6;
  std::string vct_pat = "\"vct\":\"" + c.vct + "\"";
  size_t vct_idx = payload.find(vct_pat);

  // issuer hash e (reversed digest -> field-element/MAC byte order)
  uint8_t edig[32]; ::SHA256((const uint8_t*)msg.data(), msg.size(), edig);

  // SHA witness for header.payload
  uint8_t in_pre[PRE];
  FlatSHA256Witness::BlockWitness bw[kMaxSHA];
  uint8_t numb = 0;
  FlatSHA256Witness::transform_and_witness_message(msg.size(), (const uint8_t*)msg.data(), kMaxSHA, numb, in_pre, bw);

  // cnf.x / cnf.y (device key) -> dpkx/dpky (raw big-endian coord bytes)
  size_t cnf = payload.find("\"cnf\"");
  size_t xi = payload.find("\"x\":\"", cnf) + 5;
  size_t yi = payload.find("\"y\":\"", cnf) + 5;
  std::string cx_raw = b64d(payload.substr(xi, 43));
  std::string cy_raw = b64d(payload.substr(yi, 43));

  // ---- Key Binding host data (KB header.payload + sd_hash + presented) ----
  std::string kbjwt = c.compact.substr(c.compact.rfind('~') + 1);
  size_t kd1 = kbjwt.find('.'), kd2 = kbjwt.find('.', kd1 + 1);
  std::string kbhp = kbjwt.substr(0, kd2);  // KB header.payload
  uint8_t kbdig[32]; ::SHA256((const uint8_t*)kbhp.data(), kbhp.size(), kbdig);
  uint8_t kb_in[DECKB]; FlatSHA256Witness::BlockWitness kb_bw[KBB]; uint8_t kb_numb = 0;
  FlatSHA256Witness::transform_and_witness_message(kbhp.size(), (const uint8_t*)kbhp.data(), KBB, kb_numb, kb_in, kb_bw);
  std::string kb_pl_b64 = kbjwt.substr(kd1 + 1, kd2 - kd1 - 1);
  std::string kb_pl = b64d(kb_pl_b64);
  size_t sdh_pos = kb_pl.find("\"sd_hash\":\"") + 11;

  std::string presented = c.compact.substr(0, c.compact.rfind('~') + 1);
  uint8_t pres_in[PRES]; FlatSHA256Witness::BlockWitness pres_bw[PB]; uint8_t pres_numb = 0;
  FlatSHA256Witness::transform_and_witness_message(presented.size(), (const uint8_t*)presented.data(), PB, pres_numb, pres_in, pres_bw);
  uint8_t predig[32]; ::SHA256((const uint8_t*)presented.data(), presented.size(), predig);

  // ---- pick the disclosure for each requested claim ----
  std::vector<std::string> discs;
  { size_t p = c.compact.find('~') + 1, q;
    while ((q = c.compact.find('~', p)) != std::string::npos) { if (q > p) discs.push_back(c.compact.substr(p, q - p)); p = q + 1; } }
  std::vector<std::string> chosen(nattr);
  for (size_t s = 0; s < nattr; ++s) {
    std::string key = "\"" + c.claims[s] + "\"";
    for (auto& d : discs) if (b64d(d).find(key) != std::string::npos) chosen[s] = d;
    if (chosen[s].empty()) { printf("claim %s not found\n", c.claims[s].c_str()); return 1; }
  }

  // ---- MAC: sample a_p, pick av, compute macs over e/dpkx/dpky ----
  SecureRandomEngine rng;
  MACReference<f_128> mr;
  mr.sample(c.ap, 6, &rng);
  uint8_t avb[16]; rng.bytes(avb, 16); c.av = Fs.of_bytes_field(avb).value();
  uint8_t ebytes[32], dxb[32], dyb[32];
  for (size_t i = 0; i < 32; ++i) { ebytes[i] = edig[31 - i]; dxb[i] = (uint8_t)cx_raw[31 - i]; dyb[i] = (uint8_t)cy_raw[31 - i]; }
  mr.compute(&c.macs[0], c.av, &c.ap[0], ebytes);
  mr.compute(&c.macs[2], c.av, &c.ap[2], dxb);
  mr.compute(&c.macs[4], c.av, &c.ap[4], dyb);

  // ---- circuit (cached by nattr) ----
  std::string bindir(argv[0]);
  size_t sl = bindir.rfind('/');
  std::string cacheDir = (sl == std::string::npos ? std::string(".") : bindir.substr(0, sl)) + "/../circuits-cache";
  mkdir(cacheDir.c_str(), 0755);
  std::string cacheFile = cacheDir + "/sdjwt-hash-" + std::to_string(nattr) + "attr.bin";

  std::unique_ptr<Circuit<f_128>> C;
  std::ifstream cf(cacheFile, std::ios::binary);
  auto tc0 = std::chrono::steady_clock::now();
  if (cf.good()) {
    std::vector<uint8_t> comp((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
    cf.close();
    uint64_t osz = 0; memcpy(&osz, comp.data(), 8);
    std::vector<uint8_t> bytes(osz);
    ZSTD_decompress(bytes.data(), osz, comp.data() + 8, comp.size() - 8);
    ReadBuffer rb(bytes);
    CircuitReader<f_128> rdr(Fs, GF2_128_ID);
    C = rdr.from_bytes(rb, /*enforce_circuit_id=*/false);
    printf("M7-2: loaded cached %zu-attr GF(2^128) hash circuit (%zu KB)\n", nattr, comp.size() / 1024);
  } else {
    printf("M7-2: compiling %zu-attr GF(2^128) hash circuit (SHA+MAC+exp+vct+cnf+sd_hash+N×membership/struct/consent)...\n", nattr);
    C = make_hash_circuit(Fs, nattr);
    std::vector<uint8_t> bytes; CircuitWriter<f_128> wr(Fs, GF2_128_ID); wr.to_bytes(*C, bytes);
    size_t bound = ZSTD_compressBound(bytes.size());
    std::vector<uint8_t> comp(8 + bound);
    uint64_t osz = bytes.size(); memcpy(comp.data(), &osz, 8);
    size_t csz = ZSTD_compress(comp.data() + 8, bound, bytes.data(), bytes.size(), 6);
    std::ofstream of(cacheFile, std::ios::binary); of.write((const char*)comp.data(), 8 + csz);
    printf("M7-2: compiled + cached %zu-attr circuit (%zu KB from %zu KB)\n", nattr, (8 + csz) / 1024, bytes.size() / 1024);
  }
  auto tc1 = std::chrono::steady_clock::now();
  printf("  circuit ready in %ld ms: ninputs=%zu npub_in=%zu nl=%zu  disclosing:",
         (long)std::chrono::duration_cast<std::chrono::milliseconds>(tc1 - tc0).count(),
         C->ninputs, C->npub_in, C->nl);
  for (auto& cl : c.claims) printf(" %s", cl.c_str());
  printf("\n");

  // ---- fill ----
  auto W = Dense<f_128>(1, C->ninputs);
  auto pub = Dense<f_128>(1, C->npub_in);
  BitPluckerEncoder<f_128, 4> enc(Fs);

  auto fillpub = [&](DenseFiller<f_128>& f) {
    f.push_back(Fs.one());
    for (int i = 0; i < 10; ++i) f.push_back((uint8_t)c.now[i], 8, Fs);
    for (size_t i = 0; i < MAXVCT; ++i) f.push_back(i < vct_pat.size() ? (uint8_t)vct_pat[i] : 0, 8, Fs);
    f.push_back((uint8_t)vct_pat.size(), 8, Fs);
    push_rev_bits(f, kbdig, Fs);  // e2 = SHA(KB header.payload)
    for (size_t s = 0; s < nattr; ++s) {
      std::string dj = b64d(chosen[s]);
      size_t salt_len = dj.find("\",\"") - 2;
      std::string pat = dj.substr(2 + salt_len);  // `","claim",value]`
      for (size_t i = 0; i < MAXPAT; ++i) f.push_back(i < pat.size() ? (uint8_t)pat[i] : 0, 8, Fs);
      f.push_back((uint8_t)pat.size(), 8, Fs);
    }
    for (int i = 0; i < 6; ++i) f.push_back(c.macs[i]);
    f.push_back(c.av);
  };

  { DenseFiller<f_128> f(W);
    fillpub(f);
    // front-end private
    push_rev_bits(f, edig, Fs);       // e
    push_rev_bits(f, (const uint8_t*)cx_raw.data(), Fs);  // dpkx
    push_rev_bits(f, (const uint8_t*)cy_raw.data(), Fs);  // dpky
    for (size_t i = 0; i < PRE; ++i) f.push_back(in_pre[i], 8, Fs);
    for (size_t b = 0; b < kMaxSHA; ++b) fill_sha(f, enc, bw[b]);
    f.push_back(numb, 8, Fs);
    f.push_back(d1 + 1, LOGM, Fs);
    f.push_back(payload_b64.size(), LOGM, Fs);
    f.push_back(exp_idx, LOGM, Fs);
    f.push_back(vct_idx, LOGM, Fs);
    f.push_back(xi, LOGM, Fs);
    f.push_back(yi, LOGM, Fs);
    // sd_hash binding private
    for (size_t i = 0; i < DECKB; ++i) f.push_back(kb_in[i], 8, Fs);
    for (size_t b = 0; b < KBB; ++b) fill_sha(f, enc, kb_bw[b]);
    f.push_back(kb_numb, 8, Fs);
    f.push_back(kd1 + 1, LOGM, Fs);
    f.push_back(kb_pl_b64.size(), LOGM, Fs);
    f.push_back(sdh_pos, LOGM, Fs);
    for (size_t i = 0; i < PRES; ++i) f.push_back(pres_in[i], 8, Fs);
    for (size_t b = 0; b < PB; ++b) fill_sha(f, enc, pres_bw[b]);
    f.push_back(pres_numb, 8, Fs);
    push_rev_bits(f, predig, Fs);     // pres_hash_bits
    for (size_t s = 0; s < nattr; ++s) f.push_back(presented.find(chosen[s]), LOGM, Fs);
    // per-slot private
    for (size_t s = 0; s < nattr; ++s) {
      const std::string& disc = chosen[s];
      uint8_t dg[32]; ::SHA256((const uint8_t*)disc.data(), disc.size(), dg);
      std::string entry = b64e(dg, 32);
      size_t sd_idx = payload.find(entry);
      if (sd_idx == std::string::npos) { printf("digest not in _sd\n"); return 1; }
      std::string dj = b64d(disc);
      size_t salt_len = dj.find("\",\"") - 2;
      uint8_t din[64 * MAXB]; FlatSHA256Witness::BlockWitness dbw[MAXB]; uint8_t dnumb = 0;
      FlatSHA256Witness::transform_and_witness_message(disc.size(), (const uint8_t*)disc.data(), MAXB, dnumb, din, dbw);
      for (size_t i = 0; i < 64 * MAXB; ++i) f.push_back(din[i], 8, Fs);
      push_rev_bits(f, dg, Fs);       // disc_ebits
      for (size_t b = 0; b < MAXB; ++b) fill_sha(f, enc, dbw[b]);
      f.push_back(dnumb, 8, Fs);
      f.push_back((uint8_t)disc.size(), 8, Fs);
      f.push_back((uint8_t)(2 + salt_len), 8, Fs);
      f.push_back(sd_idx, LOGM, Fs);
    }
    // MAC witnesses (full field) — must come last
    for (int i = 0; i < 6; ++i) f.push_back(c.ap[i]);
  }
  { DenseFiller<f_128> f(pub); fillpub(f); }

  // ---- prove / verify ----
  const RSGf rsf(Fs);
  ZkProof<f_128> zkp(*C, kRate, kNreq);
  Transcript tp((const uint8_t*)"hash", 4, kVer);
  ZkProver<f_128, RSGf> prover(*C, Fs, rsf);
  auto t0 = std::chrono::steady_clock::now();
  prover.commit(zkp, W, tp, rng);
  bool pok = prover.prove(zkp, W, tp);
  long pm = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
  std::vector<uint8_t> pb; zkp.write(pb, Fs);
  ZkProof<f_128> pr(*C, kRate, kNreq); ReadBuffer rb(pb); pr.read(rb, Fs);
  ZkVerifier<f_128, RSGf> ver(*C, rsf, kRate, kNreq, Fs);
  Transcript tv((const uint8_t*)"hash", 4, kVer); ver.recv_commitment(pr, tv);
  bool vok = ver.verify(pr, pub, tv);
  printf("  prove=%ld ms  proof=%zu KB  result: %s (%zu attrs, full hash circuit)\n",
         pm, pb.size() / 1024, (pok && vok) ? "ACCEPT ✅" : "REJECT ❌", nattr);
  return (pok && vok) ? 0 : 1;
}
