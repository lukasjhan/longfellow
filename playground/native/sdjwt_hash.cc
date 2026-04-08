// M7 step 2 (start): SD-JWT hash circuit over GF(2^128). Minimal core first —
// SHA(header.payload) == e  +  MACGF2 of e — to validate the GF(2^128) SHA
// packing, the MAC, and begin_full_field(), then measure prove time vs Fp256.
// (Full SD-JWT checks — exp/vct/membership/structural/sd_hash/dpk — added next.)
// Mirrors lib/circuits/mdoc/mdoc_generate_circuit.cc hash-circuit assembly.

#include <cstdint>
#include <cstdio>
#include <chrono>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

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
#include "circuits/tests/base64/decode.h"
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
using FlatSHA = FlatSHA256Circuit<LC, BitPlucker<LC, 4>>;
using SBW = FlatSHA::BlockWitness;
using MacBP = BitPlucker<LC, kMACPluckerBits>;
using MAC = MACGF2<CB, MacBP>;
using MACW = MAC::Witness;
using MACTag = MAC::v128;  // native gf2k EltW
using RSGf = LCH14ReedSolomonFactory<f_128>;

constexpr size_t kMaxSHA = 13;
constexpr size_t PRE = 64 * kMaxSHA;
constexpr size_t DECP = 64 * (kMaxSHA - 2);  // decoded-payload buffer
constexpr size_t LOGM = 11;
constexpr size_t kRate = 7, kNreq = 132, kVer = 7;

v8 vb(const LC& L, uint8_t c) { return L.template vbit<8>(c); }

LC::BitW leq_bytes(const LC& L, const v8* a, const v8* b, size_t n) {
  LC::BitW le = L.bit(1);
  for (size_t i = n; i-- > 0;) {
    auto blt = L.lt(8, a[i].data(), b[i].data());
    auto beq = L.eq(8, a[i].data(), b[i].data());
    le = L.lor(blt, L.land(beq, le));
  }
  return le;
}

std::unique_ptr<Circuit<f_128>> make_hash_circuit(const f_128& Fs) {
  QuadCircuit<f_128> Q(Fs);
  const CB cbk(&Q);
  const LC L(&cbk, Fs);
  MAC mac_check(L);

  // public: now[10], mac_e[2], av
  v8 now[10];
  for (auto& b : now) b = L.template vinput<8>();
  MACTag mac[3];
  for (auto& m : mac) m = L.eltw_input();

  Q.private_input();
  v256 e = L.template vinput<256>();
  v8 preimage[PRE];
  for (auto& b : preimage) b = L.template vinput<8>();
  SBW sha[kMaxSHA];
  for (auto& s : sha) s.input(L);
  v8 nb = L.template vinput<8>();
  LC::bitvec<LOGM> payload_ind = L.template vinput<LOGM>();
  LC::bitvec<LOGM> payload_len = L.template vinput<LOGM>();
  LC::bitvec<LOGM> exp_idx = L.template vinput<LOGM>();

  Q.begin_full_field();
  MACW macw;
  macw.input(L);

  FlatSHA sh(L);
  sh.assert_message_hash(kMaxSHA, nb, preimage, e, sha);
  mac_check.verify_mac(&mac[0], mac[2], e, macw);

  // decode payload (base64url) out of the signed preimage, then exp check
  Routing<LC> r(L);
  v8 zero = vb(L, 0);
  v8 shbuf[DECP];
  r.shift(payload_ind, DECP, shbuf, PRE, preimage, zero, 3);
  v8 dec[DECP];
  Base64Decoder<LC> b64(L);
  LC::bitvec<LOGM> plen(payload_len);
  b64.base64_rawurl_decode_len(shbuf, dec, DECP, plen);
  v8 ed[10];
  r.shift(exp_idx, 10, ed, DECP, dec, zero, 3);
  L.assert1(leq_bytes(L, now, ed, 10));

  return Q.mkcircuit(/*nc=*/1);
}

// host helpers
int b64v(char c){if(c>='A'&&c<='Z')return c-'A';if(c>='a'&&c<='z')return c-'a'+26;if(c>='0'&&c<='9')return c-'0'+52;if(c=='-')return 62;if(c=='_')return 63;return -1;}
std::string b64d(const std::string& s){std::string o;int v=0,b=0;for(char c:s){int d=b64v(c);if(d<0)continue;v=(v<<6)|d;b+=6;if(b>=8){o+=char((v>>(b-8))&0xff);b-=8;}}return o;}
std::string rf(const std::string&p){std::ifstream f(p,std::ios::binary);std::string s((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back();return s;}

}  // namespace
}  // namespace proofs

int main(int argc, char** argv) {
  using namespace proofs;
  set_log_level(ERROR);
  const f_128 Fs;
  std::string fixture = argc > 1 ? argv[1] : "playground/fixtures/sdjwt.txt";

  // header.payload from the issuer JWT
  std::string compact = rf(fixture);
  std::string jwt = compact.substr(0, compact.find('~'));
  size_t d1 = jwt.find('.'), d2 = jwt.find('.', d1 + 1);
  std::string msg = jwt.substr(0, d2);
  std::string payload_b64 = jwt.substr(d1 + 1, d2 - d1 - 1);
  std::string payload = b64d(payload_b64);
  size_t exp_idx = payload.find("\"exp\":") + 6;
  const char* now = "1700000000";  // now < exp(fixture)
  uint8_t edig[32];
  ::SHA256((const uint8_t*)msg.data(), msg.size(), edig);
  // The circuit's v256 `e` (and the MAC) use the field-element byte order,
  // which is the little-endian (reversed) form of the big-endian SHA digest
  // (matches mdoc's to_bytes_field(nat_from_be(hash)) convention).
  uint8_t ebytes[32];
  for (size_t i = 0; i < 32; ++i) ebytes[i] = edig[31 - i];

  // SHA witness
  uint8_t in[PRE];
  FlatSHA256Witness::BlockWitness bw[kMaxSHA];
  uint8_t numb = 0;
  FlatSHA256Witness::transform_and_witness_message(msg.size(), (const uint8_t*)msg.data(), kMaxSHA, numb, in, bw);

  // MAC over e (32 bytes)
  SecureRandomEngine rng;
  gf2k ap[2];
  MACReference<f_128> mr;
  mr.sample(ap, 2, &rng);
  uint8_t avb[16]; rng.bytes(avb, 16);
  gf2k av = Fs.of_bytes_field(avb).value();
  gf2k mac_e[2];
  mr.compute(mac_e, av, ap, ebytes);

  printf("M7-2(min): compiling GF(2^128) hash core (SHA + MACGF2)...\n");
  auto C = make_hash_circuit(Fs);
  std::vector<uint8_t> cb; CircuitWriter<f_128> w(Fs, GF2_128_ID); w.to_bytes(*C, cb);
  std::vector<uint8_t> comp(ZSTD_compressBound(cb.size()));
  size_t csz = ZSTD_compress(comp.data(), comp.size(), cb.data(), cb.size(), 6);
  printf("  circuit: ninputs=%zu npub_in=%zu nl=%zu  zstd=%zu KB\n", C->ninputs, C->npub_in, C->nl, csz/1024);

  auto W = Dense<f_128>(1, C->ninputs);
  auto pub = Dense<f_128>(1, C->npub_in);
  auto fillpub = [&](DenseFiller<f_128>& f) {
    f.push_back(Fs.one());
    for (int i = 0; i < 10; ++i) f.push_back((uint8_t)now[i], 8, Fs);
    f.push_back(mac_e[0]); f.push_back(mac_e[1]); f.push_back(av);
  };
  { DenseFiller<f_128> f(W);
    fillpub(f);
    fill_bit_string(f, ebytes, 32, 32, Fs);            // e (v256)
    for (size_t i = 0; i < PRE; ++i) f.push_back(in[i], 8, Fs);
    BitPluckerEncoder<f_128, 4> enc(Fs);
    for (size_t b = 0; b < kMaxSHA; ++b) {
      for (size_t k = 0; k < 48; ++k) f.push_back(enc.mkpacked_v32(bw[b].outw[k]));
      for (size_t k = 0; k < 64; ++k) { f.push_back(enc.mkpacked_v32(bw[b].oute[k])); f.push_back(enc.mkpacked_v32(bw[b].outa[k])); }
      for (size_t k = 0; k < 8; ++k) f.push_back(enc.mkpacked_v32(bw[b].h1[k]));
    }
    f.push_back(numb, 8, Fs);
    f.push_back(d1 + 1, LOGM, Fs);                      // payload_ind
    f.push_back(payload_b64.size(), LOGM, Fs);          // payload_len
    f.push_back(exp_idx, LOGM, Fs);                     // exp_idx
    f.push_back(ap[0]); f.push_back(ap[1]);            // MACGF2 witness
  }
  { DenseFiller<f_128> f(pub); fillpub(f); }

  const RSGf rsf(Fs);
  ZkProof<f_128> zkp(*C, kRate, kNreq);
  Transcript tp((const uint8_t*)"hash", 4, kVer);
  ZkProver<f_128, RSGf> prover(*C, Fs, rsf);
  auto t0 = std::chrono::steady_clock::now();
  prover.commit(zkp, W, tp, rng);
  bool pok = prover.prove(zkp, W, tp);
  long pm = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();
  std::vector<uint8_t> pb; zkp.write(pb, Fs);
  ZkProof<f_128> pr(*C, kRate, kNreq); ReadBuffer rb(pb); pr.read(rb, Fs);
  ZkVerifier<f_128, RSGf> ver(*C, rsf, kRate, kNreq, Fs);
  Transcript tv((const uint8_t*)"hash", 4, kVer); ver.recv_commitment(pr, tv);
  bool vok = ver.verify(pr, pub, tv);
  printf("  prove=%ld ms  proof=%zu KB  result: %s\n", pm, pb.size()/1024, (pok&&vok)?"ACCEPT ✅":"REJECT ❌");
  return (pok&&vok)?0:1;
}
