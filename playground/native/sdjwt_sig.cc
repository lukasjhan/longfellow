// M7 step 1: SD-JWT signature circuit over Fp256, REUSING mdoc's MdocSignature
// (ECDSA issuer-sig over e + ECDSA KB-sig over e2 + MAC of e/dpkx/dpky).
// Standalone prove from the fixture to measure the sig-circuit size/time.
// (The MAC links to the GF(2^128) hash circuit in later steps; here av/macs are
// chosen locally just to exercise + measure the circuit.)

#include <cstdint>
#include <cstdio>
#include <chrono>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <openssl/sha.h>
#include <zstd.h>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mac/mac_witness.h"
#include "circuits/mdoc/mdoc_signature.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
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

using CB = CompilerBackend<Fp256Base>;
using LC = Logic<Fp256Base, CB>;
using EltW = LC::EltW;
using v128 = LC::v128;
using Nat = Fp256Base::N;
using f_128 = GF2_128<>;
using gf2k = f_128::Elt;
using MS = MdocSignature<LC, Fp256Base, P256>;
using EcdsaHostW = VerifyWitness3<P256, Fp256Scalar>;

using f2_p256 = Fp2<Fp256Base>;
using Elt2 = f2_p256::Elt;
using FftExt = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
using RSFp = ReedSolomonFactory<Fp256Base, FftExt>;
constexpr char kRootX[] = "112649224146410281873500457609690258373018840430489408729223714171582664680802";
constexpr char kRootY[] = "84087994358540907695740461427818660560182168997182378749313018254450460212908";
constexpr size_t kRate = 7, kNreq = 132, kVer = 7;

// ---- host helpers ----
int b64v(char c){if(c>='A'&&c<='Z')return c-'A';if(c>='a'&&c<='z')return c-'a'+26;if(c>='0'&&c<='9')return c-'0'+52;if(c=='-')return 62;if(c=='_')return 63;return -1;}
std::string b64d(const std::string& s){std::string o;int v=0,b=0;for(char c:s){int d=b64v(c);if(d<0)continue;v=(v<<6)|d;b+=6;if(b>=8){o+=char((v>>(b-8))&0xff);b-=8;}}return o;}
std::string rf(const std::string&p){std::ifstream f(p,std::ios::binary);std::string s((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back();return s;}
Nat nat_be(const uint8_t* be){uint8_t t[Nat::kBytes];for(size_t i=0;i<Nat::kBytes;++i)t[i]=be[Nat::kBytes-1-i];return Nat::of_bytes(t);}

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

// fill 128 bits of a gf2k element as 0/1 field elements
void push_gf_bits(DenseFiller<Fp256Base>& f, const gf2k& g) {
  for (size_t j = 0; j < 128; ++j) f.push_back(g[j] ? p256_base.one() : p256_base.zero());
}

struct Vals { Fp256Base::Elt pkX, pkY, e_, e2, dpkx, dpky; Nat e_nat, e2_nat, ir, is, kr, ks, nx, ny; };

}  // namespace
}  // namespace proofs

int main(int argc, char** argv) {
  using namespace proofs;
  set_log_level(ERROR);
  std::string fixture = argc > 1 ? argv[1] : "playground/fixtures/sdjwt.txt";
  std::string jwk = argc > 2 ? argv[2] : "playground/fixtures/issuer-jwk.json";

  // ---- parse fixture for e, e2, dpk, sigs ----
  std::string compact = rf(fixture);
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

  Vals v;
  v.pkX = p256_base.of_untrusted_string(hx("x_hex").c_str()).value();
  v.pkY = p256_base.of_untrusted_string(hx("y_hex").c_str()).value();
  v.e_nat = nat_be(h); v.e2_nat = nat_be(h2);
  v.e_ = p256_base.to_montgomery(v.e_nat); v.e2 = p256_base.to_montgomery(v.e2_nat);
  v.ir = nat_be((const uint8_t*)isig.data()); v.is = nat_be((const uint8_t*)isig.data()+32);
  v.kr = nat_be((const uint8_t*)ksig.data()); v.ks = nat_be((const uint8_t*)ksig.data()+32);
  v.nx = nat_be((const uint8_t*)cx.data()); v.ny = nat_be((const uint8_t*)cy.data());
  v.dpkx = p256_base.to_montgomery(v.nx); v.dpky = p256_base.to_montgomery(v.ny);

  // ---- MAC: sample a_p, pick av, compute macs over e/dpkx/dpky ----
  f_128 gf;
  SecureRandomEngine rng;
  gf2k ap[6]; MACReference<f_128> mr; mr.sample(ap, 6, &rng);
  uint8_t avb[16]; rng.bytes(avb, 16); gf2k av = gf.of_bytes_field(avb).value();
  gf2k macs[6];
  uint8_t buf[32];
  Fp256Base::Elt vals[3] = {v.e_, v.dpkx, v.dpky};
  for (int i = 0; i < 3; ++i) { p256_base.to_bytes_field(buf, vals[i]); mr.compute(&macs[2*i], av, &ap[2*i], buf); }

  printf("M7-step1: compiling SD-JWT signature circuit (reuse MdocSignature)...\n");
  auto C = make_sig_circuit();
  std::vector<uint8_t> cb; CircuitWriter<Fp256Base> w(p256_base, P256_ID); w.to_bytes(*C, cb);
  std::vector<uint8_t> comp(ZSTD_compressBound(cb.size()));
  size_t csz = ZSTD_compress(comp.data(), comp.size(), cb.data(), cb.size(), 6);
  printf("  circuit: ninputs=%zu npub_in=%zu nl=%zu  zstd=%zu KB\n", C->ninputs, C->npub_in, C->nl, csz/1024);

  auto W = Dense<Fp256Base>(1, C->ninputs);
  auto pub = Dense<Fp256Base>(1, C->npub_in);
  // fill W (public + private base) then append mac witnesses
  {
    DenseFiller<Fp256Base> f(W);
    f.push_back(p256_base.one());
    f.push_back(v.pkX); f.push_back(v.pkY); f.push_back(v.e2);
    for (int i = 0; i < 6; ++i) push_gf_bits(f, macs[i]);
    push_gf_bits(f, av);
    f.push_back(v.e_); f.push_back(v.dpkx); f.push_back(v.dpky);
    EcdsaHostW isigw(p256_scalar, p256), ksigw(p256_scalar, p256);
    if (!isigw.compute_witness(v.pkX, v.pkY, v.e_nat, v.ir, v.is)) { printf("  issuer sig invalid\n"); return 1; }
    if (!ksigw.compute_witness(v.dpkx, v.dpky, v.e2_nat, v.kr, v.ks)) { printf("  kb sig invalid\n"); return 1; }
    isigw.fill_witness(f);
    ksigw.fill_witness(f);
    for (int i = 0; i < 3; ++i) {
      p256_base.to_bytes_field(buf, vals[i]);
      MacWitness<Fp256Base> mw(p256_base, gf);
      mw.compute_witness(&ap[2*i], buf);
      mw.fill_witness(f);
    }
  }
  { DenseFiller<Fp256Base> f(pub);
    f.push_back(p256_base.one()); f.push_back(v.pkX); f.push_back(v.pkY); f.push_back(v.e2);
    for (int i = 0; i < 6; ++i) push_gf_bits(f, macs[i]); push_gf_bits(f, av);
  }

  const f2_p256 p256_2(p256_base);
  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExt fft(p256_base, p256_2, omega, 1ull << 31);
  const RSFp rsf(fft, p256_base);
  ZkProof<Fp256Base> zkp(*C, kRate, kNreq);
  Transcript tp((const uint8_t*)"sig", 3, kVer);
  ZkProver<Fp256Base, RSFp> prover(*C, p256_base, rsf);
  auto t0 = std::chrono::steady_clock::now();
  prover.commit(zkp, W, tp, rng);
  bool pok = prover.prove(zkp, W, tp);
  long pm = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();
  std::vector<uint8_t> pb; zkp.write(pb, p256_base);
  ZkProof<Fp256Base> pr(*C, kRate, kNreq); ReadBuffer rb(pb); pr.read(rb, p256_base);
  ZkVerifier<Fp256Base, RSFp> ver(*C, rsf, kRate, kNreq, p256_base);
  Transcript tv((const uint8_t*)"sig", 3, kVer); ver.recv_commitment(pr, tv);
  bool vok = ver.verify(pr, pub, tv);
  printf("  prove=%ld ms  proof=%zu KB  result: %s\n", pm, pb.size()/1024, (pok&&vok)?"ACCEPT ✅":"REJECT ❌");
  return (pok&&vok)?0:1;
}
