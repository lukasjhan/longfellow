// jwt_cli — CLI harness around longfellow's experimental SD-JWT(+KB) ZK circuit
// (lib/circuits/tests/jwt). longfellow ships NO public C API for JWT, so this
// builds the circuit in-process (via the compiler) exactly like jwt_test.cc and
// drives ZkProver/ZkVerifier (mirroring zk/zk_testing.h::run2_test_zk).
//
// IMPORTANT: this circuit proves a STRING attribute is present in the token's
// payload as the substring  "id":"value"  (substring match, not JSON parsing).
// Boolean/number claims (e.g. age_over_18:true) are NOT provable this way.
//
// Commands:
//   export-example --index N --outdir DIR
//       Dump a bundled, already-ES256-signed example SD-JWT(+KB) token + its
//       issuer public key (pkx,pky) + key-binding hash (e2) to files.
//
//   prove  --jwt FILE --pkx HEX --pky HEX --e2 HEX
//          --attr-id ID --attr-value VAL --sha-blocks N --out FILE
//       Produce a ZK proof that the (private) token contains "ID":"VAL".
//
//   verify --pkx HEX --pky HEX --e2 HEX --attr-id ID --attr-value VAL
//          --sha-blocks N --proof FILE
//       Verify the proof. The token is NOT needed here. Exit 0 == accepted.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/jwt/jwt.h"
#include "circuits/tests/jwt/jwt_witness.h"
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

using Elt = Fp256Base::Elt;
using f2_p256 = Fp2<Fp256Base>;
using Elt2 = f2_p256::Elt;
using FftExtConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
using RSFactory_b = ReedSolomonFactory<Fp256Base, FftExtConvolutionFactory>;

// Root of unity for the Fp256^2 extension field (same as mdoc_zk.cc / jwt_test).
constexpr char kRootX[] =
    "112649224146410281873500457609690258373018840430489408729223714171582664"
    "680802";
constexpr char kRootY[] =
    "84087994358540907695740461427818660560182168997182378749313018254450460212"
    "908";

constexpr size_t kRate = 7;
constexpr size_t kNreq = 132;
constexpr size_t kVersion = 7;
constexpr const char* kSeed = "jwt-playground"; // shared prover/verifier transcript seed

// ---- bundled example SD-JWT(+KB) tokens (from circuits/tests/jwt/jwt_test) ---
struct Example {
  const char* jwt;
  const char* pkx;
  const char* pky;
  const char* e2;
  size_t recommended_sha_blocks;
  const char* note;
};
const Example kExamples[] = {
    // #0 — PID, string attr: given_name=Erika  (signed msg fits in 7 blocks)
    {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJpc3MiOiJodHRwczovL2JtaS5idW5kLmV4YW1wbGUvY3JlZGVudGlhbC9waWQvMS4wIiwi"
     "c3ViIjoidXNlcjEyMzQ1IiwiZXhwIjoxNzU0MDM5ODMwLCJpYXQiOjE3NTQwMzYyMzAsImdp"
     "dmVuX25hbWUiOiJFcmlrYSIsImFnZV9vdmVyXzE4Ijp0cnVlLCJjbmYiOnsiandrIjp7Imt0"
     "eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoicXB2czMyeXpDOGhZYXdOV181UUR5U2E4eFJf"
     "SUtCaTdSX1E1Tm5iYXVPZyIsInkiOiJCakxDb3M1eFZGMTJWSTdWSTAySUZMSGRzd1FLc0lK"
     "V0tOa1BuMFBaRFFnIn19fQ.U-"
     "2n0rGEYxGUGuQqNUPhe42rWZSJPR7ZccGRpqkzEoqnGDRmIauuA0hfLgwALkawWLSDETRR3v"
     "FzHfV6lNvb3Q~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiMitqd3QifQ."
     "eyJub25jZSI6IjEyMzEyMzEyMyIsImF1ZCI6IlJQIiwiaWF0IjoxNzU0MDM2MjMwfQ."
     "SjTqd6_LBXd0-fj9pk7P1VaimaEJh6TKKHKqxaPFEbiMPStEpZGE2BdyVghn0c-"
     "GUBnm8RV0k-jUkAk0bQAsxw",
     "0x369b8ba929cf0f06be8272268f4091cfde4ef00fe35f1a25ff04e2d4293d692b",
     "0xbdf89d633ac7a622d73bee63bd00a68bcee5b3262054f4e767f7c25157182364",
     "0x7f9982db0d6de18b4c5a83044912062d8d48cca2120b3badb2b7948427360159", 7,
     "PID; string attrs incl. given_name=Erika"},
    // #1 — PID with more string attrs (given_name, family_name, birthdate, ...)
    {"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJpc3MiOiJodHRwczovL2JtaS5idW5kLmV4YW1wbGUvY3JlZGVudGlhbC9waWQvMS4wIiwi"
     "c3ViIjoidXNlcjEyMzQ1IiwiZXhwIjoxNzUzOTkwNDQ5LCJpYXQiOjE3NTM5ODY4NDksImdp"
     "dmVuX25hbWUiOiJFcmlrYSIsImZhbWlseV9uYW1lIjoiTXVzdGVybWFubiIsImJpcnRoZGF0"
     "ZSI6IjE5NjMtMDgtMTIiLCJnZW5kZXIiOiJGIiwiYmlydGhfZmFtaWx5X25hbWUiOiJHYWJs"
     "ZXIiLCJhZ2Vfb3Zlcl8xOCI6dHJ1ZSwiYWdlX292ZXJfMjEiOnRydWUsImFnZV9vdmVyXzY1"
     "IjpmYWxzZSwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InY1"
     "d25RcElBMTdZd0JaNUlFMGk4ZlNiRldCSUQ4NkljVFBoRVpZam0wTmciLCJ5IjoiTkFhSDV1"
     "d3dFb2dnSkY5LU9mdUlYaVRWeGpfNjRmVGJETlpfU2hwclRoTSJ9fX0."
     "UlzoYNshYAT6GglIr2nXQ4e9ERO8VPcVNZOeFo28FwfdVNqKQZnEdQCLGftFCIH8Rhmmshf5"
     "-PAPn5g5c_u2TQ~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiMitqd3QifQ."
     "eyJub25jZSI6IjEyMzEyMzEyMyIsImF1ZCI6IlJQIiwiaWF0IjoxNzUzOTg2ODQ5fQ."
     "7eGDLcwBKfMj7d5p57FSVh9PeKqY66iN6-WSUL5mZQm4SoNElzAF-HMMwmy-jESy-"
     "97vUIe5DwwVSmc0Dk1Gyg",
     "0x3cce3bae0dd16e8a98e4d7647b449db9a170afc2c1fe0ce263a3768d9ba790b9",
     "0x462c7dd391d504e15bc6cdee6218ed495da244a198cf19da9217c796d58ab8aa",
     "0xaf246c556bba9ab47e3ce2802c3ae6901e7dd3deedf9557cc66d5b1050324b68", 11,
     "PID; string attrs: given_name, family_name, birthdate, gender, ..."},
};
constexpr size_t kNumExamples = sizeof(kExamples) / sizeof(kExamples[0]);

// ----------------------------- helpers -------------------------------------
[[noreturn]] void die(const std::string& m) {
  fprintf(stderr, "jwt_cli: %s\n", m.c_str());
  exit(2);
}
std::vector<uint8_t> read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) die("cannot read " + path);
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
}
std::string read_text(const std::string& path) {
  auto v = read_file(path);
  std::string s(v.begin(), v.end());
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
    s.pop_back();
  return s;
}
void write_file(const std::string& path, const uint8_t* d, size_t n) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) die("cannot write " + path);
  f.write(reinterpret_cast<const char*>(d), (std::streamsize)n);
}

struct Args {
  std::vector<std::pair<std::string, std::string>> kv;
  std::string get(const std::string& k, const std::string& d = "") const {
    for (auto& p : kv)
      if (p.first == k) return p.second;
    return d;
  }
};
Args parse_args(int argc, char** argv, int start) {
  Args a;
  for (int i = start; i < argc; i++) {
    std::string k = argv[i];
    if (k.rfind("--", 0) != 0) die("expected --flag: " + k);
    if (i + 1 >= argc) die("missing value for " + k);
    a.kv.emplace_back(k.substr(2), argv[++i]);
  }
  return a;
}

OpenedAttribute make_attr(const std::string& id, const std::string& val) {
  OpenedAttribute oa;
  memset(&oa, 0, sizeof(oa));
  if (id.size() > sizeof(oa.id)) die("attr-id too long (max 32)");
  if (val.size() > sizeof(oa.value)) die("attr-value too long (max 64)");
  memcpy(oa.id, id.data(), id.size());
  memcpy(oa.value, val.data(), val.size());
  oa.id_len = id.size();
  oa.value_len = val.size();
  return oa;
}

long now_ms() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch())
      .count();
}

// Build the 1-attribute JWT circuit for a given SHA-block budget.
template <size_t SHABlocks>
std::unique_ptr<Circuit<Fp256Base>> make_jwt_circuit() {
  using CompilerBackend = CompilerBackend<Fp256Base>;
  using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
  using JWTC = JWT<LogicCircuit, Fp256Base, P256, SHABlocks>;
  using EltW = typename LogicCircuit::EltW;

  QuadCircuit<Fp256Base> Q(p256_base);
  const CompilerBackend cbk(&Q);
  const LogicCircuit lc(&cbk, p256_base);
  JWTC jwtc(lc, p256, n256_order);

  EltW pkX = lc.eltw_input();
  EltW pkY = lc.eltw_input();
  EltW e2 = lc.eltw_input();

  std::vector<typename JWTC::OpenedAttribute> oa(1);
  oa[0].input(lc);
  Q.private_input();
  typename JWTC::Witness vwc;
  vwc.input(lc, 1);

  jwtc.assert_jwt_attributes(pkX, pkY, e2, oa.data(), vwc);
  return Q.mkcircuit(/*nc=*/1);
}

void make_rsf(std::unique_ptr<f2_p256>& f2, std::unique_ptr<FftExtConvolutionFactory>& fft,
              std::unique_ptr<RSFactory_b>& rsf) {
  f2 = std::make_unique<f2_p256>(p256_base);
  Elt2 omega = f2->of_string(kRootX, kRootY);
  fft = std::make_unique<FftExtConvolutionFactory>(p256_base, *f2, omega, 1ull << 31);
  rsf = std::make_unique<RSFactory_b>(*fft, p256_base);
}

// ------------------------------- prove -------------------------------------
template <size_t SHABlocks>
int prove_impl(const std::string& jwt, const std::string& pkxs,
               const std::string& pkys, const std::string& e2s,
               const OpenedAttribute& oa, const std::string& out) {
  auto CIRCUIT = make_jwt_circuit<SHABlocks>();
  Elt pkX = p256_base.of_untrusted_string(pkxs.c_str()).value();
  Elt pkY = p256_base.of_untrusted_string(pkys.c_str()).value();
  Elt e2 = p256_base.of_untrusted_string(e2s.c_str()).value();

  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);
  DenseFiller<Fp256Base> filler(W);
  filler.push_back(p256_base.one());
  filler.push_back(pkX);
  filler.push_back(pkY);
  filler.push_back(e2);
  fill_attribute(filler, oa, p256_base, 1);

  JWTWitness<P256, Fp256Scalar, SHABlocks> rvw(p256, p256_scalar);
  if (!rvw.compute_witness(jwt, pkX, pkY, {oa})) {
    printf("{\"ok\":false,\"error\":\"compute_witness failed (attr not found / "
           "sig invalid / token too big for sha-blocks)\"}\n");
    return 1;
  }
  rvw.fill_witness(filler);

  std::unique_ptr<f2_p256> f2;
  std::unique_ptr<FftExtConvolutionFactory> fft;
  std::unique_ptr<RSFactory_b> rsf;
  make_rsf(f2, fft, rsf);

  ZkProof<Fp256Base> zkp(*CIRCUIT, kRate, kNreq);
  Transcript tp((const uint8_t*)kSeed, strlen(kSeed), kVersion);
  SecureRandomEngine rng;
  ZkProver<Fp256Base, RSFactory_b> prover(*CIRCUIT, p256_base, *rsf);

  long t0 = now_ms();
  prover.commit(zkp, W, tp, rng);
  if (!prover.prove(zkp, W, tp)) {
    printf("{\"ok\":false,\"error\":\"prove failed\"}\n");
    return 1;
  }
  long dt = now_ms() - t0;

  std::vector<uint8_t> buf;
  zkp.write(buf, p256_base);
  write_file(out, buf.data(), buf.size());
  printf("{\"ok\":true,\"proof_len\":%zu,\"prove_ms\":%ld,\"sha_blocks\":%zu}\n",
         buf.size(), dt, SHABlocks);
  return 0;
}

// ------------------------------- verify ------------------------------------
template <size_t SHABlocks>
int verify_impl(const std::string& pkxs, const std::string& pkys,
                const std::string& e2s, const OpenedAttribute& oa,
                const std::string& prooffile) {
  auto CIRCUIT = make_jwt_circuit<SHABlocks>();
  Elt pkX = p256_base.of_untrusted_string(pkxs.c_str()).value();
  Elt pkY = p256_base.of_untrusted_string(pkys.c_str()).value();
  Elt e2 = p256_base.of_untrusted_string(e2s.c_str()).value();

  auto pub = Dense<Fp256Base>(1, CIRCUIT->npub_in);
  DenseFiller<Fp256Base> filler(pub);
  filler.push_back(p256_base.one());
  filler.push_back(pkX);
  filler.push_back(pkY);
  filler.push_back(e2);
  fill_attribute(filler, oa, p256_base, 1);

  std::unique_ptr<f2_p256> f2;
  std::unique_ptr<FftExtConvolutionFactory> fft;
  std::unique_ptr<RSFactory_b> rsf;
  make_rsf(f2, fft, rsf);

  ZkProof<Fp256Base> pr(*CIRCUIT, kRate, kNreq);
  auto buf = read_file(prooffile);
  ReadBuffer rb(buf);
  if (!pr.read(rb, p256_base)) {
    printf("{\"ok\":false,\"error\":\"proof parse failed\"}\n");
    return 1;
  }
  ZkVerifier<Fp256Base, RSFactory_b> ver(*CIRCUIT, *rsf, kRate, kNreq, p256_base);
  Transcript tv((const uint8_t*)kSeed, strlen(kSeed), kVersion);

  long t0 = now_ms();
  ver.recv_commitment(pr, tv);
  bool ok = ver.verify(pr, pub, tv);
  long dt = now_ms() - t0;

  printf("{\"ok\":%s,\"verify_ms\":%ld,\"sha_blocks\":%zu}\n",
         ok ? "true" : "false", dt, SHABlocks);
  return ok ? 0 : 1;
}

// supported SHA-block budgets (compile-time circuit sizes)
#define DISPATCH_SHA(fn, sb, ...)            \
  switch (sb) {                              \
    case 7:                                  \
      return fn<7>(__VA_ARGS__);             \
    case 11:                                 \
      return fn<11>(__VA_ARGS__);            \
    case 15:                                 \
      return fn<15>(__VA_ARGS__);            \
    default:                                 \
      die("unsupported --sha-blocks (use 7, 11, or 15)"); \
  }

// ------------------------------- commands ----------------------------------
int cmd_export_example(const Args& a) {
  size_t idx = a.get("index").empty() ? 0 : std::stoul(a.get("index"));
  std::string outdir = a.get("outdir");
  if (outdir.empty()) die("--outdir required");
  if (idx >= kNumExamples) die("index out of range");
  const Example& e = kExamples[idx];
  write_file(outdir + "/jwt.txt", (const uint8_t*)e.jwt, strlen(e.jwt));
  std::string j = std::string("{\"index\":") + std::to_string(idx) +
                  ",\"pkx\":\"" + e.pkx + "\",\"pky\":\"" + e.pky +
                  "\",\"e2\":\"" + e.e2 + "\",\"sha_blocks\":" +
                  std::to_string(e.recommended_sha_blocks) + ",\"note\":\"" +
                  e.note + "\"}";
  write_file(outdir + "/issued.json", (const uint8_t*)j.data(), j.size());
  printf("%s\n", j.c_str());
  return 0;
}

int cmd_prove(const Args& a) {
  std::string jwt = read_text(a.get("jwt"));
  OpenedAttribute oa = make_attr(a.get("attr-id"), a.get("attr-value"));
  size_t sb = a.get("sha-blocks").empty() ? 7 : std::stoul(a.get("sha-blocks"));
  std::string out = a.get("out");
  if (a.get("pkx").empty() || a.get("attr-id").empty() || out.empty())
    die("--pkx --pky --e2 --attr-id --attr-value --out required");
  DISPATCH_SHA(prove_impl, sb, jwt, a.get("pkx"), a.get("pky"), a.get("e2"), oa, out);
}

int cmd_verify(const Args& a) {
  OpenedAttribute oa = make_attr(a.get("attr-id"), a.get("attr-value"));
  size_t sb = a.get("sha-blocks").empty() ? 7 : std::stoul(a.get("sha-blocks"));
  if (a.get("pkx").empty() || a.get("attr-id").empty() || a.get("proof").empty())
    die("--pkx --pky --e2 --attr-id --attr-value --proof required");
  DISPATCH_SHA(verify_impl, sb, a.get("pkx"), a.get("pky"), a.get("e2"), oa, a.get("proof"));
}

}  // namespace
}  // namespace proofs

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: jwt_cli <export-example|prove|verify> [--flags]\n");
    return 2;
  }
  proofs::set_log_level(proofs::ERROR);
  std::string cmd = argv[1];
  proofs::Args a = proofs::parse_args(argc, argv, 2);
  if (cmd == "export-example") return proofs::cmd_export_example(a);
  if (cmd == "prove") return proofs::cmd_prove(a);
  if (cmd == "verify") return proofs::cmd_verify(a);
  proofs::die("unknown command: " + cmd);
}
