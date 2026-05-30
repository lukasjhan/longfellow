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
//
// Shared base (constants, helpers, MAC machinery, check_capacity) lives in
// sdjwt_common.h — this file keeps only the split-specific circuit builders.

#include "sdjwt_common.h"

namespace proofs {

// ===================== Fp256 signature circuit =====================
namespace sigc {
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

// Fill a dense array for the sig circuit. macs6/av go in the public part (zeros
// during the prover's commit; the real values for the verifier). ap is the
// shared committed key half (witness). pub_only -> stop after public inputs.
bool fill(Dense<Fp256Base>& W, bool pub_only, const Parsed& v,
          const gf2k* ap, const gf2k macs6[6], gf2k av) {
  const f_128 gf;
  DenseFiller<Fp256Base> f(W);
  f.push_back(p256_base.one());
  f.push_back(v.pkX); f.push_back(v.pkY); f.push_back(v.e2);
  for (int i = 0; i < 6; ++i) push_gf_bits(f, macs6[i]);
  push_gf_bits(f, av);
  if (pub_only) return true;
  f.push_back(v.e_); f.push_back(v.dpkx); f.push_back(v.dpky);
  EcdsaHostW isigw(p256_scalar, p256), ksigw(p256_scalar, p256);
  if (!isigw.compute_witness(v.pkX, v.pkY, v.e_nat, v.ir, v.is)) return false;
  if (!ksigw.compute_witness(v.dpkx, v.dpky, v.e2_nat, v.kr, v.ks)) return false;
  isigw.fill_witness(f); ksigw.fill_witness(f);
  Fp256Base::Elt vals[3] = {v.e_, v.dpkx, v.dpky};
  for (int i = 0; i < 3; ++i) {
    uint8_t buf[32]; p256_base.to_bytes_field(buf, vals[i]);
    MacWitness<Fp256Base> mw(p256_base, gf);
    mw.compute_witness(&ap[2 * i], buf);  // SHARED, av-independent key
    mw.fill_witness(f);
  }
  return true;
}
}  // namespace sigc

// ===================== GF(2^128) hash circuit =====================
// All circuit logic is the shared base in sdjwt_common.h; split adds no feature.
namespace hashc {
struct Inputs : BaseInputs {};  // no feature fields

void declare_inputs(const LC& L, QuadCircuit<f_128>& Q, Inputs& in, size_t nattr) {
  declare_base(L, Q, in, nattr, /*nv=*/3);
}

void assert_logic(const LC& L, const Inputs& in) {
  assert_base(L, in, /*nv=*/3);
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

bool fill(Dense<f_128>& W, bool pub_only, const Circuit<f_128>& C, const f_128& Fs,
          const std::string& compact, const char* now,
          const std::vector<std::string>& claims, const std::string& vct,
          const std::string& nonce, const std::string& aud,
          const gf2k* ap, const gf2k macs6[6], gf2k av) {
  (void)C;
  return fill_base(W, pub_only, compact, now, claims, vct, nonce, aud, Fs, /*nv=*/3, macs6, av, ap);
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
  std::string nonce = argc > 6 ? argv[6] : "1234567890";              // verifier-chosen nonce
  std::string aud = argc > 7 ? argv[7] : "https://verifier.example";  // verifier-chosen aud
  size_t nattr = claims.size();

  std::string compact = rf(fixture);
  const f_128 Fs;

  // ---- capacity check: fail clearly if the token exceeds the fixed circuit ----
  std::string cap_err;
  if (!hashc::check_capacity(compact, claims, vct, cap_err)) {
    printf("ERROR (cannot prove): %s\n", cap_err.c_str());
    return 2;
  }
  if (("\"nonce\":\"" + nonce + "\"").size() > hashc::MAXNONCE ||
      ("\"aud\":\"" + aud + "\"").size() > hashc::MAXAUD) {
    printf("ERROR (cannot prove): nonce/aud pattern too long\n"); return 2;
  }

  // ---- parse fixture; sample the prover's MAC key half a_p (committed) ----
  sigc::Parsed v;
  if (!sigc::parse(compact, jwk, v)) { printf("parse/sig material invalid\n"); return 1; }
  // holder-side: the PUBLIC STATEMENT the holder hands the verifier alongside the
  // proof — e2 (KB hash) + the disclosed `","name","value"]` per claim. This is
  // ALL the verifier needs from the credential; it never sees the raw token.
  uint8_t e2_pub[32]; std::vector<std::string> patterns_pub;
  if (!hashc::make_statement(compact, claims, {}, e2_pub, patterns_pub)) { printf("statement build failed\n"); return 1; }
  SecureRandomEngine rng;
  Linker lk;
  { MACReference<f_128> mr; mr.sample(lk.ap, 6, &rng); }
  Fp256Base::Elt common[3] = {v.e_, v.dpkx, v.dpky};  // the MAC-linked values

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
  // cache key includes the geometry so changing capacities auto-invalidates it.
  char geo[64];
  snprintf(geo, sizeof geo, "%zua-s%zu-kb%zu-pb%zu-b%zu-e2", nattr,
           hashc::kMaxSHA, hashc::KBB, hashc::PB, hashc::MAXB);
  auto Chash = get_circuit<f_128>(Fs, GF2_128_ID, cdir + "/sdjwt-hash-" + geo + ".bin",
      [&] { return hashc::make_hash_circuit(Fs, nattr); }, rh.circ_kb);
  long build_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-tb0).count();
  printf("  circuits ready in %ld ms\n", build_ms);
  rs.ninputs = Csig->ninputs; rh.ninputs = Chash->ninputs;

  // mac-wire indices: sig macs follow {1,pkX,pkY,e2}; hash macs are the last 7.
  const size_t si = 4, hi = Chash->npub_in - 7;
  const gf2k zero6[6] = {Fs.zero(), Fs.zero(), Fs.zero(), Fs.zero(), Fs.zero(), Fs.zero()};

  // RS factories
  const sigc::f2_p256 p256_2(p256_base);
  const sigc::Elt2 omega = p256_2.of_string(sigc::kRootX, sigc::kRootY);
  const sigc::FftExt fft(p256_base, p256_2, omega, 1ull << 31);
  const sigc::RSFp rsf_s(fft, p256_base);
  const hashc::RSGf rsf_h(Fs);

  // ======================= PROVER =======================
  // 1) fill both witnesses with a_p but ZERO macs/av (placeholders).
  auto W_sig = Dense<Fp256Base>(1, Csig->ninputs);
  auto W_hash = Dense<f_128>(1, Chash->ninputs);
  if (!sigc::fill(W_sig, false, v, lk.ap, zero6, Fs.zero())) { printf("sig fill failed\n"); return 1; }
  if (!hashc::fill(W_hash, false, *Chash, Fs, compact, now, claims, vct, nonce, aud, lk.ap, zero6, Fs.zero())) { printf("hash fill failed\n"); return 1; }

  // 2) commit BOTH into one shared transcript (so a_v depends on both commits).
  Transcript tp((const uint8_t*)"sdjwt-split", 11, kVer);
  ZkProof<f_128> h_zk(*Chash, kRate, kNreq);
  ZkProof<Fp256Base> s_zk(*Csig, kRate, kNreq);
  ZkProver<f_128, hashc::RSGf> hash_p(*Chash, Fs, rsf_h);
  ZkProver<Fp256Base, sigc::RSFp> sig_p(*Csig, p256_base, rsf_s);
  auto t0 = std::chrono::steady_clock::now();
  hash_p.commit(h_zk, W_hash, tp, rng);
  sig_p.commit(s_zk, W_sig, tp, rng);

  // 3) a_v from the (post-commit) transcript; compute macs; write into W.
  gf2k av = generate_mac_key(tp, Fs), gmacs[6];
  uint8_t macs_b[6 * f_128::kBytes];
  compute_macs(common, 3, gmacs, macs_b, lk.ap, av, Fs);
  update_macs(W_sig, W_hash, si, hi, gmacs, 6, av);

  // 4) prove both (same transcript, hash then sig).
  bool ph = hash_p.prove(h_zk, W_hash, tp);
  bool psg = sig_p.prove(s_zk, W_sig, tp);
  long prove_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();

  // 5) bundle: [6 macs][hash proof][sig proof]
  std::vector<uint8_t> hb, sb;
  h_zk.write(hb, Fs);
  s_zk.write(sb, p256_base);
  rh.proof_kb = hb.size() / 1024; rs.proof_kb = sb.size() / 1024;
  std::vector<uint8_t> bundle(macs_b, macs_b + 6 * f_128::kBytes);
  bundle.insert(bundle.end(), hb.begin(), hb.end());
  bundle.insert(bundle.end(), sb.begin(), sb.end());

  // Optional negative test: flip one bit of mac_e in the bundle. The committed
  // witness no longer satisfies the (now wrong) public mac under the transcript
  // a_v, so BOTH circuits must reject — proving the MAC link is load-bearing.
  bool tamper = getenv("TAMPER") != nullptr;
  if (tamper) { bundle[0] ^= 1; printf("  [TAMPER] flipped 1 bit of mac_e in the bundle\n"); }

  // ======================= VERIFIER =======================
  // parse macs from the bundle; everything else is reconstructed independently.
  gf2k gmacs2[6];
  for (int i = 0; i < 6; ++i) gmacs2[i] = Fs.of_bytes_field(bundle.data() + i * f_128::kBytes).value();
  std::vector<uint8_t> rest(bundle.begin() + 6 * f_128::kBytes, bundle.end());
  ReadBuffer rb(rest);
  ZkProof<f_128> pr_h(*Chash, kRate, kNreq);
  ZkProof<Fp256Base> pr_s(*Csig, kRate, kNreq);
  if (!pr_h.read(rb, Fs) || !pr_s.read(rb, p256_base)) { printf("proof read failed\n"); return 1; }

  auto tv0 = std::chrono::steady_clock::now();
  Transcript tv((const uint8_t*)"sdjwt-split", 11, kVer);
  ZkVerifier<f_128, hashc::RSGf> hash_v(*Chash, rsf_h, kRate, kNreq, Fs);
  ZkVerifier<Fp256Base, sigc::RSFp> sig_v(*Csig, rsf_s, kRate, kNreq, p256_base);
  hash_v.recv_commitment(pr_h, tv);
  sig_v.recv_commitment(pr_s, tv);
  gf2k av2 = generate_mac_key(tv, Fs);  // verifier re-derives the SAME a_v

  // build public inputs with the bundle's macs + the re-derived a_v.
  auto pub_sig = Dense<Fp256Base>(1, Csig->npub_in);
  auto pub_hash = Dense<f_128>(1, Chash->npub_in);
  // VERIFIER: public inputs are built WITHOUT the token. Inputs are the issuer
  // pubkey (from its trusted JWK), the holder's statement {e2, disclosed
  // name/value}, the verifier's own now/vct/nonce/aud, and macs/av from the
  // bundle. Note: neither `compact` nor the full `v` parse appears below.
  Fp256Base::Elt vpkX, vpkY; sigc::pubkey_from_jwk(jwk, vpkX, vpkY);
  sigc::fill_public(pub_sig, vpkX, vpkY, sigc::e2_elt_from_digest(e2_pub), gmacs2, 3, av2);
  hashc::fill_public(pub_hash, now, vct, nonce, aud, Fs, 3, gmacs2, av2, e2_pub, patterns_pub);
  bool vh = hash_v.verify(pr_h, pub_hash, tv);
  bool vsg = sig_v.verify(pr_s, pub_sig, tv);
  long verify_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - tv0).count();

  bool sok = psg && vsg, hok = ph && vh;
  printf("  sig  (Fp256)   : ninputs=%zu circuit=%zu KB  proof=%zu KB  %s\n",
         rs.ninputs, rs.circ_kb, rs.proof_kb, sok ? "ACCEPT" : "REJECT");
  printf("  hash (GF2^128) : ninputs=%zu circuit=%zu KB  proof=%zu KB  %s\n",
         rh.ninputs, rh.circ_kb, rh.proof_kb, hok ? "ACCEPT" : "REJECT");
  if (tamper) {
    bool pass = !sok && !hok;  // tampering MUST break verification
    printf("  TOTAL [TAMPER] : both rejected? %s  -> MAC link is enforced: %s\n",
           (!sok && !hok) ? "yes" : "no", pass ? "PASS ✅" : "FAIL ❌");
    return pass ? 0 : 1;
  }
  printf("  TOTAL          : prove=%ld ms  verify=%ld ms  bundle=%zu KB  link=MAC(e,dpkx,dpky), a_v from transcript -> %s\n",
         prove_ms, verify_ms, bundle.size() / 1024,
         (sok && hok) ? "ACCEPT ✅ (two circuits, soundly linked)" : "REJECT ❌");
  return (sok && hok) ? 0 : 1;
}
