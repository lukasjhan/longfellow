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
namespace hashc {
struct Slot {
  v8 pattern[MAXPAT]; v8 patlen;
  v8 disc_pre[64 * MAXB]; v256 disc_ebits; SBW disc_sha[MAXB]; v8 disc_nb;
  LC::bitvec<8> disc_len, disc_shift; LC::bitvec<LOGM> sd_idx;
};
struct Inputs {
  v8 now[10]; v8 vct_pat[MAXVCT]; v8 vct_len;
  v8 nonce_pat[MAXNONCE]; v8 nonce_len; v8 aud_pat[MAXAUD]; v8 aud_len;
  v256 e2;
  std::vector<Slot> slot; MACTag mac[7];
  v256 e, dpkx, dpky;
  v8 preimage[PRE]; SBW sha[kMaxSHA]; v8 nb;
  LC::bitvec<LOGM> payload_ind, payload_len, exp_idx, vct_idx, cnf_x_idx, cnf_y_idx;
  v8 kb_pre[DECKB]; SBW kb_sha[KBB]; v8 kb_nb;
  LC::bitvec<LOGM> kb_pl_ind, kb_pl_len, sd_hash_idx, nonce_idx, aud_idx;
  v8 presented[PRES]; SBW pres_sha[PB]; v8 pres_nb; v256 pres_hash_bits;
  std::vector<LC::bitvec<LOGM>> disc_in_pres;
  MACW macw[3];
};

void declare_inputs(const LC& L, QuadCircuit<f_128>& Q, Inputs& in, size_t nattr) {
  in.slot.resize(nattr); in.disc_in_pres.resize(nattr);
  for (auto& b : in.now) b = L.template vinput<8>();
  for (auto& b : in.vct_pat) b = L.template vinput<8>();
  in.vct_len = L.template vinput<8>();
  for (auto& b : in.nonce_pat) b = L.template vinput<8>();
  in.nonce_len = L.template vinput<8>();
  for (auto& b : in.aud_pat) b = L.template vinput<8>();
  in.aud_len = L.template vinput<8>();
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

// Fill a dense array for the hash circuit. macs6/av in the public tail (zeros at
// commit; real for verify). ap is the shared committed key. pub_only -> public
// inputs only (no SHA/preimage/disclosure witness).
bool fill(Dense<f_128>& W, bool pub_only, const Circuit<f_128>& C, const f_128& Fs,
          const std::string& compact, const char* now,
          const std::vector<std::string>& claims, const std::string& vct,
          const std::string& nonce, const std::string& aud,
          const gf2k* ap, const gf2k macs6[6], gf2k av) {
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
  auto fillpub = [&](DenseFiller<f_128>& f) {
    f.push_back(Fs.one());
    for (int i = 0; i < 10; ++i) f.push_back((uint8_t)now[i], 8, Fs);
    for (size_t i = 0; i < MAXVCT; ++i) f.push_back(i < vct_pat.size() ? (uint8_t)vct_pat[i] : 0, 8, Fs);
    f.push_back((uint8_t)vct_pat.size(), 8, Fs);
    for (size_t i = 0; i < MAXNONCE; ++i) f.push_back(i < nonce_pat.size() ? (uint8_t)nonce_pat[i] : 0, 8, Fs);
    f.push_back((uint8_t)nonce_pat.size(), 8, Fs);
    for (size_t i = 0; i < MAXAUD; ++i) f.push_back(i < aud_pat.size() ? (uint8_t)aud_pat[i] : 0, 8, Fs);
    f.push_back((uint8_t)aud_pat.size(), 8, Fs);
    push_rev_bits(f, kbdig, Fs);
    for (size_t s = 0; s < nattr; ++s) {
      std::string dj = b64d(chosen[s]);
      size_t salt_len = dj.find("\",\"") - 2;
      std::string pat = dj.substr(2 + salt_len);
      for (size_t i = 0; i < MAXPAT; ++i) f.push_back(i < pat.size() ? (uint8_t)pat[i] : 0, 8, Fs);
      f.push_back((uint8_t)pat.size(), 8, Fs);
    }
    for (int i = 0; i < 6; ++i) f.push_back(macs6[i]);
    f.push_back(av);
  };
  DenseFiller<f_128> f(W);
  fillpub(f);
  if (pub_only) return true;
  {
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
    for (int i = 0; i < 6; ++i) f.push_back(ap[i]);  // SHARED, av-independent key
  }
  return true;
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
  sigc::fill(pub_sig, true, v, nullptr, gmacs2, av2);
  hashc::fill(pub_hash, true, *Chash, Fs, compact, now, claims, vct, nonce, aud, nullptr, gmacs2, av2);
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
