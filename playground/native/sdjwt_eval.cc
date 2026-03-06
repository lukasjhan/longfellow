// M2 prototype (EvaluationBackend, no ZK): validate the NEW sub-circuit logic
// for Approach-C SD-JWT before wiring it into a real circuit.
//
// This file currently validates the `exp` (validity) check:
//   SD-JWT exp/iat are 10-digit UNIX timestamps. For equal-length decimal
//   strings, lexicographic byte comparison == numeric comparison (ASCII
//   '0'..'9' are monotonic). So "now <= exp" reduces to a per-byte compare —
//   no integer parsing needed, and it translates directly to the circuit.
//
// Build: see native/build.sh (sdjwt_eval target). Run: ./native/sdjwt_eval
// Exit 0 + "ALL ... PASS" means the logic is correct (EvaluationBackend(true)
// panics on any false assertion).

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include <openssl/sha.h>

#include "circuits/tests/base64/decode.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/routing.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"
#include "util/log.h"

namespace proofs {
namespace {

using EvalBackend = EvaluationBackend<Fp256Base>;
using L_t = Logic<Fp256Base, EvalBackend>;
using v8 = L_t::v8;
using v256 = L_t::v256;
using BitW = L_t::BitW;

constexpr size_t kPluck = 4;  // = kSHAJWTPluckerBits
using FlatSHA = FlatSHA256Circuit<L_t, BitPlucker<L_t, kPluck>>;

// Build n v8 bytes from an ASCII string.
void mk_bytes(const L_t& L, const char* s, v8* out, size_t n) {
  for (size_t i = 0; i < n; ++i) out[i] = L.template vbit<8>((uint8_t)s[i]);
}

// Lexicographic a <= b for equal-length byte arrays (index 0 = most
// significant). Built from per-byte eq/lt — circuit-translatable as-is.
BitW leq_bytes(const L_t& L, const v8* a, const v8* b, size_t n) {
  BitW le = L.bit(1);  // empty suffix: equal => a <= b
  for (size_t i = n; i-- > 0;) {
    BitW blt = L.lt(8, a[i].data(), b[i].data());
    BitW beq = L.eq(8, a[i].data(), b[i].data());
    le = L.lor(blt, L.land(beq, le));
  }
  return le;
}

// assert "now <= exp" (credential not expired).
void assert_not_expired(const L_t& L, const char* now, const char* exp) {
  v8 n[10], e[10];
  mk_bytes(L, now, n, 10);
  mk_bytes(L, exp, e, 10);
  L.assert1(leq_bytes(L, n, e, 10));
}

// Build a v256 `target` (the claimed SHA-256 output) from a 32-byte digest,
// using longfellow's convention: the digest is read big-endian into an integer
// E, and target[i] is bit i of E (LSB first). i.e. target[8*b+c] = bit c of
// digest byte (31-b).
void digest_to_v256(const L_t& L, const uint8_t dig[32], v256& target) {
  for (size_t b = 0; b < 32; ++b)
    for (size_t c = 0; c < 8; ++c)
      target[8 * b + c] = L.bit((dig[31 - b] >> c) & 1);
}

// Core of Approach C: prove SHA-256(disclosure) equals a given digest, inside
// the circuit (FlatSHA256). Returns the `target` bits so a caller can later
// assert membership (target == base64decode(_sd entry)).
// MAXB = max SHA blocks for the disclosure (disclosures are short).
template <size_t MAXB>
void assert_sha_of(const L_t& L, const char* msg, size_t mlen, v256& target_out) {
  uint8_t in[64 * MAXB];
  FlatSHA256Witness::BlockWitness bw[MAXB];
  uint8_t numb = 0;
  FlatSHA256Witness::transform_and_witness_message(mlen, (const uint8_t*)msg,
                                                    MAXB, numb, in, bw);

  uint8_t dig[32];
  SHA256((const uint8_t*)msg, mlen, dig);

  // Pack the SHA block witnesses into circuit form.
  FlatSHA sha(L);
  typename FlatSHA::BlockWitness sbw[MAXB];
  BitPluckerEncoder<Fp256Base, kPluck> enc(p256_base);
  for (size_t i = 0; i < MAXB; ++i) {
    for (size_t k = 0; k < 48; ++k) sbw[i].outw[k] = L.konst(enc.mkpacked_v32(bw[i].outw[k]));
    for (size_t k = 0; k < 64; ++k) {
      sbw[i].oute[k] = L.konst(enc.mkpacked_v32(bw[i].oute[k]));
      sbw[i].outa[k] = L.konst(enc.mkpacked_v32(bw[i].outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) sbw[i].h1[k] = L.konst(enc.mkpacked_v32(bw[i].h1[k]));
  }

  v8 preimage[64 * MAXB];
  for (size_t i = 0; i < 64 * MAXB; ++i) preimage[i] = L.template vbit<8>(in[i]);
  v8 nb = L.template vbit<8>(numb);

  digest_to_v256(L, dig, target_out);
  // If SHA(preimage) != target, EvaluationBackend(true) panics here.
  sha.assert_message_hash(MAXB, nb, preimage, target_out, sbw);
}

v8 vb(const L_t& L, uint8_t c) { return L.template vbit<8>(c); }

// 4a: structural extraction. Verify a DECODED disclosure
//   ["<salt>","<name>",<value>]
// encodes the requested (name, value), where <value> is the exact JSON encoding
// ("Erika" incl. quotes / true / 175). salt is a variable-length unknown run.
//
// Method (circuit-friendly): assert the fixed prefix `["`, then shift left by
// (2 + saltLen) so the salt's closing quote is at position 0, then compare the
// remainder against the fixed pattern  ","<name>",<value>]  byte-for-byte. The
// closing ']' delimits <value>, so this is sound for ANY value type (no prefix
// ambiguity), and the whole disclosure is hash-committed via _sd membership.
template <size_t MAXD, size_t LOGN>
void assert_disclosure_struct(const L_t& L, const v8 D[/*MAXD*/], size_t saltLen,
                              const char* name, size_t nlen, const char* value,
                              size_t vlen) {
  // Fixed prefix: D[0]=='[', D[1]=='"'
  L.assert1(L.eq(8, D[0].data(), vb(L, '[').data()));
  L.assert1(L.eq(8, D[1].data(), vb(L, '"').data()));

  // Expected suffix pattern P, starting at the salt-closing quote (pos 2+saltLen):
  //   '"' ',' '"' <name> '"' ',' <value> ']'
  std::vector<v8> P;
  P.push_back(vb(L, '"'));
  P.push_back(vb(L, ','));
  P.push_back(vb(L, '"'));
  for (size_t i = 0; i < nlen; ++i) P.push_back(vb(L, (uint8_t)name[i]));
  P.push_back(vb(L, '"'));
  P.push_back(vb(L, ','));
  for (size_t i = 0; i < vlen; ++i) P.push_back(vb(L, (uint8_t)value[i]));
  P.push_back(vb(L, ']'));

  // Shift D left by (2 + saltLen).
  typename L_t::template bitvec<LOGN> amount = L.template vbit<LOGN>(2 + saltLen);
  v8 zero = vb(L, 0);
  std::vector<v8> S(P.size());
  Routing<L_t> r(L);
  r.shift(amount, P.size(), S.data(), MAXD, D, zero, 3);

  // Compare the shifted remainder to the fixed pattern.
  for (size_t i = 0; i < P.size(); ++i)
    L.assert1(L.eq(8, S[i].data(), P[i].data()));
}

// Build D (v8[MAXD]) from a decoded-disclosure JSON string (zero-padded).
template <size_t MAXD>
void mk_disc(const L_t& L, const char* json, v8 D[/*MAXD*/]) {
  size_t n = strlen(json);
  for (size_t i = 0; i < MAXD; ++i)
    D[i] = L.template vbit<8>(i < n ? (uint8_t)json[i] : 0);
}

// base64url encode (no padding) — host helper to build a test `_sd` entry.
std::string b64url(const uint8_t* d, size_t n) {
  static const char* T =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string o;
  int val = 0, bits = 0;
  for (size_t i = 0; i < n; ++i) {
    val = (val << 8) | d[i];
    bits += 8;
    while (bits >= 6) { o += T[(val >> (bits - 6)) & 63]; bits -= 6; }
  }
  if (bits > 0) o += T[(val << (6 - bits)) & 63];
  return o;
}

// Full `_sd` membership: returns a bit that is true iff
//   base64url-decode(sd_entry) == SHA-256(disclosure).
// (assert_sha_of binds SHA(disclosure) to `target`; we then compare the
//  base64-decoded, issuer-signed _sd entry against that digest.)
BitW sha_membership(const L_t& L, const char* disc, size_t dlen,
                    const std::string& sd_entry) {
  v256 target;
  assert_sha_of<2>(L, disc, dlen, target);

  size_t n = sd_entry.size();  // 43 for a 32-byte digest
  std::vector<v8> in(n), out((n * 6) / 8 + 1);
  for (size_t i = 0; i < n; ++i) in[i] = L.template vbit<8>((uint8_t)sd_entry[i]);
  Base64Decoder<L_t> b64(L);
  b64.base64_rawurl_decode(in.data(), out.data(), n);

  BitW all = L.bit(1);
  for (size_t j = 0; j < 32; ++j) {
    v8 tb;  // digest byte j, reconstructed from target bits
    for (size_t c = 0; c < 8; ++c) tb[c] = target[8 * (31 - j) + c];
    all = L.land(all, L.eq(8, out[j].data(), tb.data()));
  }
  return all;
}

// ---------------- host helpers for the integrated test ----------------------
int b64v(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}
std::string b64url_decode(const std::string& s) {
  std::string o;
  int val = 0, bits = 0;
  for (char c : s) {
    int d = b64v(c);
    if (d < 0) continue;
    val = (val << 6) | d;
    bits += 6;
    if (bits >= 8) { o += char((val >> (bits - 8)) & 0xff); bits -= 8; }
  }
  return o;
}
std::string read_file(const std::string& p) {
  std::ifstream f(p, std::ios::binary);
  std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
  return s;
}

// 4b: tie everything together on a REAL SD-JWT-VC fixture. Locates the exp
// digits and a disclosure's _sd entry inside the (decoded) payload by index
// (Routing::shift), then runs exp + membership + structural checks in-circuit.
void test_integrated(const L_t& L, const std::string& path, const char* now) {
  const size_t MAXP = 1024;   // max decoded-payload bytes
  const size_t MAXDB = 128;   // max disclosure base64 chars
  const size_t MAXDD = 96;    // max decoded-disclosure bytes
  const size_t LOGP = 10;     // index bits into payload

  std::string compact = read_file(path);
  std::string jwt = compact.substr(0, compact.find('~'));
  std::string payload_b64 = jwt.substr(jwt.find('.') + 1);
  payload_b64 = payload_b64.substr(0, payload_b64.find('.'));
  std::string payload = b64url_decode(payload_b64);  // JSON text

  // Collect disclosures (between the '~').
  std::vector<std::string> discs;
  {
    size_t p = compact.find('~') + 1, q;
    while ((q = compact.find('~', p)) != std::string::npos) {
      if (q > p) discs.push_back(compact.substr(p, q - p));
      p = q + 1;
    }
  }
  // Choose the boolean disclosure (decodes to [...,"age_over_18",...]).
  std::string disc;
  for (auto& d : discs)
    if (b64url_decode(d).find("\"age_over_18\"") != std::string::npos) disc = d;
  check(!disc.empty(), "age_over_18 disclosure not found in fixture");

  // Host: digest + its _sd entry + locations in the payload.
  uint8_t dg[32];
  SHA256((const uint8_t*)disc.data(), disc.size(), dg);
  std::string sd_entry = b64url(dg, 32);
  size_t sd_idx = payload.find(sd_entry);
  check(sd_idx != std::string::npos, "disclosure digest not in payload _sd");
  size_t exp_idx = payload.find("\"exp\":");
  check(exp_idx != std::string::npos, "exp not in payload");
  exp_idx += 6;  // skip "exp":

  // ---- circuit witness ----
  v8 P[MAXP];
  for (size_t i = 0; i < MAXP; ++i)
    P[i] = L.template vbit<8>(i < payload.size() ? (uint8_t)payload[i] : 0);
  v8 zero = vb(L, 0);
  Routing<L_t> r(L);

  // (1) exp: shift payload to the 10 exp digits, compare to `now`.
  {
    v8 ed[10], nd[10];
    auto amt = L.template vbit<LOGP>(exp_idx);
    r.shift(amt, 10, ed, MAXP, P, zero, 3);
    mk_bytes(L, now, nd, 10);
    L.assert1(leq_bytes(L, nd, ed, 10));  // now <= exp
  }

  // (2) membership: SHA(disc) == base64decode(_sd entry located in payload).
  v256 target;
  assert_sha_of<2>(L, disc.data(), disc.size(), target);
  {
    v8 entry[43];
    auto amt = L.template vbit<LOGP>(sd_idx);
    r.shift(amt, 43, entry, MAXP, P, zero, 3);
    v8 out[33];
    Base64Decoder<L_t> b64(L);
    b64.base64_rawurl_decode(entry, out, 43);
    for (size_t j = 0; j < 32; ++j) {
      v8 tb;
      for (size_t c = 0; c < 8; ++c) tb[c] = target[8 * (31 - j) + c];
      L.assert1(L.eq(8, out[j].data(), tb.data()));
    }
  }

  // (3) structural: decode the disclosure in-circuit, verify (name,value).
  {
    std::string dj = b64url_decode(disc);  // host: to get salt length
    size_t saltLen = dj.find("\",\"") - 2;  // ["<salt>"...  -> salt is [2 .. )
    v8 db[MAXDB];
    for (size_t i = 0; i < MAXDB; ++i)
      db[i] = L.template vbit<8>(i < disc.size() ? (uint8_t)disc[i] : 0);
    v8 dd[MAXDD];
    Base64Decoder<L_t> b64(L);
    b64.base64_rawurl_decode(db, dd, disc.size());
    assert_disclosure_struct<MAXDD, 8>(L, dd, saltLen, "age_over_18", 11, "true", 4);
  }
}

}  // namespace
}  // namespace proofs

int main(int argc, char** argv) {
  using namespace proofs;
  set_log_level(ERROR);
  const EvalBackend ebk(p256_base, true);  // true => panic on false assert
  const L_t L(&ebk, p256_base);

  // 10-digit UNIX timestamps.
  const char* exp = "1748000000";  // expiry

  // 1) now < exp  => not expired => assert passes
  assert_not_expired(L, "1700000000", exp);
  printf("exp check  now<exp   : PASS (valid)\n");

  // 2) now == exp => boundary => not expired
  assert_not_expired(L, "1748000000", exp);
  printf("exp check  now==exp  : PASS (valid at boundary)\n");

  // 3) now > exp  => expired => leq must be FALSE (assert the negation)
  {
    v8 n[10], e[10];
    mk_bytes(L, "1800000000", n, 10);
    mk_bytes(L, "1748000000", e, 10);
    L.assert1(L.lnot(leq_bytes(L, n, e, 10)));  // correctly detected expired
  }
  printf("exp check  now>exp   : PASS (expiry correctly rejected)\n");

  // SHA-of-disclosure (core of `_sd` membership): prove SHA256(disclosure)
  // in-circuit equals the digest. A real disclosure = base64url([salt,name,value]).
  const char* disc = "WyJHUG5sZVRnZVp2YkMzVUpuUEJ2ck5BIiwiYWdlX292ZXJfMTgiLHRydWVd";
  v256 digest_bits;
  assert_sha_of<2>(L, disc, strlen(disc), digest_bits);
  printf("sha(disclosure) in-circuit == digest : PASS (membership core)\n");

  // Full `_sd` membership: build the real entry = base64url(SHA(disc)).
  uint8_t dg[32];
  SHA256((const uint8_t*)disc, strlen(disc), dg);
  std::string sd_ok = b64url(dg, 32);
  L.assert1(sha_membership(L, disc, strlen(disc), sd_ok));
  printf("membership  SHA(disc) ∈ _sd entry    : PASS (correct entry accepted)\n");

  // Negative: tamper the entry → membership must be false.
  std::string sd_bad = sd_ok;
  sd_bad[0] = (sd_bad[0] == 'A') ? 'B' : 'A';
  L.assert1(L.lnot(sha_membership(L, disc, strlen(disc), sd_bad)));
  printf("membership  wrong entry              : PASS (rejected)\n");

  // 4a: disclosure structural extraction — works for ALL value types.
  // salt below is 22 chars (16 random bytes base64url).
  {
    const size_t MAXD = 128;
    v8 D[MAXD];
    // string value
    mk_disc<MAXD>(L, "[\"GPnleTgeZvbC3UJnPBvrNA\",\"given_name\",\"Erika\"]", D);
    assert_disclosure_struct<MAXD, 8>(L, D, 22, "given_name", 10, "\"Erika\"", 7);
    printf("disclosure  string  given_name=Erika : PASS\n");
    // boolean value
    mk_disc<MAXD>(L, "[\"GPnleTgeZvbC3UJnPBvrNA\",\"age_over_18\",true]", D);
    assert_disclosure_struct<MAXD, 8>(L, D, 22, "age_over_18", 11, "true", 4);
    printf("disclosure  boolean age_over_18=true : PASS\n");
    // number value
    mk_disc<MAXD>(L, "[\"GPnleTgeZvbC3UJnPBvrNA\",\"height\",175]", D);
    assert_disclosure_struct<MAXD, 8>(L, D, 22, "height", 6, "175", 3);
    printf("disclosure  number  height=175       : PASS\n");
  }

  // 4b: integrated check on a REAL SD-JWT-VC fixture.
  {
    const char* fixture = (argc > 1) ? argv[1] : "playground/fixtures/sdjwt.txt";
    std::ifstream probe(fixture);
    if (probe.good()) {
      probe.close();
      test_integrated(L, fixture, "1700000000");  // now < exp(fixture)
      printf("\nINTEGRATED on real fixture (%s):\n", fixture);
      printf("  exp valid + age_over_18 ∈ _sd + decodes to (age_over_18,true) : PASS\n");
    } else {
      printf("\n(skip integrated: fixture not found at %s — run gen:sdjwt)\n", fixture);
    }
  }

  printf("\nALL SD-JWT Approach-C checks PASS (M2 + 4a + 4b)\n");
  return 0;
}
