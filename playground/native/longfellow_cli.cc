// longfellow_cli — thin CLI wrapper around the longfellow-zk mdoc C API.
//
// Commands:
//   export-example --index N --outdir DIR
//       Dump a bundled (already ECDSA-issued) example mdoc + session
//       transcript + issuer public key to files. This represents the
//       "issued credential" that a wallet would hold.
//
//   gencircuit --attrs N --out FILE
//       Generate (and zstd-compress) the ZK circuit for N attributes.
//       Prints a JSON spec line {system, circuit_hash, num_attributes,
//       version, circuit_len} on stdout. Run once and cache.
//
//   prove  --circuit F --mdoc F --pkx HEX --pky HEX --transcript F
//          --now STR --doctype STR --system STR --circuit-hash STR
//          --attr ns:id:hexval [--attr ...] --out F
//       Produce a ZK presentation proof for the requested attribute(s).
//
//   verify --circuit F --pkx HEX --pky HEX --transcript F --now STR
//          --doctype STR --system STR --circuit-hash STR
//          --attr ns:id:hexval [--attr ...] --proof F
//       Verify a ZK presentation proof. Exit 0 == accepted.
//
// All "result" output is a single JSON object on stdout so Node can parse it.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "circuits/mdoc/mdoc_examples.h"  // proofs::mdoc_tests[]
#include "circuits/mdoc/mdoc_zk.h"        // public C API

namespace {

// ---------- small helpers ----------

[[noreturn]] void die(const std::string& msg) {
  fprintf(stderr, "longfellow_cli: %s\n", msg.c_str());
  exit(2);
}

std::vector<uint8_t> read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) die("cannot open file for read: " + path);
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
}

void write_file(const std::string& path, const uint8_t* data, size_t len) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) die("cannot open file for write: " + path);
  f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
  if (!f) die("write failed: " + path);
}

std::vector<uint8_t> hex_decode(const std::string& in) {
  std::string s;
  s.reserve(in.size());
  for (char c : in) {
    if (c == ' ' || c == '\n' || c == '\t' || c == '\r') continue;
    s.push_back(c);
  }
  if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    s = s.substr(2);
  if (s.size() % 2 != 0) die("hex string has odd length");
  auto nyb = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  std::vector<uint8_t> out;
  out.reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2) {
    int hi = nyb(s[i]), lo = nyb(s[i + 1]);
    if (hi < 0 || lo < 0) die("invalid hex character");
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

std::string json_escape(const std::string& s) {
  std::string o;
  for (char c : s) {
    if (c == '"' || c == '\\') {
      o.push_back('\\');
      o.push_back(c);
    } else {
      o.push_back(c);
    }
  }
  return o;
}

// Minimal flag parser: collects --key value pairs and repeated --attr.
struct Args {
  std::vector<std::pair<std::string, std::string>> kv;
  std::string get(const std::string& key, const std::string& def = "") const {
    for (auto& p : kv)
      if (p.first == key) return p.second;
    return def;
  }
  bool has(const std::string& key) const {
    for (auto& p : kv)
      if (p.first == key) return true;
    return false;
  }
  std::vector<std::string> all(const std::string& key) const {
    std::vector<std::string> r;
    for (auto& p : kv)
      if (p.first == key) r.push_back(p.second);
    return r;
  }
};

Args parse_args(int argc, char** argv, int start) {
  Args a;
  for (int i = start; i < argc; i++) {
    std::string k = argv[i];
    if (k.rfind("--", 0) != 0) die("expected --flag, got: " + k);
    if (i + 1 >= argc) die("flag missing value: " + k);
    a.kv.emplace_back(k.substr(2), argv[++i]);
  }
  return a;
}

// Build a RequestedAttribute from "namespace:id:hexvalue".
RequestedAttribute parse_attr(const std::string& spec) {
  size_t c1 = spec.find(':');
  size_t c2 = (c1 == std::string::npos) ? std::string::npos
                                        : spec.find(':', c1 + 1);
  if (c1 == std::string::npos || c2 == std::string::npos)
    die("--attr must be 'namespace:id:hexvalue', got: " + spec);
  std::string ns = spec.substr(0, c1);
  std::string id = spec.substr(c1 + 1, c2 - c1 - 1);
  std::vector<uint8_t> val = hex_decode(spec.substr(c2 + 1));

  RequestedAttribute ra;
  memset(&ra, 0, sizeof(ra));
  if (ns.size() > sizeof(ra.namespace_id)) die("namespace too long");
  if (id.size() > sizeof(ra.id)) die("id too long");
  if (val.size() > sizeof(ra.cbor_value)) die("cbor value too long");
  memcpy(ra.namespace_id, ns.data(), ns.size());
  memcpy(ra.id, id.data(), id.size());
  memcpy(ra.cbor_value, val.data(), val.size());
  ra.namespace_len = ns.size();
  ra.id_len = id.size();
  ra.cbor_value_len = val.size();
  return ra;
}

std::vector<RequestedAttribute> parse_attrs(const Args& a) {
  std::vector<RequestedAttribute> v;
  for (auto& s : a.all("attr")) v.push_back(parse_attr(s));
  if (v.empty()) die("at least one --attr is required");
  return v;
}

// Pick the highest-version ZkSpec that supports `nattr` attributes.
const ZkSpecStruct* latest_spec_for(size_t nattr) {
  const ZkSpecStruct* best = nullptr;
  for (size_t i = 0; i < kNumZkSpecs; i++) {
    if (kZkSpecs[i].num_attributes != nattr) continue;
    if (best == nullptr || kZkSpecs[i].version > best->version)
      best = &kZkSpecs[i];
  }
  return best;
}

long now_ms() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch())
      .count();
}

// ---------- commands ----------

int cmd_export_example(const Args& a) {
  size_t index = a.has("index") ? std::stoul(a.get("index")) : 0;
  std::string outdir = a.get("outdir");
  if (outdir.empty()) die("--outdir required");
  size_t n = sizeof(proofs::mdoc_tests) / sizeof(proofs::mdoc_tests[0]);
  if (index >= n) die("index out of range (0.." + std::to_string(n - 1) + ")");

  const proofs::MdocTests& t = proofs::mdoc_tests[index];
  write_file(outdir + "/mdoc.bin", t.mdoc, t.mdoc_size);
  write_file(outdir + "/transcript.bin", t.transcript, t.transcript_size);

  // issued.json describes the credential + session for the Node side.
  std::string j = "{";
  j += "\"index\":" + std::to_string(index);
  j += ",\"pkx\":\"" + json_escape(t.pkx.as_pointer) + "\"";
  j += ",\"pky\":\"" + json_escape(t.pky.as_pointer) + "\"";
  j += ",\"now\":\"" + json_escape((const char*)t.now) + "\"";
  j += ",\"doctype\":\"" + json_escape(t.doc_type) + "\"";
  j += ",\"mdoc_size\":" + std::to_string(t.mdoc_size);
  j += ",\"transcript_size\":" + std::to_string(t.transcript_size);
  j += "}";
  write_file(outdir + "/issued.json",
             reinterpret_cast<const uint8_t*>(j.data()), j.size());

  printf("%s\n", j.c_str());
  return 0;
}

int cmd_gencircuit(const Args& a) {
  if (!a.has("attrs")) die("--attrs required");
  size_t nattr = std::stoul(a.get("attrs"));
  std::string out = a.get("out");
  if (out.empty()) die("--out required");

  const ZkSpecStruct* spec = latest_spec_for(nattr);
  if (spec == nullptr) die("no ZkSpec supports " + std::to_string(nattr) +
                           " attributes");

  uint8_t* cb = nullptr;
  size_t clen = 0;
  long t0 = now_ms();
  CircuitGenerationErrorCode rc = generate_circuit(spec, &cb, &clen);
  long dt = now_ms() - t0;
  if (rc != CIRCUIT_GENERATION_SUCCESS) {
    printf("{\"ok\":false,\"code\":%d}\n", (int)rc);
    return 1;
  }
  write_file(out, cb, clen);
  free(cb);

  printf(
      "{\"ok\":true,\"system\":\"%s\",\"circuit_hash\":\"%s\","
      "\"num_attributes\":%zu,\"version\":%zu,\"circuit_len\":%zu,"
      "\"gen_ms\":%ld}\n",
      spec->system, spec->circuit_hash, spec->num_attributes, spec->version,
      clen, dt);
  return 0;
}

const ZkSpecStruct* resolve_spec(const Args& a) {
  std::string system = a.get("system");
  std::string hash = a.get("circuit-hash");
  if (system.empty() || hash.empty())
    die("--system and --circuit-hash are required");
  const ZkSpecStruct* spec = find_zk_spec(system.c_str(), hash.c_str());
  if (spec == nullptr) die("no matching ZkSpec for given system/circuit-hash");
  return spec;
}

int cmd_prove(const Args& a) {
  std::vector<uint8_t> circuit = read_file(a.get("circuit"));
  std::vector<uint8_t> mdoc = read_file(a.get("mdoc"));
  std::vector<uint8_t> transcript = read_file(a.get("transcript"));
  std::string pkx = a.get("pkx"), pky = a.get("pky");
  std::string now = a.get("now"), doctype = a.get("doctype");
  std::string out = a.get("out");
  if (pkx.empty() || pky.empty() || now.empty() || out.empty())
    die("--pkx --pky --now --out are required");
  const ZkSpecStruct* spec = resolve_spec(a);
  std::vector<RequestedAttribute> attrs = parse_attrs(a);

  uint8_t* prf = nullptr;
  size_t prf_len = 0;
  long t0 = now_ms();
  MdocProverErrorCode rc = run_mdoc_prover(
      circuit.data(), circuit.size(), mdoc.data(), mdoc.size(), pkx.c_str(),
      pky.c_str(), transcript.data(), transcript.size(), attrs.data(),
      attrs.size(), now.c_str(), &prf, &prf_len, spec);
  long dt = now_ms() - t0;

  if (rc != MDOC_PROVER_SUCCESS) {
    printf("{\"ok\":false,\"code\":%d,\"prove_ms\":%ld}\n", (int)rc, dt);
    return 1;
  }
  write_file(out, prf, prf_len);
  free(prf);
  printf("{\"ok\":true,\"proof_len\":%zu,\"prove_ms\":%ld}\n", prf_len, dt);
  return 0;
}

int cmd_verify(const Args& a) {
  std::vector<uint8_t> circuit = read_file(a.get("circuit"));
  std::vector<uint8_t> transcript = read_file(a.get("transcript"));
  std::vector<uint8_t> proof = read_file(a.get("proof"));
  std::string pkx = a.get("pkx"), pky = a.get("pky");
  std::string now = a.get("now"), doctype = a.get("doctype");
  if (pkx.empty() || pky.empty() || now.empty() || doctype.empty())
    die("--pkx --pky --now --doctype are required");
  const ZkSpecStruct* spec = resolve_spec(a);
  std::vector<RequestedAttribute> attrs = parse_attrs(a);

  long t0 = now_ms();
  MdocVerifierErrorCode rc = run_mdoc_verifier(
      circuit.data(), circuit.size(), pkx.c_str(), pky.c_str(),
      transcript.data(), transcript.size(), attrs.data(), attrs.size(),
      now.c_str(), proof.data(), proof.size(), doctype.c_str(), spec);
  long dt = now_ms() - t0;

  bool ok = (rc == MDOC_VERIFIER_SUCCESS);
  printf("{\"ok\":%s,\"code\":%d,\"verify_ms\":%ld}\n", ok ? "true" : "false",
         (int)rc, dt);
  return ok ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr,
            "usage: longfellow_cli <export-example|gencircuit|prove|verify> "
            "[--flags]\n");
    return 2;
  }
  std::string cmd = argv[1];
  Args a = parse_args(argc, argv, 2);
  if (cmd == "export-example") return cmd_export_example(a);
  if (cmd == "gencircuit") return cmd_gencircuit(a);
  if (cmd == "prove") return cmd_prove(a);
  if (cmd == "verify") return cmd_verify(a);
  die("unknown command: " + cmd);
}
