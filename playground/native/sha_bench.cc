// Micro-benchmark: build the SAME "K SHA-256 blocks" circuit over Fp256 vs
// GF(2^128) and compare circuit size. This quantifies why mdoc (which does its
// hashing in GF(2^128)) is so much smaller than our single-field Fp256 SD-JWT
// circuit — and how much a two-field split would save.

#include <cstdint>
#include <cstdio>
#include <vector>

#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "proto/circuit_io.h"
#include "proto/circuit_writer.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include <zstd.h>

namespace proofs {
namespace {

template <class Field>
void bench(const char* name, const Field& F, FieldID fid, size_t nblocks) {
  using CB = CompilerBackend<Field>;
  using LC = Logic<Field, CB>;
  using v8 = typename LC::v8;
  using v256 = typename LC::v256;
  using FlatSHA = FlatSHA256Circuit<LC, BitPlucker<LC, 4>>;
  using SBW = typename FlatSHA::BlockWitness;

  QuadCircuit<Field> Q(F);
  const CB cbk(&Q);
  const LC L(&cbk, F);

  std::vector<v8> pre(64 * nblocks);
  for (auto& b : pre) b = L.template vinput<8>();
  v256 ebits = L.template vinput<256>();
  std::vector<SBW> sha(nblocks);
  for (auto& s : sha) s.input(L);
  v8 nb = L.template vinput<8>();

  FlatSHA sh(L);
  sh.assert_message_hash(nblocks, nb, pre.data(), ebits, sha.data());
  auto C = Q.mkcircuit(/*nc=*/1);

  std::vector<uint8_t> bytes;
  CircuitWriter<Field> w(F, fid);
  w.to_bytes(*C, bytes);

  std::vector<uint8_t> comp(ZSTD_compressBound(bytes.size()));
  size_t csz = ZSTD_compress(comp.data(), comp.size(), bytes.data(), bytes.size(), 6);

  printf("  %-10s blocks=%2zu  ninputs=%7zu  nl=%2zu  raw=%6zu KB  zstd=%5zu KB\n",
         name, nblocks, C->ninputs, C->nl, bytes.size() / 1024, csz / 1024);
}

}  // namespace
}  // namespace proofs

int main() {
  using namespace proofs;
  set_log_level(ERROR);
  GF2_128<> Fs;
  printf("SHA-256 circuit size: Fp256 (소수체) vs GF(2^128) (이진체)\n");
  for (size_t k : {1u, 4u, 18u}) {
    bench<Fp256Base>("Fp256", p256_base, P256_ID, k);
    bench<GF2_128<>>("GF(2^128)", Fs, GF2_128_ID, k);
    printf("\n");
  }
  return 0;
}
