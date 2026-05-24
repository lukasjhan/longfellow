# Longfellow-ZK Source Code Analysis Report

> Analyzed target: `google/longfellow-zk` (commit `c849531`, main as of 2026-05-23)
> Location: `/home/unknown/longfellow/longfellow-zk`
> Date: 2026-05-23

---

## 1. At-a-Glance Summary (TL;DR)

**Longfellow** is a C++ library released by Google **for applying zero-knowledge proofs (ZK) to credentials without changing existing identity standards (ISO mdoc/mDL, JWT, W3C VC)**. The core challenge is "proving in ZK an **ECDSA-signed** credential that is already deployed worldwide, without revealing the signature," and to address it the library combines two well-vetted building blocks.

- **Sumcheck protocol** (zero-knowledge variant) — an interactive proof (IP) that proves the correct computation of an arithmetic circuit `C(x,w)=0`
- **Ligero argument system** — a commitment + ZK argument that requires no trusted setup and assumes only a collision-resistant hash (SHA-256)

The entire system has **no trusted setup**, has **no complex assumptions beyond a collision-resistant hash**, and targets performance of ~60ms for an ECDSA proof / ~1.2s for the full mdoc presentation flow (mobile).

- Name origin: the **Longfellow Bridge** in front of Google's Cambridge office
- Paper: [Anonymous credentials from ECDSA (ePrint 2024/2010)](https://eprint.iacr.org/2024/2010), Matteo Frigo & abhi shelat (Google)
- Standardization: [IETF draft-google-cfrg-libzk](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)

---

## 2. The Problem Being Solved

Existing anonymous credential schemes (BBS+, CL signatures, etc.) require **new cryptographic assumptions and new signature schemes**. That is, the entire issuer (government/institution) infrastructure must be replaced. Real-world mobile driver's licenses (mDL), e-passports, etc. are almost all signed with **ECDSA (P-256)**, so the key is to add privacy while leaving this legacy intact.

Longfellow's approach: **express "the ECDSA signature verification algorithm itself" as an arithmetic circuit**, and prove in ZK that "I know a valid signature that verifies under this public key, and a specific attribute within it (e.g., age≥18) holds." The verifier does not see the signature, name, or date of birth and only obtains the fact that **"the proof passed."** Furthermore, a new proof is generated each time, which also prevents tracking (linkability).

---

## 3. Overall Architecture

### 3.1 5-Stage Protocol (Concept)

The Overview section at `docs/specs/libzk.md:328` defines the full flow.

1. **Commit**: the prover commits to all witness values (= private inputs + one-time pads).
2. **Encrypted sumcheck**: the prover runs sumcheck on the witness, but sends the resulting polynomials/claims to the verifier **with one-time pads subtracted element by element (encryption)**. The verifier cannot verify directly because it does not know the pads.
3. **Constraint generation**: both prover and verifier construct **linear/quadratic constraints** from the public inputs + encrypted proof. The form is "if these constraints are satisfied, the sumcheck verifier would have accepted."
4. **Ligero proof**: the prover proves with the commitment and witness that the stage-3 constraints are satisfied.
5. **Verification**: the verifier performs final verification with the stage-4 proof + stage-3 constraints.

> Stages 2-3 are called "sumcheck," and stages 4-5 are called the "commitment scheme." The commitment is modularized so that something other than Ligero can be swapped in.

The core insight of this design (`lib/zk/zk_prover.h:38`):
> The sumcheck **verifier** essentially only does "checking the evaluation of a degree-2/3 polynomial + one multiplication per layer," so this simple verification logic can be reduced to constraints that Ligero proves. (Similar to the observation in the Hyrax paper, but Hyrax is elliptic-curve based, whereas here Ligero is used.)

### 3.2 Directory Structure (`lib/`)

| Directory | Role |
|---|---|
| `algebra/` | Finite field arithmetic — `Fp256` (P-256 base field), `f_128`=GF(2^128), FFT/NTT, CRT, interpolation, convolution |
| `gf2k/` | GF(2^128)-specific implementation (extend based on additive FFT) |
| `ec/` | Elliptic curves — `p256.h`, `p256k1.h` (P-256, secp256k1) |
| `sumcheck/` | Layered circuit sumcheck prover/verifier, quad representation |
| `ligero/` | Ligero commit/prove/verify, parameters |
| `merkle/` | Merkle tree for the Ligero commitment (batched inclusion proof) |
| `zk/` | Higher-level ZK wrapper that ties the above two together (`ZkProver`, `ZkVerifier`, `ZkProof`) |
| `circuits/` | Circuit building blocks (ECDSA, SHA-256, CBOR, MAC, mdoc, compiler, logic) |
| `random/` | Fiat-Shamir transcript (random oracle), secure RNG |
| `arrays/` | Witness containers such as `Dense`/`DenseFiller` |
| `cbor/`, `proto/`, `util/` | CBOR serialization, proto, logging/panic utilities |

---

## 4. Core Operating Principles (Cryptographic Layer)

### 4.1 Sumcheck (Zero-Knowledge Variant) — `docs/specs/sumcheck.md`, `lib/sumcheck/`

**Layered circuit model**: a circuit is composed of `NL` layers, and layer `j` computes the output wires `V[j]` from the input wires `V[j+1]`. `V[0]` is the final output, and **if all output wires are 0, the theorem is considered true** (`sumcheck.md:124`).

The computation of each layer is represented by a **quad** (3-dimensional sparse array):
```
V[j][g] = Σ_{l,r} Q[j][g,l,r] · V[j+1][l] · V[j+1][r]
```
That is, every gate has the form "products of two input wires multiplied by a constant and summed" (`sumcheck.md:130`).

**In-circuit assertion optimization** (`sumcheck.md:149`): copying the output=0 check up to the output layer incurs large overhead, so for each layer there are two quads, `Q` (general computation) and `Z` (a quadratic that must be 0), combined with a random `beta` as `QZ = Q + beta·Z` to check them at once. The two quads are disjoint and `Z` is binary, so they can be compactly represented as a single `(g,l,r,v)` 4-tuple (`v=0` means Z, `v≠0` means Q).

**Encryption/deferred verification** (`sumcheck.md:224`): the polynomials/claims produced by sumcheck are not given to the verifier in plaintext; instead, they are sent **with one-time pads subtracted**. Rather than verifying directly, the verifier converts them into **linear/quadratic constraints** over the private inputs and pad values and defers verification to Ligero.

**Polynomial representation optimization** (`sumcheck.md:198`): every round polynomial is **degree 2** and is represented by the evaluations at the three points `P0=0, P1=1, P2`. Because of the identity `p(P0)+p(P1)=the previous claim`, **only `p(P0)` and `p(P2)` are transmitted** and `p(P1)` is reconstructed. → In the code this appears as the "P(1) optimization" where `fill_pad` generates a pad only when `k!=1` (`lib/zk/zk_prover.h:156`, `:168`).

> P2 selection: in fields of characteristic >2, `P2=2`; in GF(2^128), `inj(2)` (`sumcheck.md:205`).

### 4.2 Ligero Commitment & Argument — `docs/specs/ligero.md`, `lib/ligero/`

Ligero [Ames-Hazay-Ishai-Venkitasubramaniam, ePrint 2022/1608] is a sublinear argument **with no trusted setup**. Longfellow uses it not for proving arbitrary circuits but **to directly prove the linear/quadratic constraints produced by the sumcheck verifier above**.

**Commitment structure** (`ligero.md:180`):
- The witness vector `W` is laid out as a **2D tableau matrix `T[NROW][NCOL]`**. Each row is `[random pad NREQ | witness values WR | polynomial evaluations ...]`. Mixing random pads into the rows provides **zero-knowledge**.
- The first 3 rows are random rows for ZK (for the low-degree test, for the linear test, for the quadratic test).
- Reed-Solomon `extend` (low-degree encoding) is applied to each row.
- **The Merkle tree is built over the "columns," not the rows** (`ligero.md:234`). The commitment = the Merkle root.

**Subfield optimization** (`ligero.md:220`): if a row's witness all lies in a subfield (GF(2^16)), the randomness is also drawn from the subfield to reduce the serialization size to 16 bits. → The `subfield_boundary` handling in `ZkProver::commit` (`lib/zk/zk_prover.h:85`).

**Three kinds of proofs** (`ligero.md:314`):
1. **Low-degree test**: take a linear combination of the rows using the verifier challenge `u` and confirm it is an RS codeword.
2. **Linear constraint test (dot proof)**: confirm constraints of the form `A·W = b` all at once via a random combination `alpha_l`.
3. **Quadratic constraint test (quadratic proof)**: reduce constraints `W[x]·W[y]=W[z]` by making `Qx,Qy,Qz` rows that copy the witness, into a linear constraint "the copy is correct" plus the product check "Qz=Qx⊗Qy".

Finally, the verifier opens `NREQ` randomly chosen columns and confirms consistency with all the above messages. **The Merkle inclusion proofs are batch-compressed** (removing duplicate sibling nodes) before being sent (`ligero.md:46`).

Default parameters (`lib/circuits/mdoc/mdoc_zk.h:33`):
- v6 and below: `rate=4`, `NREQ=128` → 86-bit+ statistical security
- v7 and above: `rate=7`, `NREQ=132` → ~109-bit statistical security

### 4.3 Fiat-Shamir (Non-Interactivity) — `docs/specs/libzk.md:136`, `lib/random/`

To turn the interactive IP into a **single message**, the Fiat-Shamir transform is used. A transcript object accumulates prover messages with a collision-resistant hash `H` (SHA-256) and derives verifier challenges from it. Each message also includes its **type and length** so that each query maps to a unique transcript (`libzk.md:143`). It also follows the best practice of setting the random oracle's circuit depth/gate count larger than the target circuit `C` to avoid correlation-intractability attacks (`libzk.md:141`).

### 4.4 Finite Fields & FFT — `lib/algebra/`, `lib/gf2k/`

- **`Fp256Base`**: P-256 base field (for signature/ECDSA circuits).
- **`f_128` = GF(2^128)**: `GF(2)[x]/(x^128+x^7+x^2+x+1)`, with `x` as the multiplicative-group generator (for hash/SHA circuits). Serialization is reduced via the subfield GF(2^16) (`libzk.md:107`).
- **extend (RS encoding)**: in prime fields, interpolation/NTT/Nussbaumer convolution; in GF(2^k), an efficient implementation using **Lin et al.'s additive FFT** (novel polynomial basis) (`libzk.md:96`).
- `f2_p256` + `FftExtConvolutionFactory`: extension field/FFT for the RS factory over P-256 (`mdoc_zk.cc:474`).

---

## 5. Circuit Layer (`lib/circuits/`)

The "theorems" that ZK actually proves are all arithmetic circuits. Longfellow implements every operation needed for mdoc verification as a circuit.

### 5.1 Circuit Compiler — `circuits/compiler/`
Compiles high-level arithmetic operations into a sumcheck-compatible **QuadCircuit** (`QuadCircuit` in `compiler.h`). Each gate has the form `Σ(w_left·w_right·const)`. Optimizations: constant folding, common subexpression elimination (CSE), linear-term optimization, layer-depth-minimizing scheduling. Reports output metadata such as `depth/nwires/nquad_terms`.

### 5.2 Logic / Bit Operations — `circuits/logic/`
Abstracts bit/vector operations over the field (`Logic` in `logic.h`). Core types:
- `EltW` (field-element wire), `BitW` (bit wire, using the `c0 + c1·x` change-of-basis to make XOR etc. efficient), `bitvec<N>` (= `v8/v32/v64/v128/v256`).
- Operations: `add/sub/mul/axpy`, bit logic `land/lor/lxor/lnot`, shift/rotate `shl/shr/ror/rol`, vector `vappend/vextract/veq/vlt` (range check).
- `bit_plucker.h` (field element → bit extraction/packing), `bit_adder.h` (mod 2^32 addition, for SHA), `counter.h` (CBOR cumulative scan).

### 5.3 ECDSA Verification Circuit — `circuits/ecdsa/`
Implements P-256 ECDSA verification in the form of a **triple scalar multiplication** (`VerifyCircuit` in `verify_circuit.h`, `VerifyWitness3` in `verify_witness.h`). It groups the verification equation into the form `g·e + pk·r + R·(-s) = identity`:
- **Precomputed table**: the 8 combination points of `{g, pk, R}` are precomputed, and one point is selected using 3 bits of the scalar at a time.
- **Intermediate-point witnesses provided**: each intermediate result of the loop is given as a witness to reduce circuit depth.
- **Complete addition formula** (exception-free Weierstrass addition).
- Range checks for `r,s ≠ 0` and `r,s < order`.

### 5.4 SHA-256 Circuit — `circuits/sha/`
A "flattened" arithmetic circuit of SHA-256 (`FlatSHA256Circuit` in `flatsha256_circuit.h`). All 64 rounds are unrolled into the circuit, but the message schedule `W[16..63]` and each round state are received as witnesses to verify. The round function (`T1,T2`, Ch/Maj/Σ) and mod 2^32 addition (`BitAdder`) are circuitized. Bit packing trades off smaller input size (↑ depth).

### 5.5 CBOR Parser Circuit — `circuits/cbor_parser/`, `cbor_parser_v2/`
Because mdoc is encoded in **CBOR**, the circuit parses CBOR internally to attest "where a specific attribute is / what its value is." v1 is based on a segmented scan (cumulative length); **v2 is based on `UnaryPlucker`, removing unnecessary scans** to improve efficiency. At each byte position it interprets the header (type/length) and tracks element boundaries.

### 5.6 MAC Circuit — `circuits/mac/`
Verifies the MAC of a 256-bit message over GF(2^128) (`mac_circuit.h`). The form is `mac[i] = (a_p[i] + a_v)·x[i]`. `a_p` is the key committed by the prover, and **`a_v` is the verifier randomness**. The forgery success probability is ≤ 2^-128. Its purpose is to be the **glue that links the two circuits (signature/hash)** (see section 6 below).

### 5.7 mdoc Integration Circuit — `circuits/mdoc/`
Ties the above blocks together to circuitize the full mdoc verification.
- `mdoc_signature.h`: issuer (MSO)/device ECDSA signature verification.
- `mdoc_hash.h`: mdoc hash computation + confirming that the hash of the requested attribute exists in the MSO's attribute digest map. **age_over_18**-type proofs happen here.
- `mdoc_witness.h` (`ParsedMdoc`, `FullAttribute`): mdoc parsing / witness filling.
- `zk_spec.cc`: registry of supported circuit versions (system name, circuit hash, attribute count, rate/nreq parameters).
- `circuit_maker.cc` / `mdoc_generate_circuit.cc`: generate a circuit once and store it as a cache (compressed bytes) → reused by prover/verifier.

---

## 6. Core Design: "Two Circuits + MAC Glue" (Implementation Analysis)

Looking at `run_mdoc_prover` (`:394`) / `run_mdoc_verifier` (`:538`) in `lib/circuits/mdoc/mdoc_zk.cc`, the most important architecture is that **two independent circuits over two different fields are proved simultaneously** and linked by a MAC.

| | signature circuit | hash circuit |
|---|---|---|
| field | `Fp256Base` (P-256) | `f_128` (GF(2^128)) |
| responsibility | ECDSA signature verification | SHA-256 hash + CBOR attribute extraction |
| why split? | ECDSA is natural in P-256 arithmetic | hash/bit operations are far cheaper in GF(2^128) |

**Why is a MAC needed?** It must be guaranteed that the two circuits handle "the same message hash `e` / the same device key." One side is Fp256 and the other is GF(2^128), so they cannot directly share the same value; therefore, **a MAC over the common value (common) is placed in both circuits to make them match**.

Implementation flow (prover, `mdoc_zk.cc:419`~`535`):
1. `decompress` the cached compressed circuit bytes, then parse the two circuits `c_sig` (P256) and `c_hash` (GF2_128) with `CircuitReader`.
2. Fill the witnesses of the two circuits (`W_sig`, `W_hash`) with `fill_witness` — the results of mdoc parsing/signature/hash/attribute extraction.
3. Commit to the witness+pad of each circuit with `ZkProver.commit` (`:487`, `:488`).
4. **After committing**, draw the verifier challenge `av = generate_mac_key(tp)` from the transcript, compute the MAC `compute_macs` of the common value, and inject it into the two witnesses (`update_macs`, `:500`~`:504`). ← the step that links the two circuits.
5. Generate proofs for hash and sig respectively with `ZkProver.prove` (`:506`, `:511`).
6. Serialization: `[6 MACs] [hash proof] [sig proof]` (`:517`~`:524`).

The verifier (`mdoc_zk.cc:608`~`690`) does the symmetric thing: read the 6 MACs → parse the two proofs → `recv_commitment` → derive `av` identically → construct the public inputs with `fill_public_inputs` (here pk, transcript, requested attributes, now, docType, and the MACs go in) → `hash_v.verify` && `sig_v.verify`. **Both must pass** to succeed.

The internals of `ZkProver::prove` (`lib/zk/zk_prover.h:102`) perform exactly the 5 stages of section 4:
- After computing all wires with `eval_circuit`, confirm that the outputs are all 0 (`:117`).
- Run the **encrypted sumcheck** with `super::prove(...)`.
- Generate the linear/quadratic constraint matrix `A` and vector `b` with `verifier_constraints` (`:134`).
- Generate the **Ligero proof** with `lp_->prove(...)` (`:144`).

---

## 7. Public C API (Integration Point)

`lib/circuits/mdoc/mdoc_zk.h` defines the C interface to be called from the outside (e.g., Android gmscore, Google Wallet):

- `generate_circuit(zk_spec, &cb, &clen)` — generate and compress a circuit matching the attribute count. Build once and cache.
- `run_mdoc_prover(circuit, mdoc, pkx,pky, transcript, attrs[], now, &prf, &len, zk_spec)` — generate a proof. Fails if `now` falls outside the validFrom/validUntil range.
- `run_mdoc_verifier(circuit, pkx,pky, transcript, attrs[], now, proof, len, docType, zk_spec)` — verify.
- `RequestedAttribute{namespace, id, cbor_value}` — the attribute the verifier requires (the value is raw CBOR bytes). Examples: `{"age_over_18", ...}`, `{"family_name","Mustermann"}`, `{"birth_date","1971-09-01"(tag 0xD9 03EC 6A)}` (`mdoc_zk.h:150`).
- `ZkSpecStruct` — a version-negotiation structure bundling the system name ("longfellow-libzk-v*"), circuit hash, attribute count, version, and block parameters. The prover/verifier negotiate the version in advance (`mdoc_zk.h:114`). Currently `kNumZkSpecs=12` specs are hardcoded.

---

## 8. Performance & Security Considerations

**Performance** (per the paper/official materials)
- ECDSA ZK proof generation: ~60ms
- Full ZK proof of the ISO mdoc presentation flow: ~1.2s (mobile, varies with credential size)
- Circuit scale (examples): ECDSA verification circuit depth 7 / wires ~21k / multiplications ~14k, SHA-256 depth 7 / wires ~38k.

**Security assumptions/characteristics**
- **No trusted setup, no CRS** — deliberately excluding many SNARK-type schemes (`libzk.md:42`).
- **Assumes only a collision-resistant hash (SHA-256)** — no other complex assumptions.
- Fiat-Shamir soundness: depends on round-by-round soundness + the correlation-intractability of the random oracle (`libzk.md:139`).
- Statistical security: tunable via parameters (rate, NREQ) — ~109 bits at v7.
- **Two independent security audits** in progress (academic/industry panel; reports published on the official Reviews page).

**Version compatibility**: if the circuit gates change, a new circuit hash must be added to `zk_spec`, and if the witness layout changes, version-branching code must be added (`circuits/mdoc/README.md`).

---

## 9. Standardization & Ecosystem

- **IETF**: being specified at CFRG as `draft-google-cfrg-libzk` ("libzk: A C++ Library for Zero-Knowledge Proofs"). `docs/specs/` is the working file for it.
- **Europe (EUDI)**: the Dyne.org Foundation maintains a European edition (dyne/longfellow-zk), used in EUDI ARF / age-verification solutions.
- **Google Wallet**: planned for application to online age verification based on government-issued digital ID.
- Integrates with the digital credential SDK ecosystem such as the **OpenWallet Foundation Multipaz**.

---

## 10. Build & Run Instructions

Dependencies: `clang, cmake, openssl, zstd, googletest, googlebenchmark` (see README).

```bash
# Dependencies (Ubuntu/Debian)
sudo apt install -y clang cmake libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev

# Build
CXX=clang++ cmake -D CMAKE_BUILD_TYPE=Release -S lib -B clang-build-release --install-prefix ${PWD}/install
cd clang-build-release && make -j 16 && ctest -j 16

# Benchmark example
./algebra/fft_test --benchmark_filter='BM_*'
./circuits/sha/flatsha256_circuit_test --benchmark_filter=BM_ShaZK_fp2_128
```
> A `.devcontainer` is present, so you can build/benchmark immediately in GitHub Codespaces (being a VM, performance figures may be lower).

---

## 11. Related Papers & Resources (stored at: `../references/`)

| Resource | Description | Notes |
|---|---|---|
| **Anonymous credentials from ECDSA** (ePrint 2024/2010) | The original Longfellow paper. Frigo & shelat (Google). ECDSA ZK via sumcheck+Ligero | `references/2024-2010_Anonymous-credentials-from-ECDSA.pdf` |
| **Ligero** (ePrint 2022/1608) | Sublinear argument with no trusted setup. The commitment+ZK foundation | `references/2022-1608_Ligero.pdf` |
| **Novel polynomial basis / Additive FFT** (arXiv 1404.3458) | The basis for the efficient GF(2^k) extend implementation (Lin, Chung, Han 2014) | `references/1404.3458_Additive-FFT_Lin-et-al.pdf` |
| IETF draft-google-cfrg-libzk | Specification draft | `longfellow-zk/docs/specs/` (local working copy) |
| Fiat-Shamir from Simpler Assumptions (ePrint 2018/1004) | Theoretical basis for FS soundness | See link |
| Official documentation | https://google.github.io/longfellow-zk/ | Includes Reviews (security audits) |

---

## 12. Conclusion

Longfellow-ZK is an engineering masterpiece that achieves the practical goal of "**leaving the legacy ECDSA identity infrastructure intact while layering on privacy (selective disclosure / non-traceability)**," **using only a hash assumption with no trusted setup**. The essence of the design is:

1. **Module separation** — (encrypted) sumcheck IP + Ligero commitment, with a swappable commitment.
2. **Verifier reduction** — instead of complex ZK, prove the simple constraints of "the sumcheck verifier logic" with Ligero.
3. **Two circuits + MAC** — ECDSA implemented optimally in the P-256 field and hash/bit operations in the GF(2^128) field, linked by a MAC.
4. **Circuit caching / version negotiation** — generate the circuit once and cache it compressed, negotiating the version via `ZkSpec`.

In the SD-JWT VC / mdoc / digital wallet context that hopae deals with, this library is a direct reference implementation for the scenario of **"adding ZK selective disclosure without changing the issuer."**
