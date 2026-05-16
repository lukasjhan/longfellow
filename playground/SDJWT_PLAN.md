# SD-JWT-VC Zero-Knowledge Circuit Design (Approach C: Disclosure/`_sd` Membership)

Goal: go beyond longfellow's experimental JWT (substring) circuit and implement an **mdoc-grade** SD-JWT-VC ZK — all value types (string/date/boolean/number/nested) + **validity period (exp)** + Key Binding + standard selective disclosure.

## Why Membership Instead of Parsing

Neither mdoc nor SD-JWT **parses JSON/CBOR inside the circuit.** Both **salt+hash each claim** and put it into a signed digest set, and the proof is done by **membership** over that set.

| | mdoc | SD-JWT-VC |
|---|---|---|
| Claim unit | `IssuerSignedItem=[digestID,salt,id,value]` (CBOR) | `Disclosure=base64url([salt,name,value])` |
| Signed digest set | MSO `valueDigests` | payload `_sd` |
| Proof | SHA(item)∈valueDigests + (id,value) match | SHA(disclosure)∈`_sd` + (name,value) match |

→ Whatever the value is (boolean `true`, number `175`), it goes **entirely inside the hash unit**, so substring's prefix ambiguity (`18`⊂`180`) is eliminated at the source. (Reference implementation:
`src/decode-sdjwt.js`, data: `tools/gen-sdjwt.mjs` → `fixtures/`.)

## The Statement the Circuit Proves

Public input: issuer `pkX,pkY`, KB hash `e2`, `now`, and `(claimName, claimValueJSON)` for each requested disclosure.
Private witness: issuer JWT signature, payload preimage, each requested disclosure string and salt,
and the position indices.

1. **Issuer signature**: `ECDSA.verify3(pkX,pkY, e=SHA256(header.payload), jwt_sig)`
2. **Key Binding**: `ECDSA.verify3(dpkX,dpkY, e2, kb_sig)` (holder key `cnf.jwk`)
3. **Validity period**: extract `"exp":<digits>` from payload → convert to integer → `now ≤ exp`
4. **Each disclosure**:
   a. `digest = SHA256(ascii(disclosure))`
   b. **Membership**: the 32B obtained by base64url-decoding some entry of `_sd` == `digest` (that entry's position is
      inside the signed payload → guaranteed by the issuer signature)
   c. **Structural match**: base64url-decode `disclosure` → `["<salt>","<name>",<value>]` matches
      the requested `(name,value)` (salt is a variable-length witness, value is matched up to the closing `]`)

## longfellow Reuse / New

| Block | Reuse? | Source |
|---|---|---|
| ECDSA verify3 (×2) | ✅ | `circuits/ecdsa/verify_circuit.h` (used by jwt.h) |
| FlatSHA256 (header.payload, and disclosure hash) | ✅ | `circuits/sha/flatsha256_circuit.h` |
| base64url decode | ✅ | `circuits/tests/base64/decode.h` (used by jwt.h) |
| Routing/shift (align by index) | ✅ | `circuits/logic/routing.h` |
| Byte equality/`vlt`/`assert_implies` | ✅ | `circuits/logic/logic.h` |
| **`_sd` membership** (SHA==base64decode(entry)) | 🆕 | conceptually identical to mdoc `MdocHash`'s digest-membership |
| **Structural disclosure equality** (variable salt) | 🆕 | extension of jwt.h `assert_string_eq` |
| **exp integer parsing + comparison** | 🆕 | digit→value accumulation (×10) + `vlt` |

## Witness (prover-supplied) Essentials

- payload position/length (within the preimage)
- per requested disclosure: disclosure bytes, salt length, index of the matching entry within `_sd`,
  name/value offsets within the plaintext obtained by base64-decoding the disclosure
- position/digit count of the exp number

## Milestones (incremental, verifiable)

- **M1 ✅**: real SD-JWT-VC issuer + dependency-free reference verifier + design.
  `tools/gen-sdjwt.mjs`, `src/decode-sdjwt.js`, `fixtures/`.
- **M2 ✅** (eval): exp comparison subcircuit + EvaluationBackend harness. `native/sdjwt_eval.cc`.
- **M4-core ✅** (eval): SHA(disclosure) in-circuit + `_sd` membership (base64 decode+compare),
  legitimate accept/forged reject.
- **4a ✅** (eval): disclosure structural extraction `["salt","name",value]` (variable salt) — string/boolean/number.
- **4b ✅** (eval): **real fixture integration** — after locating the exp·`_sd` entry indices in the payload,
  exp+membership+structural extraction end-to-end PASS (including boolean). `pnpm run eval:sdjwt`.
- **M3 ✅** (real ZK): compile exp(M3a) + `_sd` membership(M3b) + structural extraction(M3c) with CompilerBackend
  → prove/verify ACCEPT with ZkProver/ZkVerifier (~1.4s, proof ~239KB). `native/sdjwt_zk.cc`.
  ZK works up to boolean `age_over_18:true`. (SHA witness declared/loaded as a circuit input.)
- **M5 ✅** (real ZK, full): compile issuer ES256 signature (VerifyWitness3 directly) + header.payload SHA +
  payload base64 decode + exp + `_sd` membership + structural extraction into **a single circuit**,
  ZK prove/verify on a real SD-JWT-VC fixture. `native/sdjwt_full.cc`, `pnpm run demo:sdjwt-zk`.
  - Proof: "issuer signature valid + not expired + age_over_18 ∈ _sd = **true (boolean)**" (signature·other
    claims·salt hidden). ACCEPT (proof ~408KB, ninputs ~31k, ~10s). REJECT when expired.
  - **Works even on a freshly issued new token** → the witness builder parses arbitrary real tokens.
  - KB (holder binding) is excluded (already working in jwt_cli; adding it is mechanical). To avoid dependence on the cnf format,
    VerifyWitness3 is used directly instead of JWTWitness.
- **M6a ✅** (real ZK): **simultaneous disclosure of multiple attributes** — NATTR(=3) disclosure slots, with (name,value) as
  a public input pattern. given_name(string)+age_over_18(boolean)+height(number) in one ZK proof.
- **M6b ✅** (real ZK): **Key Binding** — verify holder KB signature + bind dpk to the payload's cnf.jwk
  (base64-decode cnf.x/y in-circuit and compare against dpk bits). e2 is a public input.
  The issuer (gen-sdjwt) produces kbjwt. `pnpm run demo:sdjwt-zk`.
  → in one ZK proof, **issuer signature + KB + exp + 3-attribute membership** all ACCEPT (~461KB, ~13s), REJECT when expired.
- **M6c ✅** (real ZK): **sd_hash binding (canonical/in-circuit)** — the circuit verifies that the `sd_hash` signed by KB
  matches the actual presentation bundle. Chain: KB signature→e2→kb_pre(SHA==e2)→extract
  sd_hash from payload→`SHA(presented)==sd_hash`→the disclosed disclosures are contained in presented.
  → enforces "disclosed disclosure ⊆ presentation bundle signed by the holder". ACCEPT (proof ~572KB, ~27s), REJECT when expired.
- **M6d ✅** (real ZK): closing the gap relative to mdoc.
  - **vct verification**: compare the payload's `"vct":"<type>"` against a public input pattern (confirmed REJECT on wrong vct).
  - **variable multi-attribute N**: NATTR as a runtime parameter (vector). Works for 2·3·4 attributes. claims specified via argv.
  - **circuit caching**: zstd-compressed cache of the compiled circuit per N via CircuitWriter/Reader
    (`circuits-cache/sdjwt-<N>attr.bin`, 145MB→~3MB). On rerun, **compile ~23s → load ~0.4s**.
- **M7 ✅** (2-body split + MAC, mdoc architecture): split the monolithic single Fp256 circuit
  into **two circuits** like mdoc to gain performance. SHA/CBOR-like hash operations are ~5x cheaper on the binary field GF(2¹²⁸)
  than on the prime field Fp256 (measured with `native/sha_bench.cc`: 18 blocks 1181KB→236KB, prove 1412→283ms).
  - **M7-1 ✅** signature circuit (Fp256): reuse `MdocSignature` — issuer ES256 + holder KB ES256 +
    MAC of e/dpkx/dpky. `native/sdjwt_sig.cc` (ninputs 3739, prove ~200ms).
  - **M7-2 ✅** hash circuit (GF2¹²⁸): port SHA + exp + vct + cnf + sd_hash binding +
    N×(`_sd` membership + structural + consent) in full to GF(2¹²⁸). `native/sdjwt_hash.cc`
    (3-attribute ninputs 86723, prove ~720ms). zstd cache per nattr (99MB→948KB).
  - **M7-3 ✅** orchestration (`native/sdjwt_split.cc`): **soundly bind the two circuits via MAC**.
    Commit both sides into a shared transcript → derive `a_v` from the post-commit transcript →
    compute macs of common values (e/dpkx/dpky) → write into the committed public-input slots → prove/verify both sides.
    Because the witness (a_p) is independent of a_v, revealing a_v after commit is safe; the prover cannot pick a_v
    and so cannot feed different e into the two circuits (Schwartz-Zippel). e2 is a public input of both circuits.
    Bundle `[6 macs][hash proof][sig proof]`. **Tampering test** (`TAMPER=1`): when 1 bit of a mac is altered,
    both circuits confirmed REJECT. 3 attributes **prove(both) ~0.95s, bundle 353KB, ACCEPT**.
  - **Comparison**: monolithic (`sdjwt_full`) end-to-end ~6.6s vs split ~1.7s (≈4x), prove alone ~6x.
    Circuit cache 145MB→3MB (mono) vs 164KB+948KB (split).
- **M8 ✅** (production hardening): raise circuit constants to mdoc level **generously** + **a clear error on overflow**.
  - Constant increases: kMaxSHA 13→32 (payload 2KB), KBB 4→6, PB 18→40 (presented 2.5KB),
    MAXB 2→4 (disclosure 256B), MAXPAT 96→160, MAXVCT 80→128, LOGM 11→12.
    Applied identically to the three binaries (split/hash/full). Auto-invalidation via a geometry tag in the cache filename.
  - `check_capacity()`: validate header.payload/KB/presented SHA blocks, decoded payload, presented<2^LOGM,
    vct·disclosure pattern lengths on the host → a concrete error (exit 2) instead of a buffer overflow.
    (Corresponds to mdoc's `MDOC_PROVER_TAGGED_MSO_TOO_BIG`.)
  - **Large fixture verification**: issuing with `BIG=1` (13-attribute PID-grade, header.payload 20 blocks·presented 35 blocks —
    **would overflow under the old constants**) ACCEPTed via split. Demonstrated in step [5] of `demo:sdjwt-split`.
  - Cost: split 3-attribute prove ~0.95s→~1.6s (still ↓ monolithic), monolithic is ~13s (circuit 318MB,
    RAM 6.4GB) → the split advantage stands out even more, ~8x.
- **M9 (remaining/optional)**: W3C VC, public API/Node bindings, tidying single-bundle serialization/deserialization,
  size tiers (auto-select among multiple profiles), status/revocation·type metadata·alg flexibility.

> Current status: **achieved beyond mdoc parity + the same 2-body+MAC architecture as mdoc** — SD-JWT-VC
> selective-disclosure ZK works end-to-end on real tokens. All value types (boolean/number/date) + validity period (exp)
> + Key Binding + **sd_hash binding** + simultaneous multi-attribute disclosure via `_sd` membership without parsing, and
> **split into an Fp256 signature circuit + a GF(2¹²⁸) hash circuit, soundly bound via MAC** (prove ~4–6x faster).

## Risks / Effort

- The heaviest task (days to weeks). Requires circuit DSL · soundness review.
- Risk points: (a) base64 length/alignment boundaries, (b) variable salt length handling, (c) exp digit-count boundaries,
  (d) block count (length) of the disclosure SHA → circuit size.
- Mitigation: use the existing mdoc/jwt circuits as a reference frame, validate the logic before ZK with M2 (plaintext witness+eval).

## Open Decisions

- How KB's `e2` (KB message hash) is computed: externally provided as in current longfellow vs computed in-circuit.
- Upper bound on the disclosure max length/count (directly tied to circuit size).
- Upper bound on the number of `_sd` entries (membership search range).
