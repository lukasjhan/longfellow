# Longfellow ZK Playground (Node.js)

A playground that **calls `google/longfellow-zk`** (a C++ zero-knowledge library) **from Node.js** to
**issue → present (ZK proof) → verify** an mdoc.

```
Node.js ──spawn──▶ longfellow_cli (C++)  ──▶ longfellow-zk C API
        ◀── JSON ──┘
```

- Integration approach: **CLI subprocess** (no native addon/ABI required, the simplest option)
- Credential format: **mdoc (ISO 18013-5 mDL)** ✅
  - ※ longfellow has **no public API** for JWT/W3C VC (only experimental circuits exist). So this playground is mdoc-only.
- Example proof target: **`age_over_18 = true`** (name, date of birth, and signature stay hidden)

---

## ⚠️ Important to know: longfellow does NOT "issue" mdocs

longfellow only performs **ZK present/verify** on an **mdoc that is already signed with ECDSA**.
Therefore the "issue" step in this playground is simulated by pulling out an **example mdoc built into**
longfellow (already issued and signed). Real issuance (creating a new ECDSA mdoc)
is the job of a separate library (such as `@auth0/mdl`), and that is a next-step task
(see "Next steps" below).

---

## Prerequisites

- Node.js 18+ (tested: v24), `pnpm` (or npm)
- C++ build: `cmake`, `clang-17`, system `openssl`/`zstd`/`zlib` development headers

> **Toolchain note**: this machine's default `clang++` (Swift toolchain) cannot find
> `libstdc++`. `native/build.sh` works around this by automatically generating a
> wrapper (`../.toolchain/clang++w`) that wraps the system `clang-17` with `--gcc-install-dir`. If your GCC path differs,
> specify it via the `GCC_INSTALL_DIR` environment variable.

---

## Build & Run

```bash
cd playground

# 1) Build the C++ library + CLI (once, takes a few minutes)
pnpm run build:native        # == bash native/build.sh

# 2) Pre-generate and cache circuits per N (once, N=1~4 about 1 minute)
pnpm run circuits            # circuits/circuit-<N>attr.bin + manifest.json

# 3) Full-flow demo (issue → setup → present → verify → tamper-reject)
pnpm run demo                # ~2s when using the cache
```

> Circuits depend **only on the number of attributes N**, independent of the mdoc, so they are built once and reused.
> If you cache N=1~4 into `circuits/` with `pnpm run circuits`, subsequent present/verify
> pick a circuit from the cache instead of regenerating (~14s) each time (the whole demo ~2s). Even if you don't pre-build the circuits,
> the demo auto-generates and caches them when needed (`ensureCircuit`).

**Multi-attribute simultaneous proof** (example #3 = Sprind-Funke, holds 5 attributes):

```bash
pnpm run demo:multi                                  # family_name + age_over_18 (default)
node src/demo-multi.js 3 family_name,height,age_over_18   # mixed-type 3 attributes
```
It **extracts each attribute's raw CBOR value as-is** from the mdoc, discloses them all at once with a `--attrs N` circuit,
and also shows that forging just one attribute value gets rejected.

**SD-JWT(+KB) zero-knowledge proof** (longfellow's experimental JWT circuit):

```bash
pnpm run demo:jwt                                  # given_name=Erika (example 0)
node src/demo-jwt.js 1 family_name Mustermann      # different token/attribute
```
From a real SD-JWT-VC + Key Binding token (ES256 signature), it zero-knowledge discloses the **`"id":"value"` string attribute**.
The verifier verifies using only pk, e2, and attr, **without the raw token**.

> ⚠️ The JWT circuit is longfellow's **experimental** one (`circuits/tests/jwt`) and has no public API, so
> `native/jwt_cli.cc` builds the circuit directly to drive the ZK. Unlike mdoc, it can only prove **string
> attributes** (booleans/numbers like `age_over_18:true` are not possible). There is also no circuit cache, so
> prove/verify builds the circuit every time (~5s each).

#### ✅ mdoc-grade SD-JWT-VC selective disclosure ZK (Approach C)

Going beyond the substring limitation above, we implemented a real ZK circuit that supports
**all value types + validity period (exp) + vct + Key Binding + sd_hash binding + multi-attribute (variable N)**
via the **`_sd` Disclosure membership of standard SD-JWT-VC** (design: [`SDJWT_PLAN.md`](SDJWT_PLAN.md)).

```bash
pnpm run gen:sdjwt       # issue a real ES256 SD-JWT-VC → fixtures/ (deps: node_modules symlink)
pnpm run decode:sdjwt    # verify disclosure hash ∈ _sd without dependencies (plaintext reference of what the circuit does)
pnpm run eval:sdjwt      # eval-verify the new subcircuits (exp·SHA·membership·structural)
pnpm run demo:sdjwt-zk   # ⭐ real ZK: issue → present → verify (age_over_18=true), REJECT when expired
```

`demo:sdjwt-zk` prove/verifies in **a single ZK proof**: **issuer ES256 signature + holder Key Binding + sd_hash binding + vct +
`now≤exp` + 3 attributes (given_name·age_over_18·height = string·boolean·number) ∈ `_sd`**
(the signature, other claims, salt, and device key stay hidden).
The **booleans/numbers/dates** that the substring approach couldn't handle are all safe thanks to `_sd` membership (no parsing needed).

The number and kinds of disclosed attributes are runtime-variable (the circuit is compiled per N), and the compiled circuit is
zstd-compression-cached (`circuits-cache/sdjwt-<N>attr.bin`), skipping compilation (~23s) on re-runs:

```bash
# Direct call: <fixture> <issuer-jwk> <now> <comma-separated claims> <vct>
native/sdjwt_full fixtures/sdjwt.txt fixtures/issuer-jwk.json 1700000000 \
  "given_name,age_over_18" "https://credentials.example/pid"
```

> Key point: both mdoc and SD-JWT do selective disclosure via "per-claim salt+hash → membership in the signed digest set."
> The circuit building blocks (ECDSA·SHA·base64) are reused from longfellow; the new parts are membership·structural·exp.
> Key Binding verifies the holder signature and binds the device key to the payload's cnf.jwk, and
> with **sd_hash binding** (the canonical way) the circuit verifies `SHA(presentation bundle)==KB's sd_hash`
> to enforce "disclosed disclosures ⊆ the presentation bundle the holder signed" (preventing disclosure splicing).

#### ⚡ 2-circuit + MAC split (same architecture as mdoc)

The `sdjwt_full` above is a **single Fp256 circuit** (prime field), so SHA is expensive. Splitting the work into
**two circuits** like mdoc is much faster — because SHA/hash is ~5x cheaper on the binary field **GF(2¹²⁸)** than on Fp256
(measured directly with `native/sha_bench.cc`).

- **Signature circuit (Fp256)** `native/sdjwt_sig.cc`: issuer ES256 + holder KB ES256.
- **Hash circuit (GF2¹²⁸)** `native/sdjwt_hash.cc`: all of SHA + exp + vct + cnf + sd_hash +
  N×(`_sd` membership·structural·consent).
- **Binding** `native/sdjwt_split.cc`: binds the shared values e/dpkx/dpky **with a MAC**. Since `a_v` (half of the MAC
  key) is **derived from the transcript after commit**, the prover cannot put different values into the two circuits
  (sound). e2 is a public input of both circuits.

```bash
pnpm run demo:sdjwt-split             # ⭐ Node demo: issue → 2-circuit present+verify → expired/tampered/big-token
pnpm run gen:sdjwt-big                # issue a large 13-attribute PID-grade credential (fixtures/sdjwt-big.txt)
native/sha_bench                      # Fp256 vs GF(2^128) SHA circuit-size/time benchmark
native/sdjwt_split                    # 2-circuit present+verify (3 attributes), both ACCEPT
TAMPER=1 native/sdjwt_split           # tamper 1 bit of the mac → both circuits REJECT (proves the link is enforced)
```

Measurement (3 attributes): **prove(both) ~1.6s, bundle 386KB** (sig 194KB + hash 192KB). Compared to the single
`sdjwt_full` (~13s, end-to-end), this is **about 8x faster**. The circuit cache is also small: 164KB+1.7MB (split)
versus 318MB→6.5MB (single).

**Capacity is fixed (the nature of all ZK) but set generously** — `kMaxSHA=32` (payload 2KB)·`PB=40` (presented
2.5KB)·`MAXB=4` (disclosure 256B), etc., set at mdoc levels, and if a token exceeds them the host raises a
**clear error** instead of a buffer overflow (e.g., `... > kMaxSHA=32 (2048B)`, corresponding to mdoc's
`MDOC_PROVER_TAGGED_MSO_TOO_BIG`). The 13-attribute large token works too (demo step [5]).

You can also run step by step (state is saved to `artifacts/`):

```bash
pnpm run issue      # load example mdoc + generate ZK circuit (cache)
pnpm run present    # generate ZK proof → artifacts/proof.bin
pnpm run verify     # verify the proof (exit 0 if ACCEPT)

# Use a different example mdoc (0~23):  node src/playground.js issue 3
# View detailed C++ logs:               DEBUG=1 pnpm run demo
```

### Seeing what's inside an mdoc (`decode`)

Check the attributes the issuer signed in (= candidates that can be disclosed via ZK) (built-in CBOR
decoder with no dependencies):

```bash
pnpm run decode                       # decode artifacts/mdoc.bin
node src/decode-mdoc.js /path/x.bin   # any mdoc file
```

The output shows the issuer-signed attributes (id=value), the MSO's valueDigests count and validity period,
and whether deviceKey exists. Key point: the **MSO digest count ≥ the number of IssuerSignedItems actually
present** is possible, and a ZK proof is only possible for **attributes whose preimage (IssuerSignedItem)
exists**.

### Expected output (gist)

```
[1] ISSUE   issuer pkx, doctype=org.iso.18013.5.1.mDL, mdoc=1452 bytes
[2] SETUP   circuit v7, hash 8d079211…, 307873 bytes  (~14s, one-time)
[3] PRESENT proof 360KB in ~1.1s
[4] VERIFY  ACCEPT ✅  (~0.6s)
[5] VERIFY  TAMPERED → REJECT ✅
```

| Step | One-time? | Approx. time (this machine) |
|---|---|---|
| Circuit generation `gencircuit` | yes (cached) | ~14 s |
| Proof `present` | every presentation | ~1.1 s |
| Verify `verify` | every verification | ~0.6 s |

---

## Structure

```
playground/
├── native/
│   ├── longfellow_cli.cc   # CLI wrapping the longfellow C API (export-example/gencircuit/prove/verify)
│   ├── build.sh            # library + CLI build script
│   └── longfellow_cli      # (build artifact)
├── src/
│   ├── longfellow.js       # Node wrapper: spawns the CLI and parses JSON results
│   ├── demo.js             # full automated demo
│   └── playground.js       # step-by-step CLI (issue/present/verify)
├── artifacts/              # mdoc.bin, transcript.bin, circuit.bin, proof.bin, *.json
└── package.json
```

### How it works (summary)

1. **Issue** — `longfellow_cli export-example` dumps the built-in example's (`mdoc_examples.h`)
   mdoc, session transcript, and issuer public key to files → "issued credential".
2. **Setup** — `gencircuit` generates/compresses a ZK circuit matching the number of attributes and
   returns `ZkSpec` (system, circuit_hash). Built once and cached.
3. **Present** — `prove` calls `run_mdoc_prover`. Internally it builds encrypted
   sumcheck + Ligero proofs for **two circuits** (an ECDSA signature circuit over P-256
   + a SHA/CBOR hash circuit over GF(2^128)) and binds them with a MAC.
4. **Verify** — `verify` checks both proofs with `run_mdoc_verifier`. Both must
   pass to ACCEPT.

For a detailed analysis, see [`../longfellow-zk_analysis-report.md`](../longfellow-zk_analysis-report.md) in the parent folder.

---

## Next steps (extension ideas)

**Completed since the original mdoc demo:**

- ✅ **Real issuance integration** — issue + present a real mdoc with `@lukas.j.han/mdoc` (`pnpm run gen:mdoc`) and a real ES256 SD-JWT-VC (`pnpm run gen:sdjwt`); both are accepted by longfellow end-to-end. (No PD needed; full issuerSigned + empty deviceNS + ES256 deviceSignature + raw SessionTranscript.)
- ✅ **SD-JWT-VC selective-disclosure ZK** — single circuit (`sdjwt_full`) and 2-circuit MAC-linked split (`sdjwt_split`); see the SD-JWT sections above.
- ✅ **Multi-attribute proof** — the SD-JWT demos disclose 3 attributes by default (and a 13-attribute PID-grade credential via `pnpm run gen:sdjwt-big`); the mdoc CLI supports `gencircuit --attrs N` + multiple `--attr` (example index 3, Sprind-Funke, has several attributes such as `family_name`).
- ✅ **Pseudonymous nullifier (CI/DI analogue)** on both formats — `pnpm run demo:nullifier` (SD-JWT) and `pnpm run demo:mdoc-nullifier` (real mdoc). The issuer commits a `pseudonym_secret`; the circuit proves `nullifier = SHA(secret ‖ SHA(context))` with the secret hidden. Reports: [`sd-jwt-nullifier_analysis-report.md`](../sd-jwt-nullifier_analysis-report.md), [`mdoc-nullifier_analysis-report.md`](../mdoc-nullifier_analysis-report.md) (each lists its own future work, e.g. blind issuance and arbitrary-field-order generalization).

**Still open:**

- **N-API migration**: to eliminate process-startup overhead, wrap the logic of `longfellow_cli.cc`
  with node-addon-api to replace it with an in-process call.
- **HTTP API exposure**: expose it as NestJS endpoints (`/present`,
  `/verify`) like `research-eudi-module`.
