# Longfellow ZK — Analysis & Node.js Playground

A working repository that **analyzes** [google/longfellow-zk](https://github.com/google/longfellow-zk)
(Google's zero-knowledge identity-proof C++ library) and builds a **playground** that
**calls it from Node.js** to **issue → present (ZK proof) → verify** mdocs.

> One-line summary: For an mdoc (ISO 18013-5 mDL) signed with legacy **ECDSA(P-256)**,
> we actually got it working in Node to **selectively disclose only attributes like
> "age_over_18" in zero-knowledge**, without changing the issuer infrastructure.

---

## Directory structure

```
longfellow/
├── README.md                    # (this file) overall overview · reproduction
├── longfellow-zk_analysis-report.md   # in-depth source code analysis (12 chapters; Korean: -ko.md)
├── longfellow-zk/               # upstream as a git submodule (pinned SHA; init via --recurse-submodules)
├── playground/                  # ⭐ Node.js playground (issue→present→verify)
│   ├── native/longfellow_cli.cc #   longfellow C API wrapper CLI
│   ├── native/build.sh          #   library + CLI build script
│   ├── src/longfellow.js        #   Node wrapper (CLI spawn + JSON parsing)
│   ├── src/demo.js              #   full automated demo
│   ├── src/playground.js        #   step-by-step CLI
│   └── README.md                #   detailed playground documentation
├── references/                  # related papers (PDFs excluded from git, links in references/README.md)
├── build/                       # cmake build artifacts (excluded from git)
└── .toolchain/                  # clang wrapper (auto-generated, excluded from git)
```

---

## 1. What is longfellow-zk?

A C++ library for adding zero-knowledge proofs (ZK) to existing identity standards
(ISO **mdoc/mDL**, JWT, W3C VC) **without changing them**. It solves the core challenge,
**"proving an ECDSA-signed credential in ZK without revealing the signature,"** with
two building blocks.

- **(Encrypted) Sumcheck protocol** — proves the correct computation of the arithmetic circuit `C(x,w)=0`
- **Ligero argument** — a commitment that requires **no trusted setup** and assumes only a collision-resistant hash (SHA-256)

The most important design: it splits mdoc verification into **two circuits**, optimally implements each in its own field, and links them with a MAC.
- **ECDSA signature circuit** over `Fp256` (`circuits/ecdsa/`)
- **SHA-256 + CBOR hash circuit** over `GF(2^128)` (`circuits/sha/`, `cbor_parser_v2/`)

> 📖 **For a detailed explanation of how it works and the code analysis, see [`longfellow-zk_analysis-report.md`](longfellow-zk_analysis-report.md).**

### Supported format status (per code)

| Format | Public C API | Playground ZK |
|---|---|---|
| **mdoc (ISO 18013-5)** | ✅ available | ✅ present/verify (`demo`, `demo:multi`) — all types |
| **SD-JWT (substring)** | ⚠️ experimental circuit | ✅ string attributes (`demo:jwt`) — longfellow JWT circuit harness |
| **SD-JWT-VC (`_sd` membership)** | ❌ (custom implementation) | ✅ **all types + exp + vct + Key Binding + sd_hash binding + multi-attribute (variable N) + circuit cache** (`demo:sdjwt-zk`) — Approach C new circuit |
| W3C VC | ❌ none | unsupported |

> The playground runs three ZK paths:
> - **mdoc** — full support (public API), all types.
> - **SD-JWT(substring)** — longfellow experimental circuit, strings only.
> - **SD-JWT-VC(`_sd` membership, Approach C)** — with our custom-implemented circuit, going beyond mdoc parity to **boolean · numeric · date
>   + validity period (exp) + Key Binding + simultaneous multi-attribute disclosure**. Issuer signature +
>   holder KB + 3 attributes in a single ZK proof. `pnpm run demo:sdjwt-zk`. (design: `playground/SDJWT_PLAN.md`)

⚠️ longfellow **does not issue** mdocs. For an mdoc that is already ECDSA-signed it
**only does present/verify** (issuance is the job of a separate library).

---

## 2. Node.js playground

`Node → longfellow_cli(C++) → longfellow C API` (CLI subprocess approach —
no native addon/ABI required, the simplest).

```bash
cd playground
pnpm run build:native     # once: build C++ library + CLI (a few minutes)
pnpm run circuits         # once: pre-generate · cache circuits per N (N=1~4, about 1 minute)
pnpm run demo             # issue → setup → present → verify → tamper-rejection demo (~2s)
pnpm run demo:multi       # multi-attribute (example 3) simultaneous proof
```

Step-by-step execution (state is saved in `playground/artifacts/`):
```bash
pnpm run issue     # load example mdoc + generate ZK circuit (cache)
pnpm run present   # generate ZK proof → artifacts/proof.bin
pnpm run verify    # verify proof (exit 0 if ACCEPT)
```

> For playground details, see [`playground/README.md`](playground/README.md).

### Operating results (measured, this machine)

| Step | Result | Time |
|---|---|---|
| circuit generation `gencircuit` (once/cached) | hash `8d079211…` (matches registry) | ~14 s |
| **present (ZK proof)** | proof ~360 KB | **~1.1 s** |
| **verify (normal)** | ACCEPT ✅ | **~0.6 s** |
| verify (tampered proof) | REJECT ✅ | — |
| verify (forged value: f4≠f5) | REJECT ✅ | — |

→ This matches the paper's "mobile ~1.2s" prove performance, and confirms that **both tampering and false claims are rejected**.

---

## 3. Reproduction (from scratch)

```bash
# 0) clone this repo WITH the upstream submodule
git clone --recurse-submodules <this-repo-url>
cd longfellow
# (already cloned without --recurse-submodules? run:)
#   git submodule update --init

# 1) build & run the playground
cd playground
pnpm install        # (currently no dependencies — in preparation for future expansion)
pnpm run build:native
pnpm run demo
```

### ⚠️ Build toolchain caveat (non-obvious)

This machine's default `clang++` (Swift toolchain) cannot find `libstdc++`.
`playground/native/build.sh` works around this by auto-generating a wrapper
(`.toolchain/clang++w`) that wraps the system `clang-17` with
`--gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/11`. If your GCC path is
different, specify it via the `GCC_INSTALL_DIR` environment variable.

Dependencies: `cmake`, `clang-17`, system `openssl`/`zstd`/`zlib` development headers, Node 18+.

---

## 4. Next steps (expansion ideas)

1. **Real issuance integration** — issue a new ECDSA mdoc with `@auth0/mdl` etc., then
   present/verify with longfellow (CBOR/MSO/deviceKey/transcript structure compatibility verification needed).
2. **Multi-attribute proof** — `gencircuit --attrs 2+` + multiple `--attr` (example index 3 = Sprind-Funke, includes `family_name` etc.).
3. **N-API transition** — eliminate process startup overhead (in-process calls).
4. **HTTP API** — expose NestJS endpoints (`/present`, `/verify`) like `research-eudi-module`.

---

## 5. References

- Original paper *Anonymous credentials from ECDSA* (Frigo & shelat, Google): https://eprint.iacr.org/2024/2010
- *Ligero* (commitment/argument foundation): https://eprint.iacr.org/2022/1608
- IETF draft: https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/
- Official docs (including security audit): https://google.github.io/longfellow-zk/
- Detailed list: [`references/README.md`](references/README.md)
