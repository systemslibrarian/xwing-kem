# Known Gaps

This library follows a deliberately narrow scope and an honest-documentation
discipline. What is *not* yet guaranteed is listed here so you can make an
informed decision before depending on it.

## Test-vector validation (the most important gap)

**Status: NOT yet validated against official X-Wing Known-Answer-Test (KAT)
vectors.** This is the single most important caveat in this document. Read it
before depending on the package.

What *is* tested today (see `tests/test_xwing.py`, all passing against a real
ML-KEM-768 backend):

- Functional round-trip: keygen -> encapsulate -> decapsulate agreement.
- Negative paths: wrong-length public key, ciphertext, and secret key are
  rejected; a single flipped ciphertext bit changes the recovered secret.
- Construction pinning: an explicit test asserts the combiner hashes exactly
  `ss_M || ss_X || ct_X || pk_X || label` and **never** mixes in the ML-KEM
  ciphertext `ct_M`, matching the draft.

What is *not* yet proven: that this implementation reproduces the draft's
fixed KAT bytes. Round-trip tests only show the code agrees with *itself*.
Only KAT reproduction shows it agrees with the *spec* and interoperates with
other implementations.

Why it is not run here, honestly:

1. The draft's vector appendix (Appendix C) was still under a "TODO" heading
   at the time of writing, and the bytes were not cleanly extractable.
2. The KAT is **derandomized** (seed-driven KeyGen and Encaps). pyca/
   cryptography exposes no derandomized encapsulation hook, so the
   `cryptography` backend physically cannot reproduce the fixed ciphertext
   even if the combiner is perfect. KAT validation requires the `liboqs`
   backend (or the pure-Python reference) plus the vector file.

**How to close this gap** (a three-part, wired harness already ships in
`tests/test_kat.py`, with a vector-file template at
`tests/xwing_kat.json.template`):

1. On a networked machine, obtain real vectors from the draft's reference
   repository (`github.com/dconnolly/draft-connolly-cfrg-xwing-kem`) or a
   trusted reference implementation. Copy the template to
   `tests/xwing_kat.json` and fill in the hex values.
2. The harness validates in three independent pieces, each skipping cleanly
   when its prerequisites are absent:
   - **(C) Combiner KAT** — runs with *no backend* if the vector file includes
     the intermediate components (`ss_m`, `ss_x`, `ct_x`, `pk_x`). This is the
     easiest piece to enable and directly checks the SHA3-256 combiner.
   - **(A) Keygen KAT** — runs with `liboqs-python` (`pip install
     "xwing-kem[liboqs]"`), which provides derandomized `generate_keypair_seed`.
     Confirm the SHAKE-256 seed-expansion split against the reference
     `xwing.py`, set `_SEED_EXPANSION_CONFIRMED = True`, and it asserts.
   - **(B) Encaps KAT** — neither liboqs nor pyca/cryptography exposes *seeded*
     encapsulation, so this half requires a derandomized reference encaps
     supplied via the `XWING_REF_ENCAPS` environment hook.
3. `pytest` — each piece flips from SKIP to a real assertion as its inputs
   become available.

Until at least the combiner KAT (C) and keygen KAT (A) pass on your machine,
treat conformance as **claimed but unproven**, and prefer "spec-faithful,
round-trip-tested" over "production-grade" in any public description.

## Constant-time / side-channel

- The lattice and curve operations run in **C** inside the chosen backend
  (pyca/cryptography or liboqs). Their constant-time properties are inherited
  from those implementations and are **not** re-verified here.
- The X-Wing combiner glue in this package is pure Python. It operates only on
  fixed-length values and performs **no secret-dependent branching**, but
  Python provides **no constant-time guarantee** (object allocation, GC, and
  interpreter behaviour are out of our control). Do not rely on this layer for
  timing-side-channel resistance in a hostile co-located environment.
- No formal side-channel analysis has been performed.

## Backend availability

- `cryptography` exposes ML-KEM only when its wheel was built against
  OpenSSL 3.5+, AWS-LC, or BoringSSL. The maintainers have stated some PQC
  APIs may be unavailable on plain-OpenSSL wheels. This package **probes** the
  backend at import and **falls back** to `liboqs-python` automatically; if
  neither works, `get_backend()` raises with install guidance.

## Secret-key encoding is backend-dependent

- The ML-KEM-768 secret key is serialized differently per backend
  (`cryptography` returns the 64-byte seed form; `liboqs` returns the
  ~2400-byte expanded form). An X-Wing secret key produced by one backend is
  therefore **not portable** to the other. Keys are usable only with the
  backend that generated them. A portable, self-describing key container is
  future work.

## Scope

- X-Wing only. No ML-KEM-1024 variant, no authenticated KEM, no signatures,
  no HPKE/TLS wiring. These are intentionally out of scope.

---

Soli Deo Gloria — 1 Corinthians 10:31.
