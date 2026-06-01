# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-01

### Changed

- **BREAKING (class API):** `XWing.encapsulate()` now returns
  `(shared_secret, ciphertext)`, matching the functional `encapsulate()`, the
  draft's pseudocode, and pyca/cryptography. It previously returned
  `(ciphertext, shared_secret)`. Update call sites from `ct, ss =
  kem.encapsulate(pk)` to `ss, ct = kem.encapsulate(pk)`. The functional API is
  unchanged.
- Clearer, more actionable `ValueError` messages for wrong-length public keys,
  ciphertexts, and secret keys (now state the expected structure and common
  causes).

### Added

- `examples/` directory with runnable scripts (functional API, class API, and
  backend selection).
- README: "Key Features", "When to use X-Wing", a prose "Performance" section
  with measured benchmarks vs pure X25519, and a regression test pinning the
  functional/class return-order contract.

### Fixed

- README links are now absolute GitHub URLs so they resolve on PyPI (relative
  links such as `KNOWN-GAPS.md` previously 404'd on the project page).
- README/`KNOWN-GAPS.md` validation status corrected: the package **is**
  validated against the official X-Wing KAT vectors (the 0.1.0 page predated
  that work and still read "not yet validated").

## [0.1.0] - 2026-06-01

Initial release.

### Added

- X-Wing hybrid KEM (X25519 + ML-KEM-768) per
  `draft-connolly-cfrg-xwing-kem`, with the SHA3-256 combiner and the ML-KEM
  ciphertext deliberately omitted, matching the draft.
- Dual backend with automatic selection: prefers pyca/cryptography's native
  ML-KEM (v48+, when built against OpenSSL 3.5+/AWS-LC/BoringSSL), falls back
  to `liboqs-python`. Backend is probed at first use and cached.
- Functional API (`generate_keypair`, `encapsulate`, `decapsulate`) and an
  object-style `XWing` wrapper, both using a unified `(ciphertext,
  shared_secret)` return order.
- Test suite: round-trip, distinctness, tamper detection, length validation,
  combiner-construction pinning, and backend reporting (10 tests).
- A wired-but-skippable Known-Answer-Test harness (`tests/test_kat.py`) ready
  to validate against the official derandomized X-Wing vectors once supplied.
- Honest `KNOWN-GAPS.md` documenting that the package is round-trip-tested and
  spec-construction-verified, but **not yet KAT-validated**.

### Known limitations

- Not validated against official X-Wing KAT vectors (see `KNOWN-GAPS.md`).
- Secret-key encoding is backend-dependent and not portable between backends.
- Constant-time guarantees apply to the C backend primitives only, not the
  Python combiner glue.

[0.2.0]: https://github.com/systemslibrarian/xwing-kem/releases/tag/v0.2.0
[0.1.0]: https://github.com/systemslibrarian/xwing-kem/releases/tag/v0.1.0
