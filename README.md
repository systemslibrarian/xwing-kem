# xwing-kem

**The X-Wing hybrid post-quantum KEM (X25519 + ML-KEM-768) for Python.**

[![CI](https://github.com/systemslibrarian/xwing-kem/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/xwing-kem/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/xwing-kem.svg)](https://pypi.org/project/xwing-kem/)
[![Python](https://img.shields.io/pypi/pyversions/xwing-kem.svg)](https://pypi.org/project/xwing-kem/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/systemslibrarian/xwing-kem/blob/main/LICENSE)

`xwing-kem` is a single, drop-in key-encapsulation mechanism that stays secure
as long as **either** classical X25519 **or** post-quantum ML-KEM-768 holds. It
implements [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
faithfully, so you get the vetted hybrid construction without ever hand-rolling
a combiner — the single most common (and dangerous) post-quantum migration bug.

> ### ⚠️ Pre-1.0 — please read before production use
>
> `xwing-kem` is **validated against all three official X-Wing Known-Answer-Test
> (KAT) vectors** from the draft: key generation from seed and the SHA3-256
> combiner are checked **byte-for-byte**, and derandomized encapsulation is
> verified against the draft's **reference implementation**.
>
> Honest limits that still apply: no ML-KEM backend exposes *seeded*
> encapsulation, so the library's own randomized `encapsulate()` is validated
> **transitively** (round-trip + keygen KAT + combiner KAT + reference-encaps
> KAT), not by a direct ciphertext-byte match; constant-time guarantees come
> only from the C-backend primitives, **not** the Python glue; and secret keys
> are **not portable** between backends. The full, candid accounting is in
> **[KNOWN-GAPS.md](https://github.com/systemslibrarian/xwing-kem/blob/main/KNOWN-GAPS.md)**.

---

## Contents

- [Key Features](#key-features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [When to Use X-Wing](#when-to-use-x-wing)
- [Why X-Wing?](#why-x-wing)
- [The X-Wing Construction](#the-x-wing-construction)
- [Backend Selection](#backend-selection)
- [Performance](#performance)
- [Validation & Limitations](#validation--limitations)
- [Design Notes](#design-notes)
- [Contributing & Security](#contributing--security)
- [License](#license)

## Key Features

- 🛡️ **Hybrid by construction** — secure unless an attacker breaks *both*
  X25519 *and* ML-KEM-768.
- 🎯 **Concrete, not generic** — algorithms, combiner (SHA3-256), and security
  level (NIST PQC level 1) are all fixed. Nothing to misconfigure.
- 🔌 **Two real backends, auto-selected** — native `cryptography` preferred,
  with a `liboqs` fallback. No simulated math.
- ⚡ **Inherits native speed** — sits *above* the primitives, so it gets faster
  the moment your platform ships native ML-KEM.
- ✅ **KAT-validated** — checked byte-for-byte against the official draft
  vectors (see the status note above).
- 🧩 **Consistent, predictable API** — functional and class forms return values
  in the same order; fixed 1216-byte public keys, 1120-byte ciphertexts, and a
  32-byte shared secret.
- 🪶 **Narrow, auditable scope** — X-Wing only, MIT-licensed.

## Quick Start

Both APIs return values in the **same order** — `encapsulate()` gives you
`(shared_secret, ciphertext)`.

**Functional API:**

```python
from xwing_kem import generate_keypair, encapsulate, decapsulate

kp = generate_keypair()                                  # kp.public_key, kp.secret_key
shared_sender, ciphertext = encapsulate(kp.public_key)
shared_recipient = decapsulate(ciphertext, kp.secret_key)

assert shared_sender == shared_recipient                 # 32-byte shared secret
```

**Class-based API:**

```python
from xwing_kem import XWing

kem = XWing()
public_key, secret_key = kem.generate_keypair()
shared_sender, ciphertext = kem.encapsulate(public_key)
shared_recipient = kem.decapsulate(ciphertext, secret_key)

assert shared_sender == shared_recipient
```

The only difference between the two forms is how the key pair is handed back:
the functional `generate_keypair()` returns a small `XWingKeyPair` object
(`.public_key` / `.secret_key`), while `XWing.generate_keypair()` returns a
plain `(public_key, secret_key)` tuple. Pick whichever reads better for you.

More runnable scripts live in
[`examples/`](https://github.com/systemslibrarian/xwing-kem/tree/main/examples).

## Installation

```bash
pip install xwing-kem
```

That's it — the library auto-detects an ML-KEM backend at import time, so most
users need nothing further. ML-KEM-768 is provided natively by `cryptography>=48`
when its wheel is built against OpenSSL 3.5+, AWS-LC, or BoringSSL. If your
platform's wheel lacks post-quantum support, install the optional `liboqs`
fallback backend:

```bash
pip install "xwing-kem[liboqs]"   # requires liboqs.so on the system
```

See [Backend Selection](#backend-selection) to inspect or pin the active choice.

## When to Use X-Wing

**Reach for X-Wing when:**

- You're adding **post-quantum protection to key exchange** and want
  defense-in-depth — security that holds if *either* the classical *or* the
  post-quantum component is later broken.
- You want a **standards-track, opinionated** construction with no knobs to
  tune, suitable for HPKE-style sealing, secure messaging, or wrapping data
  keys.
- You'd otherwise be tempted to **glue X25519 and ML-KEM together yourself** —
  this library is exactly that glue, done to spec.

**Look elsewhere when:**

- You need a **bare ML-KEM or bare X25519** KEM (use `cryptography` or `liboqs`
  directly).
- You need **signatures or an authenticated KEM** — out of scope here.
- You require **certified constant-time guarantees across the whole stack**;
  the Python combiner layer offers no timing guarantee (see
  [Validation & Limitations](#validation--limitations)).

## Why X-Wing?

Migrating to post-quantum cryptography, you almost never want a *raw* KEM — you
want a **hybrid** that survives the failure of either half. The dangerous part
is the combiner that mixes the two shared secrets; a hand-rolled one is the
classic PQ-migration footgun, and getting the byte order or omitted inputs
wrong silently produces incompatible or insecure secrets.

X-Wing removes that risk by being **opinionated and concrete**:

- **No parameters.** The constituent algorithms (X25519 + ML-KEM-768), the
  combiner hash (SHA3-256), and the security target are all fixed by the spec.
- **Belt-and-suspenders security.** An attacker must defeat *both* a
  well-studied elliptic curve *and* a NIST-standardized lattice KEM.
- **One obvious API.** `generate_keypair` / `encapsulate` / `decapsulate`, fixed
  lengths, a 32-byte secret — easy to wire into HPKE, TLS-like handshakes, or
  file/message encryption.

This library exists so you can adopt the vetted construction instead of writing
the combiner yourself.

## The X-Wing Construction

The 32-byte shared secret is the SHA3-256 hash of the two component secrets, the
X25519 ciphertext and public key, and a fixed label:

```text
ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || XWING_LABEL )
```

| Symbol        | Meaning                                            | Size |
| ------------- | -------------------------------------------------- | ---- |
| `ss_M`        | ML-KEM-768 shared secret                           | 32 B |
| `ss_X`        | X25519 raw shared secret                           | 32 B |
| `ct_X`        | X25519 ciphertext (the ephemeral public key)       | 32 B |
| `pk_X`        | recipient's X25519 public key                      | 32 B |
| `XWING_LABEL` | the 6-byte X-Wing sigil, appended **last**         |  6 B |

The ML-KEM ciphertext `ct_M` is **deliberately omitted** from the hash:
ML-KEM-768 is ciphertext-collision-resistant, so mixing it in is unnecessary,
and leaving it out is exactly what gives X-Wing its performance edge over a
generic combiner.

## Backend Selection

**By default, no choice is required.** The library auto-selects a backend at
first use — native `cryptography` first, then `liboqs` — and caches it. You can
inspect the active choice or pin it explicitly:

```python
import xwing_kem
from xwing_kem import generate_keypair, XWing

# Which backend is active right now?
print(xwing_kem.active_backend())            # 'cryptography' or 'liboqs'

# Force a specific backend for a single call...
kp = generate_keypair(prefer_backend="liboqs")

# ...or for every operation on an object-style instance:
kem = XWing(prefer_backend="cryptography")
print(kem.backend_name)                      # 'cryptography'
public_key, secret_key = kem.generate_keypair()
```

`prefer_backend` accepts `"cryptography"`, `"liboqs"`, or `None` (auto). An
unavailable choice **raises** rather than silently falling back, so pinning is
always explicit and predictable.

## Performance

`xwing-kem` is intentionally a thin, correct layer over the primitives — all the
heavy lattice and curve math runs in vetted **C** inside the chosen backend, not
in Python. That has two practical consequences:

1. **It inherits native speed.** As native ML-KEM lands in `cryptography` /
   OpenSSL, this package gets faster automatically — no code change on your side.
2. **The construction itself is lean.** By omitting the ML-KEM ciphertext from
   the combiner, X-Wing avoids extra hashing that a generic combiner would incur.

Indicative single-thread timings (median of 300 runs, `cryptography` backend,
Python 3.12, x86-64), compared against **pure X25519** used KEM-style (ephemeral
keygen + DH for "encapsulate", DH for "decapsulate"):

| Operation     | X-Wing  | Pure X25519 | Overhead |
| ------------- | ------: | ----------: | -------: |
| keygen        | ~240 µs |      ~51 µs |     4.7× |
| encapsulate   | ~145 µs |     ~117 µs |     1.2× |
| decapsulate   | ~294 µs |      ~54 µs |     5.5× |

**Takeaway:** full post-quantum protection costs roughly **2–6× a bare X25519
exchange**, yet every operation still completes in **well under a millisecond**.
Encapsulation is nearly free relative to X25519, because ML-KEM encapsulation is
fast and X-Wing layers only a single curve operation on top. Numbers vary by
machine, Python version, and backend.

## Validation & Limitations

This project follows an honest-documentation discipline. The short version:

- ✅ **KAT-validated.** Key generation from seed and the SHA3-256 combiner are
  checked **byte-for-byte** against all three official draft vectors;
  derandomized encapsulation is verified against the reference implementation.
- ⚠️ **Randomized `encapsulate()` is validated transitively.** No backend
  exposes seeded encapsulation, so it is covered by round-trip + keygen KAT +
  combiner KAT + reference-encaps KAT rather than a direct ciphertext-byte match.
- ⚠️ **Constant-time only in the C primitives.** The Python combiner glue does
  no secret-dependent branching, but Python offers no timing guarantees — don't
  rely on this layer in a hostile co-located environment.
- ⚠️ **Secret keys are not portable between backends** (`cryptography` stores
  the 64-byte seed form; `liboqs` the expanded form).

The complete accounting lives in
**[KNOWN-GAPS.md](https://github.com/systemslibrarian/xwing-kem/blob/main/KNOWN-GAPS.md)**.
Please read it before depending on this in production.

## Design Notes

- **Future-proof by position.** This package sits *above* the primitives, so it
  inherits faster/native ML-KEM the moment your wheel has it.
- **No simulated cryptography.** Both backends use real, vetted C implementations.
- **Deliberately narrow scope.** X-Wing only — no ML-KEM-1024 variant, no
  authenticated KEM, no signatures, no HPKE/TLS wiring.

## Contributing & Security

Contributions are welcome — see
[CONTRIBUTING.md](https://github.com/systemslibrarian/xwing-kem/blob/main/CONTRIBUTING.md).
For vulnerability reports and the disclosure process, see
[SECURITY.md](https://github.com/systemslibrarian/xwing-kem/blob/main/SECURITY.md).

## License

[MIT](https://github.com/systemslibrarian/xwing-kem/blob/main/LICENSE).

---

X-Wing is the work of the IETF CFRG draft authors; this package is just a
faithful, well-tested Python home for it. If it helps you ship post-quantum
protection with a little more confidence, it's doing its job — issues and
improvements are always welcome.

*Soli Deo Gloria — 1 Corinthians 10:31.*
