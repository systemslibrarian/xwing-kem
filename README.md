# xwing-kem

[![CI](https://github.com/systemslibrarian/xwing-kem/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/xwing-kem/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/xwing-kem.svg)](https://pypi.org/project/xwing-kem/)
[![Python](https://img.shields.io/pypi/pyversions/xwing-kem.svg)](https://pypi.org/project/xwing-kem/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> ## ✅ Validation status (read me)
>
> As of **0.1.0**, `xwing-kem` is **validated against the official X-Wing
> Known-Answer-Test vectors** from the draft — **all three** published vectors.
> Key generation from seed and the SHA3-256 combiner are checked **byte-for-byte**;
> derandomized encapsulation is verified against the draft's **reference
> implementation**.
>
> **Honest caveats that still apply:** neither ML-KEM backend exposes *seeded*
> encapsulation, so the library's own `encapsulate()` (which uses fresh
> randomness) is validated **transitively** — via round-trip, the keygen KAT, the
> combiner KAT, and the reference-encaps KAT — not by emitting KAT ciphertext
> bytes directly. Constant-time guarantees apply only to the C-backend
> primitives, **not** the Python glue, and secret keys are **not portable**
> between backends. **Please read [KNOWN-GAPS.md](KNOWN-GAPS.md) before relying
> on this in production.**

The **X-Wing** hybrid KEM (X25519 + ML-KEM-768) for Python, implementing the
construction from
[draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).

```python
from xwing_kem import generate_keypair, encapsulate, decapsulate

kp = generate_keypair()
shared_sender, ciphertext = encapsulate(kp.public_key)
shared_recipient = decapsulate(ciphertext, kp.secret_key)
assert shared_sender == shared_recipient   # 32-byte shared secret
```

## Contents

- [Why X-Wing?](#why-x-wing)
- [Install](#install)
- [Usage](#usage)
- [Backend selection](#backend-selection)
- [The construction](#the-construction)
- [Benchmarks](#benchmarks)
- [Honesty](#honesty)
- [Design notes](#design-notes)
- [License](#license)

## Why X-Wing?

If you are migrating to post-quantum cryptography, you almost never want a *raw*
KEM — you want a **hybrid** that stays secure as long as *either* X25519 *or*
ML-KEM-768 holds. The dangerous part is the combiner that mixes the two secrets;
a hand-rolled one is the classic PQ-migration footgun.

X-Wing solves that for you:

- **Concrete, not generic.** The constituent algorithms (X25519 + ML-KEM-768),
  the combiner hash (SHA3-256), and the security target (NIST PQC level 1) are
  all **fixed**. There are no parameters to misconfigure.
- **Belt-and-suspenders security.** Breaks only if an attacker defeats *both* a
  well-studied elliptic curve *and* a NIST-standardized lattice KEM.
- **One obvious API.** `generate_keypair` / `encapsulate` / `decapsulate`, a
  32-byte shared secret, fixed-length keys and ciphertexts.
- **Real primitives.** Both backends do the lattice/curve math in vetted C — no
  simulated cryptography.

This library exists so you don't write the combiner yourself.

## Install

```bash
pip install xwing-kem
```

ML-KEM-768 is provided natively by `cryptography>=48` when its wheel is built
against OpenSSL 3.5+, AWS-LC, or BoringSSL. If your wheel's OpenSSL lacks PQC,
install the fallback backend:

```bash
pip install "xwing-kem[liboqs]"   # requires liboqs.so on the system
```

## Usage

Functional API:

```python
from xwing_kem import generate_keypair, encapsulate, decapsulate

kp = generate_keypair()
ss_sender, ct = encapsulate(kp.public_key)
ss_recipient = decapsulate(ct, kp.secret_key)
assert ss_sender == ss_recipient
```

Object-style API, if you prefer:

```python
from xwing_kem import XWing

kem = XWing()
pk, sk = kem.generate_keypair()
ct, ss = kem.encapsulate(pk)
ss2 = kem.decapsulate(ct, sk)
```

## Backend selection

By default the library auto-selects a backend (native `cryptography` first,
then `liboqs`). You can inspect or pin it:

```python
import xwing_kem
from xwing_kem import generate_keypair, XWing

# Which backend is active right now?
print(xwing_kem.active_backend())          # 'cryptography' or 'liboqs'

# Force a specific backend for a single call...
kp = generate_keypair(prefer_backend="liboqs")

# ...or for every operation on an object-style instance:
kem = XWing(prefer_backend="cryptography")
print(kem.backend_name)                    # 'cryptography'
pk, sk = kem.generate_keypair()
```

`prefer_backend` accepts `"cryptography"`, `"liboqs"`, or `None` (auto). An
unavailable choice raises rather than silently falling back, so pinning is
explicit.

## The construction

The shared secret is derived as:

```
ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || XWING_LABEL )
```

where `ss_M` is the ML-KEM-768 shared secret, `ss_X` the X25519 raw shared
secret, `ct_X` the ephemeral X25519 public key, and `pk_X` the recipient's
X25519 public key. The ML-KEM ciphertext `ct_M` is **deliberately not** mixed
in — ML-KEM-768 is ciphertext-collision-resistant, and omitting it is the
performance advantage of X-Wing over a generic combiner. `XWING_LABEL` is the
6-byte X-Wing sigil, appended last.

## Benchmarks

Indicative single-thread timings (median of 300 runs, `cryptography` backend,
Python 3.12, x86_64), comparing X-Wing against **pure X25519** used KEM-style
(ephemeral keygen + DH for "encapsulate", DH for "decapsulate"):

| Operation     | X-Wing  | Pure X25519 | Ratio |
| ------------- | ------: | ----------: | ----: |
| keygen        | ~240 µs |      ~51 µs |  4.7× |
| encapsulate   | ~145 µs |     ~117 µs |  1.2× |
| decapsulate   | ~294 µs |      ~54 µs |  5.5× |

Takeaway: post-quantum protection costs roughly **2–6× a bare X25519 exchange**,
and every operation is still **well under a millisecond**. Encapsulation is
nearly free relative to X25519 because ML-KEM encapsulation is fast and X-Wing
adds only a single curve operation on top. Numbers vary by machine and backend;
reproduce with the snippet in the project's benchmark notes.

## Honesty

Please read [KNOWN-GAPS.md](KNOWN-GAPS.md) before depending on this. In short:
key generation and the combiner are now validated **byte-for-byte against the
official draft KAT vectors**, and derandomized encapsulation is checked against
the reference implementation — but the library's own randomized `encapsulate()`
is covered transitively rather than by a direct ciphertext-byte match (no
backend exposes seeded encapsulation), constant-time guarantees apply only to
the C backend primitives and not the Python glue, and secret keys are not
portable between backends.

## Design notes

- Survives native ML-KEM landing in `cryptography` / OpenSSL: this package
  sits *above* the primitives, so it inherits faster/native ML-KEM the moment
  your wheel has it.
- No simulated math — both backends use real, vetted C implementations.
- Narrow scope on purpose: X-Wing only.

## License

MIT.

---

Soli Deo Gloria — 1 Corinthians 10:31.
