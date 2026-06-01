# xwing-kem

[![CI](https://github.com/systemslibrarian/xwing-kem/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/xwing-kem/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/xwing-kem.svg)](https://pypi.org/project/xwing-kem/)
[![Python](https://img.shields.io/pypi/pyversions/xwing-kem.svg)](https://pypi.org/project/xwing-kem/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Validation status:** round-trip-tested and spec-construction-verified, but
> **not yet validated against official X-Wing Known-Answer-Test vectors.** See
> [KNOWN-GAPS.md](KNOWN-GAPS.md) before relying on this in production.

The **X-Wing** hybrid KEM (X25519 + ML-KEM-768) for Python, implementing the
construction from
[draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).

X-Wing is a *concrete* post-quantum/traditional hybrid KEM — not a generic
combiner. The constituent algorithms (X25519 + ML-KEM-768), the combiner hash
(SHA3-256), and the security target (NIST PQC level 1) are all fixed, so there
are no parameters to misconfigure. The most common post-quantum migration bug
is a hand-rolled, insecure hybrid combiner; this library exists so you don't
write one.

```python
from xwing_kem import generate_keypair, encapsulate, decapsulate

kp = generate_keypair()
shared_sender, ciphertext = encapsulate(kp.public_key)
shared_recipient = decapsulate(ciphertext, kp.secret_key)
assert shared_sender == shared_recipient   # 32-byte shared secret
```

Object-style API, if you prefer:

```python
from xwing_kem import XWing

kem = XWing()
pk, sk = kem.generate_keypair()
ct, ss = kem.encapsulate(pk)
ss2 = kem.decapsulate(ct, sk)
```

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

You can check which backend is active:

```python
import xwing_kem
print(xwing_kem.active_backend())   # 'cryptography' or 'liboqs'
```

## The construction

The shared secret is derived as:

```
ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || XWING_LABEL )
```

where `ss_M` is the ML-KEM-768 shared secret, `ss_X` the X25519 raw shared
secret, `ct_X` the ephemeral X25519 public key, and `pk_X` the recipient's
X25519 public key. The ML-KEM ciphertext `ct_M` is **deliberately not** mixed
in — ML-KEM-768 is ciphertext-collision-resistant, and omitting it is the
performance advantage of X-Wing over a generic combiner. The label is the
6-byte X-Wing sigil.

## Honesty

Please read [KNOWN-GAPS.md](KNOWN-GAPS.md) before depending on this. In short:
the round-trip and combiner construction are tested, but this version is **not
yet validated against official X-Wing test vectors** (the draft's KAT appendix
was still a TODO at release), constant-time guarantees apply only to the C
backend primitives and not the Python glue, and secret keys are not portable
between backends.

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
