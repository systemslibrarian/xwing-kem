"""xwing-kem: the X-Wing hybrid KEM (X25519 + ML-KEM-768) for Python.

X-Wing is a concrete post-quantum/traditional hybrid KEM specified in
draft-connolly-cfrg-xwing-kem. It fixes the constituent algorithms
(X25519 + ML-KEM-768), the combiner (SHA3-256), and the security level
(NIST PQC level 1 / "128-bit"), so there are no parameters to get wrong.

Functional API:

    from xwing_kem import generate_keypair, encapsulate, decapsulate

    kp = generate_keypair()
    ss_sender, ct = encapsulate(kp.public_key)
    ss_recipient = decapsulate(ct, kp.secret_key)
    assert ss_sender == ss_recipient

Class API (same behaviour, object style):

    from xwing_kem import XWing

    kem = XWing()
    pk, sk = kem.generate_keypair()
    ct, ss = kem.encapsulate(pk)
    ss2 = kem.decapsulate(ct, sk)

Backend: prefers pyca/cryptography's native ML-KEM (v48+, when built
against OpenSSL 3.5+/AWS-LC/BoringSSL); falls back to liboqs-python.
See KNOWN-GAPS.md for the honest limitations.
"""

from ._core import (
    XWingKeyPair,
    decapsulate,
    encapsulate,
    generate_keypair,
    SHARED_SECRET_LEN,
    XWING_CT_LEN,
    XWING_PK_LEN,
    XWING_LABEL,
)
from ._backend import get_backend

__version__ = "0.1.0"

__all__ = [
    "XWing",
    "XWingKeyPair",
    "generate_keypair",
    "encapsulate",
    "decapsulate",
    "active_backend",
    "SHARED_SECRET_LEN",
    "XWING_CT_LEN",
    "XWING_PK_LEN",
    "XWING_LABEL",
]


def active_backend(prefer: str | None = None) -> str:
    """Return the name of the ML-KEM backend in use ('cryptography' or 'liboqs')."""
    return get_backend(prefer).name


class XWing:
    """Object-style wrapper over the functional X-Wing API.

    prefer_backend: 'cryptography', 'liboqs', or None to auto-select.

    Note the argument order on encapsulate/decapsulate mirrors the
    functional API and the draft: ciphertext first on decapsulate.
    """

    def __init__(self, prefer_backend: str | None = None):
        self.prefer_backend = prefer_backend
        # Resolve eagerly so construction fails fast if no backend exists.
        self.backend_name = get_backend(prefer_backend).name

    def generate_keypair(self):
        kp = generate_keypair(self.prefer_backend)
        return kp.public_key, kp.secret_key

    def encapsulate(self, public_key: bytes):
        ss, ct = encapsulate(public_key, self.prefer_backend)
        return ct, ss

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        return decapsulate(ciphertext, secret_key, self.prefer_backend)
