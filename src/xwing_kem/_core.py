"""The X-Wing hybrid KEM construction.

X-Wing combines X25519 and ML-KEM-768 into a single PQ/T hybrid KEM, as
specified in draft-connolly-cfrg-xwing-kem. It is a *concrete* KEM, not a
generic combiner: the constituent algorithms, security level, and
combiner hash are all fixed.

Combiner (draft "Combiner" section):

    ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || XWING_LABEL )

where
    ss_M  = ML-KEM-768 shared secret      (32 bytes)
    ss_X  = X25519 raw shared secret       (32 bytes)
    ct_X  = X25519 ephemeral public key    (32 bytes)  [the "ciphertext"]
    pk_X  = recipient X25519 public key    (32 bytes)
    XWING_LABEL = the 6-byte X-Wing sigil  b"\\.//^\\"

The ML-KEM-768 ciphertext is deliberately NOT mixed in (see draft 1.3 /
section 6): ML-KEM-768 is ciphertext-collision-resistant, so including
ct_M is unnecessary and X-Wing omits it for performance. The output is a
fixed 32-byte shared secret.

This module performs no secret-dependent branching. All concatenated
inputs are fixed length, so no length-encoding is required.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ._backend import get_backend

# The X-Wing label, draft section 5.3. Six ASCII bytes forming the
# "X-Wing" sigil: backslash-dot-slash-slash-caret-backslash.
XWING_LABEL = b"\\.//^\\"

# Component sizes (bytes) for ML-KEM-768 + X25519.
#
# Note: the ML-KEM-768 *public key* and *ciphertext* are fixed length and
# identical across backends, but the *secret key* representation is NOT.
# pyca/cryptography (v48) serialises the seed-only form (64 bytes) via
# private_bytes_raw(); liboqs exports the expanded FIPS-203 form (2400
# bytes). We therefore never hardcode the secret-key length: the X-Wing
# secret key stores sk_X (32 bytes, fixed) as a trailing suffix and treats
# everything before it as the backend-specific sk_M.
MLKEM768_PK_LEN = 1184
MLKEM768_CT_LEN = 1088
X25519_LEN = 32
SHARED_SECRET_LEN = 32

# X-Wing public key  = pk_M (1184) || pk_X (32)
# X-Wing ciphertext  = ct_M (1088) || ct_X (32)
# X-Wing secret key  = sk_M (backend-specific) || sk_X (32)   -- sk_X is the suffix
XWING_PK_LEN = MLKEM768_PK_LEN + X25519_LEN
XWING_CT_LEN = MLKEM768_CT_LEN + X25519_LEN


def _combiner(ss_M: bytes, ss_X: bytes, ct_X: bytes, pk_X: bytes) -> bytes:
    # Per draft-connolly-cfrg-xwing-kem (combiner section), XWingLabel is
    # appended LAST: ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel).
    # (Draft changelog "Since draft-04": "Move label at the end.") Confirmed
    # against the reference xwing.py and the official KAT vectors.
    h = hashlib.sha3_256()
    h.update(ss_M)
    h.update(ss_X)
    h.update(ct_X)
    h.update(pk_X)
    h.update(XWING_LABEL)
    return h.digest()


@dataclass(frozen=True)
class XWingKeyPair:
    public_key: bytes   # XWING_PK_LEN bytes
    secret_key: bytes   # XWING_SK_LEN bytes


def generate_keypair(prefer_backend: str | None = None) -> XWingKeyPair:
    """Generate an X-Wing key pair.

    Returns concatenated (pk_M || pk_X) and (sk_M || sk_X).
    """
    backend = get_backend(prefer_backend)
    pk_M, sk_M = backend.keygen()

    sk_x = X25519PrivateKey.generate()
    pk_X = sk_x.public_key().public_bytes_raw()
    sk_X = sk_x.private_bytes_raw()

    return XWingKeyPair(
        public_key=pk_M + pk_X,
        secret_key=sk_M + sk_X,
    )


def encapsulate(public_key: bytes, prefer_backend: str | None = None) -> Tuple[bytes, bytes]:
    """Encapsulate to an X-Wing public key.

    Returns (shared_secret, ciphertext):
        shared_secret : 32 bytes
        ciphertext    : ct_M || ct_X  (XWING_CT_LEN bytes)
    """
    if len(public_key) != XWING_PK_LEN:
        raise ValueError(
            f"X-Wing public key must be {XWING_PK_LEN} bytes, got {len(public_key)}"
        )
    pk_M = public_key[:MLKEM768_PK_LEN]
    pk_X = public_key[MLKEM768_PK_LEN:]

    backend = get_backend(prefer_backend)
    ss_M, ct_M = backend.encaps(pk_M)

    eph = X25519PrivateKey.generate()
    ct_X = eph.public_key().public_bytes_raw()
    ss_X = eph.exchange(X25519PublicKey.from_public_bytes(pk_X))

    ss = _combiner(ss_M, ss_X, ct_X, pk_X)
    return ss, ct_M + ct_X


def decapsulate(ciphertext: bytes, secret_key: bytes, prefer_backend: str | None = None) -> bytes:
    """Decapsulate an X-Wing ciphertext. Returns the 32-byte shared secret."""
    if len(ciphertext) != XWING_CT_LEN:
        raise ValueError(
            f"X-Wing ciphertext must be {XWING_CT_LEN} bytes, got {len(ciphertext)}"
        )
    if len(secret_key) <= X25519_LEN:
        raise ValueError(
            f"X-Wing secret key too short: {len(secret_key)} bytes"
        )
    ct_M = ciphertext[:MLKEM768_CT_LEN]
    ct_X = ciphertext[MLKEM768_CT_LEN:]
    # sk_X is the fixed 32-byte suffix; sk_M is everything before it
    # (length depends on the backend's ML-KEM secret-key encoding).
    sk_M = secret_key[:-X25519_LEN]
    sk_X = secret_key[-X25519_LEN:]

    backend = get_backend(prefer_backend)
    ss_M = backend.decap(ct_M, sk_M)

    sk_x = X25519PrivateKey.from_private_bytes(sk_X)
    pk_X = sk_x.public_key().public_bytes_raw()
    ss_X = sk_x.exchange(X25519PublicKey.from_public_bytes(ct_X))

    return _combiner(ss_M, ss_X, ct_X, pk_X)
