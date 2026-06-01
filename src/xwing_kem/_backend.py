"""ML-KEM-768 backend selection for xwing-kem.

Prefers pyca/cryptography's native ML-KEM (available as of cryptography
v48.0.0 when built against OpenSSL 3.5.0+, AWS-LC, or BoringSSL). Falls
back to liboqs-python if the cryptography wheel in use does not expose
ML-KEM (e.g. wheels statically linked against an OpenSSL build without
PQC).

The backend abstracts exactly three operations, matching the draft's
ML-KEM-768 dependency surface:

    keygen()          -> (pk_M: bytes, sk_M: bytes)
    encaps(pk_M)      -> (ss_M: bytes, ct_M: bytes)
    decap(ct_M, sk_M) -> ss_M: bytes

Constant-time note: both backends perform the lattice operations in C.
The constant-time properties are inherited from those C implementations;
the SHA3-256 combiner glue in this package (see _core.py) operates only
on fixed-length public/shared values and performs no secret-dependent
branching. See KNOWN-GAPS.md for the full honest accounting.
"""

from __future__ import annotations

from typing import Protocol, Tuple


class MLKEMBackend(Protocol):
    name: str

    def keygen(self) -> Tuple[bytes, bytes]: ...
    def encaps(self, pk_M: bytes) -> Tuple[bytes, bytes]: ...
    def decap(self, ct_M: bytes, sk_M: bytes) -> bytes: ...


def _try_cryptography() -> "MLKEMBackend | None":
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem  # type: ignore
    except Exception:
        return None

    # The module may import but raise UnsupportedAlgorithm at use time when
    # the linked OpenSSL lacks ML-KEM. Probe once with a real keygen.
    class _CryptographyBackend:
        name = "cryptography"

        def keygen(self) -> Tuple[bytes, bytes]:
            sk = mlkem.MLKEM768PrivateKey.generate()
            pk = sk.public_key()
            # private_bytes_raw() returns the 64-byte seed in this API;
            # it is reloaded via from_seed_bytes (there is no
            # from_private_bytes for ML-KEM in cryptography 48).
            return (
                pk.public_bytes_raw(),
                sk.private_bytes_raw(),
            )

        def encaps(self, pk_M: bytes) -> Tuple[bytes, bytes]:
            pk = mlkem.MLKEM768PublicKey.from_public_bytes(pk_M)
            ss_M, ct_M = pk.encapsulate()
            return ss_M, ct_M

        def decap(self, ct_M: bytes, sk_M: bytes) -> bytes:
            sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(sk_M)
            return sk.decapsulate(ct_M)

    backend = _CryptographyBackend()
    try:
        pk, sk = backend.keygen()
        ss, ct = backend.encaps(pk)
        if backend.decap(ct, sk) != ss:
            return None
    except Exception:
        return None
    return backend


def _try_liboqs() -> "MLKEMBackend | None":
    try:
        import oqs  # type: ignore
    except Exception:
        return None

    class _LiboqsBackend:
        name = "liboqs"
        _alg = "ML-KEM-768"

        def keygen(self) -> Tuple[bytes, bytes]:
            with oqs.KeyEncapsulation(self._alg) as kem:
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()
            return pk, sk

        def encaps(self, pk_M: bytes) -> Tuple[bytes, bytes]:
            with oqs.KeyEncapsulation(self._alg) as kem:
                ct_M, ss_M = kem.encap_secret(pk_M)
            return ss_M, ct_M

        def decap(self, ct_M: bytes, sk_M: bytes) -> bytes:
            with oqs.KeyEncapsulation(self._alg, secret_key=sk_M) as kem:
                return kem.decap_secret(ct_M)

    backend = _LiboqsBackend()
    try:
        pk, sk = backend.keygen()
        ss, ct = backend.encaps(pk)
        if backend.decap(ct, sk) != ss:
            return None
    except Exception:
        return None
    return backend


_CACHED: "MLKEMBackend | None" = None


def get_backend(prefer: str | None = None) -> "MLKEMBackend":
    """Return a working ML-KEM-768 backend.

    prefer: 'cryptography' or 'liboqs' to force a choice; None to
            auto-select (cryptography first, then liboqs).
    Raises RuntimeError if no backend is available.
    """
    global _CACHED
    if prefer is None and _CACHED is not None:
        return _CACHED

    order = []
    if prefer == "cryptography":
        order = [_try_cryptography]
    elif prefer == "liboqs":
        order = [_try_liboqs]
    elif prefer is None:
        order = [_try_cryptography, _try_liboqs]
    else:
        raise ValueError(f"unknown backend preference: {prefer!r}")

    for factory in order:
        backend = factory()
        if backend is not None:
            if prefer is None:
                _CACHED = backend
            return backend

    raise RuntimeError(
        "No ML-KEM-768 backend available. Install either "
        "'cryptography>=48' built against OpenSSL 3.5+/AWS-LC/BoringSSL, "
        "or 'liboqs-python' (pip install liboqs-python, requires liboqs.so)."
    )
