"""Known-Answer-Test (KAT) validation against the official X-Wing vectors.

WHAT THIS VALIDATES, AND THE HONEST LIMIT
-----------------------------------------
The X-Wing draft ships deterministic vectors: a fixed 32-byte seed expands to
the key material, and fixed encapsulation coins produce a fixed ciphertext and
shared secret. There are therefore THREE things we can attempt to validate,
each with different backend requirements:

  (A) KEYGEN from seed  -> the X-Wing public key bytes.
        liboqs-python (>=0.14.0) exposes derandomized generate_keypair_seed(),
        so this CAN run -- once the SHAKE seed-expansion split is confirmed
        against the reference xwing.py (see the guard in the test).

  (B) ENCAPS from coins -> ciphertext + shared secret.
        Neither liboqs-python nor pyca/cryptography exposes a *seeded*
        encapsulation, so this half can only run against a derandomized
        reference implementation supplied via XWING_REF_ENCAPS.

  (C) COMBINER against intermediate components -> shared secret.
        Pure SHA3-256 over known inputs; runs EVERYWHERE with no backend, if
        the vector file includes the intermediate secrets.

Every part SKIPS independently with an explanatory message rather than passing
falsely. A skip is honest; a silently-green self-test would not be.

VECTOR FILE (`tests/xwing_kat.json`), all values hex-encoded:
    {
      "seed":        "<32 bytes>",     # X-Wing KeyGen seed
      "expected_pk": "<1216 bytes>",   # pk_M (1184) || pk_X (32)
      "eseed":       "<64 bytes>",     # Encaps coins
      "expected_ct": "<1120 bytes>",   # ct_M (1088) || ct_X (32)
      "expected_ss": "<32 bytes>",     # shared secret
      # Optional, enables the backend-free combiner KAT (C):
      "ss_m": "<32>", "ss_x": "<32>", "ct_x": "<32>", "pk_x": "<32>"
    }

Obtain vectors from github.com/dconnolly/draft-connolly-cfrg-xwing-kem or a
trusted reference implementation. Do not hand-edit them.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from xwing_kem._core import _combiner

HERE = os.path.dirname(__file__)
KAT_PATH = os.path.join(HERE, "xwing_kat.json")


def _raw_vector_list():
    """Return the list of raw (hex-encoded) KAT vectors, or [] if the file is
    absent. The file holds {"_comment": ..., "vectors": [ {...}, ... ]}; a
    legacy single top-level vector object is also accepted for compatibility.
    Used at collection time to size the parametrization -- never skips here.
    """
    if not os.path.exists(KAT_PATH):
        return []
    with open(KAT_PATH) as fh:
        doc = json.load(fh)
    if isinstance(doc, dict) and "vectors" in doc:
        return list(doc["vectors"])
    return [doc]  # legacy: a single vector object at the top level


# Sized at import time so each test is parametrized once per official vector.
# When the file is missing we still emit one parametrization (idx 0) so the
# test appears and SKIPs with an explanatory message rather than vanishing.
_NUM_VECTORS = len(_raw_vector_list())
_VECTOR_IDS = list(range(_NUM_VECTORS)) if _NUM_VECTORS else [0]


def _load_vector(idx: int):
    """Parse vector `idx` to bytes, or skip if the KAT file is absent."""
    raw_list = _raw_vector_list()
    if not raw_list:
        pytest.skip(
            f"No official X-Wing KAT file at {KAT_PATH}. "
            "Add tests/xwing_kat.json from the draft reference to enable "
            "spec-conformance validation. Until then this package is "
            "UNVALIDATED against official vectors (see KNOWN-GAPS.md)."
        )
    raw = raw_list[idx]
    # Keys beginning with "_" are metadata (e.g. "_comment" provenance), not
    # hex vector material -- skip them so they don't reach bytes.fromhex().
    return {k: bytes.fromhex(v) for k, v in raw.items() if not k.startswith("_")}


def _require_liboqs():
    try:
        import oqs  # noqa: F401
        return oqs
    except Exception:
        pytest.skip(
            "Keygen KAT requires liboqs-python (>=0.14.0), which exposes "
            'derandomized generate_keypair_seed(). Install with: '
            'pip install "xwing-kem[liboqs]".'
        )


# Set to True only after you have checked the SHAKE-256 seed-expansion split
# in _xwing_keygen_from_seed() byte-for-byte against the draft's reference
# xwing.py (Appendix B). Leaving it False keeps the keygen KAT in a safe SKIP
# rather than asserting on an unconfirmed expansion.
#
# CONFIRMED against draft-connolly-cfrg-xwing-kem/spec/xwing.py,
# expandDecapsulationKey() (verbatim):
#
#     def expandDecapsulationKey(seed):
#         expanded = hashlib.shake_256(seed).digest(length=96)
#         pkM, skM = mlkem.KeyGen(expanded[0:64], mlkem.params768)
#         skX = expanded[64:96]
#         pkX = x25519.X(skX, x25519.BASE)
#         return skM, skX, pkM, pkX
#
# i.e. SHAKE-256(seed) -> 96 bytes; bytes [0:64] are the ML-KEM-768 keygen seed
# (d || z), bytes [64:96] are the X25519 scalar; ML-KEM first, X25519 second.
# _xwing_keygen_from_seed() below uses exactly that split (shake_256, digest 96,
# [:64] -> mlkem_seed, [64:96] -> x25519 scalar). The match was also verified
# empirically: the reference reproduces expected_pk from the seed, and liboqs
# generate_keypair_seed() over expanded[0:64] reproduces the same pk_M.
_SEED_EXPANSION_CONFIRMED = True


def _xwing_keygen_from_seed(oqs, seed: bytes) -> bytes:
    """Deterministically derive the X-Wing public key from the 32-byte seed.

    Per the draft's key derivation, the seed is expanded with SHAKE-256 into
    the ML-KEM-768 keygen randomness and the 32-byte X25519 private scalar.
    Returns the X-Wing public key (pk_M || pk_X).

    WARNING: the exact byte split below is a best-effort reconstruction and
    MUST be confirmed against the reference xwing.py before being trusted.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    expanded = hashlib.shake_256(seed).digest(64 + 32)
    mlkem_seed = expanded[:64]          # ML-KEM derand seed (d || z)
    x25519_sk_bytes = expanded[64:96]   # X25519 scalar

    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        mlkem_pk = kem.generate_keypair_seed(mlkem_seed)

    x25519_sk = X25519PrivateKey.from_private_bytes(x25519_sk_bytes)
    x25519_pk = x25519_sk.public_key().public_bytes_raw()
    return mlkem_pk + x25519_pk


# --------------------------------------------------------------------------- #
# (A) KEYGEN-from-seed KAT
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("idx", _VECTOR_IDS)
def test_kat_keygen_public_key(idx):
    vectors = _load_vector(idx)
    oqs = _require_liboqs()

    if not _SEED_EXPANSION_CONFIRMED:
        pytest.skip(
            "Keygen KAT is wired for liboqs, but the SHAKE-256 seed-expansion "
            "split in _xwing_keygen_from_seed() has not been confirmed against "
            "the draft reference xwing.py. Confirm it, set "
            "_SEED_EXPANSION_CONFIRMED = True, and this test will assert "
            "derived_pk == expected_pk."
        )

    derived_pk = _xwing_keygen_from_seed(oqs, vectors["seed"])
    assert derived_pk == vectors["expected_pk"], (
        "X-Wing public key derived from seed does not match the KAT vector"
    )


# --------------------------------------------------------------------------- #
# (B) ENCAPS-from-coins KAT  -- needs a derandomized reference encaps
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("idx", _VECTOR_IDS)
def test_kat_encaps_shared_secret(idx):
    vectors = _load_vector(idx)
    ref_path = os.environ.get("XWING_REF_ENCAPS")
    if not ref_path:
        pytest.skip(
            "Encaps KAT requires a derandomized reference encapsulation. "
            "Neither liboqs-python nor pyca/cryptography exposes seeded "
            "encapsulation, so this half cannot run on those backends. Set "
            "XWING_REF_ENCAPS to the directory holding the draft reference "
            "xwing.py (e.g. draft-connolly-cfrg-xwing-kem/spec, with its "
            "kyber submodule initialised and pycryptodome installed) to "
            "enable it. The combiner itself is independently validated by "
            "test_kat_combiner_against_vector_components above."
        )

    # Import the reference xwing.py from XWING_REF_ENCAPS. This is an
    # INDEPENDENT implementation (the draft's spec code over ML-KEM-768 +
    # X25519), never src/xwing_kem -- so the check is non-circular.
    import importlib
    import sys

    if not os.path.isdir(ref_path):
        pytest.skip(f"XWING_REF_ENCAPS={ref_path!r} is not a directory.")
    sys.path.insert(0, ref_path)
    try:
        ref = importlib.import_module("xwing")
    except Exception as exc:  # missing kyber submodule / pycryptodome / etc.
        pytest.skip(
            f"Could not import reference xwing.py from {ref_path!r}: {exc}. "
            "Ensure the kyber submodule is initialised and pycryptodome is "
            "installed."
        )
    finally:
        # Leave sys.path as we found it on the error paths above; on success we
        # keep it so the module's own imports stay resolvable for this process.
        pass

    # Derandomized reference encaps from the KAT coins + public key.
    ss, ct = ref.EncapsulateDerand(vectors["expected_pk"], vectors["eseed"])

    assert ct == vectors["expected_ct"], (
        "reference ciphertext from eseed does not match the KAT vector"
    )
    assert ss == vectors["expected_ss"], (
        "reference shared secret from eseed does not match the KAT vector"
    )

    # Cross-check our own combiner against the reference-derived components:
    # both must yield the same KAT shared secret.
    pk_M = vectors["expected_pk"][:1184]
    pk_X = vectors["expected_pk"][1184:]
    ek_X = vectors["eseed"][32:64]
    import x25519  # provided alongside the reference xwing.py
    import mlkem
    ct_X = x25519.X(ek_X, x25519.BASE)
    ss_X = x25519.X(ek_X, pk_X)
    ct_M, ss_M = mlkem.Enc(pk_M, vectors["eseed"][0:32], mlkem.params768)
    assert _combiner(ss_M, ss_X, ct_X, pk_X) == vectors["expected_ss"], (
        "our _combiner over reference-derived components != KAT shared secret"
    )


# --------------------------------------------------------------------------- #
# (C) COMBINER KAT  -- ALWAYS runnable, no backend needed
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("idx", _VECTOR_IDS)
def test_kat_combiner_against_vector_components(idx):
    vectors = _load_vector(idx)
    needed = ("ss_m", "ss_x", "ct_x", "pk_x", "expected_ss")
    if not all(k in vectors for k in needed):
        pytest.skip(
            "Vector file lacks intermediate components (ss_m, ss_x, ct_x, "
            "pk_x). Add them to validate the combiner against the KAT with no "
            "backend dependency."
        )
    got = _combiner(vectors["ss_m"], vectors["ss_x"], vectors["ct_x"], vectors["pk_x"])
    assert got == vectors["expected_ss"], "combiner output != KAT shared secret"
