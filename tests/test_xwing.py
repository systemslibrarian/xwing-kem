import hashlib

import pytest

import xwing_kem
from xwing_kem import (
    XWing,
    decapsulate,
    encapsulate,
    generate_keypair,
    SHARED_SECRET_LEN,
    XWING_CT_LEN,
    XWING_PK_LEN,
    XWING_LABEL,
)
from xwing_kem._core import _combiner, X25519_LEN


def test_label_is_six_bytes():
    # The X-Wing sigil label, draft section 5.3.
    assert XWING_LABEL == b"\\.//^\\"
    assert len(XWING_LABEL) == 6


def test_roundtrip_functional():
    kp = generate_keypair()
    ss_a, ct = encapsulate(kp.public_key)
    ss_b = decapsulate(ct, kp.secret_key)
    assert ss_a == ss_b
    assert len(ss_a) == SHARED_SECRET_LEN == 32


def test_roundtrip_class():
    kem = XWing()
    pk, sk = kem.generate_keypair()
    ct, ss = kem.encapsulate(pk)
    ss2 = kem.decapsulate(ct, sk)
    assert ss == ss2


def test_public_key_and_ciphertext_sizes():
    kp = generate_keypair()
    assert len(kp.public_key) == XWING_PK_LEN == 1216
    _, ct = encapsulate(kp.public_key)
    assert len(ct) == XWING_CT_LEN == 1120
    # Secret key length is backend-dependent (seed vs expanded ML-KEM SK)
    # but must always end with the 32-byte X25519 secret.
    assert len(kp.secret_key) > X25519_LEN


def test_distinct_encapsulations_differ():
    kp = generate_keypair()
    ss1, ct1 = encapsulate(kp.public_key)
    ss2, ct2 = encapsulate(kp.public_key)
    assert ct1 != ct2
    assert ss1 != ss2  # ephemeral X25519 + ML-KEM randomness


def test_tampered_ciphertext_changes_secret():
    kp = generate_keypair()
    ss, ct = encapsulate(kp.public_key)
    tampered = bytearray(ct)
    tampered[-1] ^= 0x01  # flip a bit in ct_X
    ss_bad = decapsulate(bytes(tampered), kp.secret_key)
    assert ss_bad != ss


def test_combiner_omits_mlkem_ciphertext():
    # X-Wing must NOT mix in ct_M. The combiner signature only accepts
    # ss_M, ss_X, ct_X, pk_X -- there is no parameter for ct_M.
    ss_M = b"\x01" * 32
    ss_X = b"\x02" * 32
    ct_X = b"\x03" * 32
    pk_X = b"\x04" * 32
    # Draft combiner order: components first, XWingLabel appended LAST.
    expected = hashlib.sha3_256(ss_M + ss_X + ct_X + pk_X + XWING_LABEL).digest()
    assert _combiner(ss_M, ss_X, ct_X, pk_X) == expected


def test_wrong_public_key_length_rejected():
    with pytest.raises(ValueError):
        encapsulate(b"\x00" * 100)


def test_wrong_ciphertext_length_rejected():
    kp = generate_keypair()
    with pytest.raises(ValueError):
        decapsulate(b"\x00" * 100, kp.secret_key)


def test_backend_reports_name():
    name = xwing_kem.active_backend()
    assert name in ("cryptography", "liboqs")
