"""End-to-end sealing: use the X-Wing shared secret as an AES-GCM key.

This is the typical real-world shape: a KEM gives both parties the same 32-byte
secret, which you feed to an AEAD to encrypt actual data. `cryptography` is a
dependency of xwing-kem, so AESGCM is already available.

    sender:    (ss, ct) = encapsulate(recipient_pk);  seal data under ss
    recipient: ss = decapsulate(ct, sk);              open data under ss
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from xwing_kem import generate_keypair, encapsulate, decapsulate


def main() -> None:
    plaintext = b"Attack at dawn -- but post-quantum."

    # Recipient publishes public_key; keeps secret_key.
    kp = generate_keypair()

    # --- Sender side -------------------------------------------------------
    shared, ciphertext = encapsulate(kp.public_key)
    nonce = os.urandom(12)
    sealed = AESGCM(shared).encrypt(nonce, plaintext, associated_data=None)
    # Wire format you'd transmit: KEM ciphertext + nonce + AEAD ciphertext.
    wire = ciphertext + nonce + sealed

    # --- Recipient side ----------------------------------------------------
    ct = wire[:len(ciphertext)]
    nonce = wire[len(ciphertext):len(ciphertext) + 12]
    sealed = wire[len(ciphertext) + 12:]
    shared_r = decapsulate(ct, kp.secret_key)
    recovered = AESGCM(shared_r).decrypt(nonce, sealed, associated_data=None)

    assert recovered == plaintext
    print("plaintext :", plaintext.decode())
    print("wire bytes:", len(wire), "(kem ct + nonce + aead ct)")
    print("recovered :", recovered.decode())
    print("OK: decrypted with the X-Wing-derived key.")


if __name__ == "__main__":
    main()
