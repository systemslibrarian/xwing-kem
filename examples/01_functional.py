"""Functional API: the three-call X-Wing flow.

    generate_keypair() -> XWingKeyPair(public_key, secret_key)
    encapsulate(pk)    -> (shared_secret, ciphertext)
    decapsulate(ct, sk)-> shared_secret
"""

from xwing_kem import generate_keypair, encapsulate, decapsulate


def main() -> None:
    # Recipient generates a long-term key pair and publishes public_key.
    kp = generate_keypair()

    # Sender encapsulates to the recipient's public key.
    shared_sender, ciphertext = encapsulate(kp.public_key)

    # Recipient recovers the same shared secret from the ciphertext.
    shared_recipient = decapsulate(ciphertext, kp.secret_key)

    assert shared_sender == shared_recipient
    print("public key :", len(kp.public_key), "bytes")
    print("ciphertext :", len(ciphertext), "bytes")
    print("shared secret:", shared_sender.hex())
    print("OK: sender and recipient agree on the shared secret.")


if __name__ == "__main__":
    main()
