"""Object-style API: the same flow via the XWing class.

The class returns values in the SAME order as the functional API:
encapsulate() -> (shared_secret, ciphertext).
"""

from xwing_kem import XWing


def main() -> None:
    kem = XWing()
    print("active backend:", kem.backend_name)

    public_key, secret_key = kem.generate_keypair()
    shared_sender, ciphertext = kem.encapsulate(public_key)
    shared_recipient = kem.decapsulate(ciphertext, secret_key)

    assert shared_sender == shared_recipient
    print("shared secret :", shared_sender.hex())
    print("OK: round-trip agrees.")


if __name__ == "__main__":
    main()
