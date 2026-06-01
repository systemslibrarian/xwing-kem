"""Inspecting and pinning the ML-KEM backend.

By default the backend is auto-selected (native `cryptography` first, then
`liboqs`) and cached. You can report it, or pin a specific one. Pinning an
unavailable backend raises rather than silently falling back.
"""

import xwing_kem
from xwing_kem import generate_keypair, encapsulate, decapsulate


def main() -> None:
    print("auto-selected backend:", xwing_kem.active_backend())

    for choice in ("cryptography", "liboqs"):
        try:
            kp = generate_keypair(prefer_backend=choice)
            ss, ct = encapsulate(kp.public_key, prefer_backend=choice)
            assert decapsulate(ct, kp.secret_key, prefer_backend=choice) == ss
            print(f"  {choice:13}: available, round-trip OK")
        except Exception as exc:  # backend not installed/usable on this machine
            print(f"  {choice:13}: unavailable ({type(exc).__name__})")


if __name__ == "__main__":
    main()
