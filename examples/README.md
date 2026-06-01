# xwing-kem examples

Runnable, self-contained scripts. Each one prints what it does and exits 0 on
success.

```bash
pip install xwing-kem            # or: pip install "xwing-kem[liboqs]"
python examples/01_functional.py
python examples/02_class.py
python examples/03_backend_selection.py
python examples/04_encrypt_message.py
```

| Script                     | Shows                                                  |
| -------------------------- | ------------------------------------------------------ |
| `01_functional.py`         | The functional API: keygen → encapsulate → decapsulate |
| `02_class.py`              | The object-style `XWing` API (same return order)       |
| `03_backend_selection.py`  | Inspecting and pinning the ML-KEM backend              |
| `04_encrypt_message.py`    | Using the 32-byte shared secret as an AES-GCM key      |

`encapsulate()` returns `(shared_secret, ciphertext)` in **both** APIs.
