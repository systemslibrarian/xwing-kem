# Contributing

Thanks for your interest in improving `xwing-kem`. This is a small, deliberately
narrow library, so contributions are most valuable when they sharpen
correctness, validation, or honesty rather than expand scope.

## The most wanted contribution

**Closing the KAT gap.** The single highest-value change is wiring up official
Known-Answer-Test validation. See the "Test-vector validation" section of
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) and the scaffold in `tests/test_kat.py`. If you
can supply `tests/xwing_kat.json` from the draft reference and complete the two
marked assertions against a derandomized backend, that moves the package from
"round-trip-tested" to "spec-validated."

## Ground rules

- **Do not change the cryptographic construction.** The combiner is
  `SHA3-256(label || ss_M || ss_X || ct_X || pk_X)` with the ML-KEM ciphertext
  omitted, per the draft. Changes to this require a spec citation and review.
- **Keep the dual-backend design.** cryptography preferred, liboqs fallback.
- **Keep `KNOWN-GAPS.md` honest.** If a change closes a gap, update it. Never
  remove a caveat that is still true.
- **No new dependencies** without strong justification.

## Development setup

```bash
git clone https://github.com/systemslibrarian/xwing-kem
cd xwing-kem
pip install -e ".[dev]"
pytest -v
```

For a guaranteed ML-KEM backend (and to run the KAT harness once vectors are
present):

```bash
pip install -e ".[dev,liboqs]"
```

## Pull requests

- Add or update tests for any behavior change.
- Run `pytest` and `python -m build && twine check dist/*` before submitting.
- Keep commits focused; describe *why*, not just *what*.

---

Soli Deo Gloria — 1 Corinthians 10:31.
