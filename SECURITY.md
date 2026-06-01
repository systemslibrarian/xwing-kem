# Security Policy

## Maturity and intended use

`xwing-kem` is an implementation of the X-Wing hybrid KEM intended for
study, prototyping, and migration experimentation. Please read
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) in full before relying on it. In particular,
as of the current release it is **not validated against official X-Wing
Known-Answer-Test vectors**, and the Python combiner glue carries no
constant-time guarantee. Do not deploy it to protect production secrets until
the KAT gap is closed and you have performed your own review.

The underlying lattice and curve operations are performed by vetted C
libraries (pyca/cryptography or liboqs); this package does not reimplement any
cryptographic primitive.

## Reporting a vulnerability

If you believe you have found a security issue, please report it privately
rather than opening a public issue:

- Email: paul@systemslibrarian.dev
- Use the GitHub "Report a vulnerability" feature on the repository's Security
  tab if enabled.

Please include a description, affected version, and a minimal reproduction if
possible. You can expect an acknowledgment within a reasonable time; this is a
volunteer-maintained project, so please be patient.

## Scope

In scope: incorrect cryptographic output, deviations from the X-Wing draft,
backend-selection flaws that silently weaken security, and input-handling bugs.

Out of scope: theoretical concerns about ML-KEM-768 or X25519 themselves
(report those upstream), and timing characteristics of the Python glue layer,
which are documented as a known limitation rather than a vulnerability.

---

Soli Deo Gloria — 1 Corinthians 10:31.
