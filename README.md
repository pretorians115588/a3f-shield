# A3F Shield research prototype

Author: `pretorians115588/Andrw`

A3F Shield is experimental research software for authenticated file
encryption, native Threefish-1024 experimentation, and replay-witness state.
It is not a standardized cryptosystem, a certified security product, or a
replacement for BitLocker or an independently reviewed encryption library.

## Scope

The v4 component provides an authenticated file format using AES-GCM-SIV,
native Threefish-1024, per-file derivation, authenticated manifests, and
fail-closed output publication. The v6 witness is a separate experimental
prototype. It demonstrates monotonic generations and challenge-bound receipts;
it is not wired into the v4 CLI in this release candidate.

Replay protection requires an independently trusted witness state. A local
database and its secret are not an unrollbackable security boundary. A complete
rollback of all witness state and every external checkpoint is indistinguish-
able from the historical state without an independent non-rollbackable system.

## Build and test

```text
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
python -m pytest -q
```

The native implementation is built from `native/threefish1024.c`. Windows
validation requires x64 MSVC Build Tools and is documented in
`docs/VALIDATION.md`. No precompiled binary is part of the repository.

## Security status

This is a research prototype. It has no independent cryptographic audit, no
formal certification, and no promise of constant-time behaviour on every
compiler or processor. Read `SECURITY.md` and `docs/THREAT_MODEL.md` before
using the code.

## Repository layout

- `src/` – v4 encryption and supporting modules
- `native/` – C source only
- `tests/` – v4, native, pipeline, and security tests
- `experimental/witness-v6/` – standalone replay-witness research
- `scripts/` – validation and profiling helpers
- `docs/` – threat model and reproducibility notes

