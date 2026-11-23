# Acknowledgements and citations

The MACS 902 guidelines require that AI tools and public code are cited.
This file is the project's single place for that.

## Cryptographic libraries (runtime dependencies)

| Library | Version | Used for |
| --- | --- | --- |
| [PyNaCl](https://pynacl.readthedocs.io/) (libsodium bindings) | 1.6.2 | ChaCha20-Poly1305 AEAD, X25519, Ed25519, Argon2id, random bytes |
| [cryptography](https://cryptography.io/) | 44.0.3 | X.509 certificates and CRLs, HKDF-Expand |

## Standards and designs followed

* RFC 5869 (HKDF), RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 8439
  (ChaCha20-Poly1305), RFC 5280 (X.509 / CRL), RFC 9106 (Argon2).
* The handshake and key-update design are modelled on TLS 1.3 (RFC 8446) and
  the Noise protocol framework; see `docs/ARCHITECTURE.md` §2.2.

## Developer tooling (not shipped at runtime)

pytest, ruff, mypy, bandit, pip-audit (versions pinned in `pyproject.toml`).
The web dashboard (`securepay gui`) uses only the Python standard library.

## AI tools and public code

> **Group to complete before submitting.** List every AI assistant and every
> piece of public code (repositories, snippets, tutorials) used, what it was
> used for, and which files it touched. If none were used, say so explicitly.

| Tool / source | Used for | Files / sections affected |
| --- | --- | --- |
| _e.g. name and version of the AI tool_ | _e.g. drafting the web dashboard_ | _e.g. `src/securepay/gui.py`, `tests/test_gui.py`_ |

Every group member remains responsible for understanding and being able to
explain all submitted code in the presentation.
