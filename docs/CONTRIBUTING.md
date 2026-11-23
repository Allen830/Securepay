# Contributing to SecurePay

This is a course project (MACS 902, Assessment 1), but the workflow below
is what CI enforces on every push — a PR that fails any gate is not merged.

## Setup

```bash
python3 -m venv .venv                # Python >= 3.10
.venv/bin/pip install -e ".[dev]"
```

Runtime dependencies are deliberately just two vetted crypto libraries
(PyNaCl and `cryptography`); anything new must justify itself.

## Before every push

```bash
make lint        # ruff check + ruff format --check
make typecheck   # mypy (full annotations enforced)
make security    # bandit + pip-audit on requirements.txt
make test        # pytest (178 tests incl. the slow attack and dashboard suites)
make attacks     # python -m securepay attack --all  (must be 15/15 PASS)
```

or run `make format` first to auto-fix style. The same commands run in CI
on Python 3.10 and 3.12 (`.github/workflows/ci.yml`).

## Non-negotiable rules

1. **No new crypto primitives.** Use libsodium via `pki.py` /
   `handshake.py` / `keystore.py`. Never hand-roll an encoder, a KDF, or
   padding.
2. **No magic numbers.** Every protocol bound lives in `config.py`. If a
   test or demo needs to weaken one, use `config.temporary(...)` (whitelisted,
   self-restoring) — never edit the default.
3. **Validate before use.** Every field that arrives from the network or
   disk goes through an `encoding.validate_*` / `protocol.validate_*`
   function before any business logic runs.
4. **Errors carry wire-safe codes.** Raise the precise subclass from
   `errors.py`; detailed reasons go to the local log, never to the peer.
5. **Money is integer fils.** Floats are rejected by the canonical
   serialiser; keep it that way.
6. **Every security claim needs a test.** If you add or change a defence,
   add or update the attack case / test that proves it, and update the
   "Security properties" notes in the module docstring and
   `docs/ARCHITECTURE.md`.
7. **No secrets in the repo.** The `network/` directory (vaults, ledger,
   passphrases, receipts) is git-ignored and must stay that way.

## Commit style

Short imperative subject, body explaining *why* (the diff already says
what). Example:

```
Enforce per-merchant identity on payment requests

A terminal could previously register a request under any merchant_id.
Bind the request to the session identity and verify the signature
against the registry key for THAT merchant. Covered by
test_merchant_cannot_charge_for_another_merchant.
```

## Adding an attack case

1. Write `attack_<name>(lab)` in `attacks/simulator.py`; return
   `(passed, detail)` where `passed=True` only when the attack is blocked
   for the *intended* reason (use `_expect_blocked(..., "expected_code")`).
2. Register it in `CASES` with a one-line description.
3. Add a line to the table in `docs/DEMO_SCRIPT.md` from a real run.

## Housekeeping

* `make clean` removes caches and the `network/` runtime directory.
* Keep docstrings current — the module docstrings double as the security
  property inventory for the report.
* If a check tool flags something you believe is a false positive, silence
  it *narrowly* (`# noqa: CODE - reason` / a commented config skip), never
  file-wide.
