# SecurePay — Campus Card-Payment Network

**MACS 902 Modern Cryptography · Assessment 1 (Design and Implementation)**

SecurePay is a payment network for a university campus (UOWD): students pay at
merchant terminals (canteen, espresso bar, library printing), a central
settlement switch ("Aani") moves the money, and every party can prove what
happened afterwards. It replaces an earlier Jupyter-notebook prototype and
fixes every weakness found in that prototype (see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), "Prototype weaknesses fixed").

Three independently runnable programs talk over **real TCP sockets**:

| Node | Command | Runs |
| --- | --- | --- |
| Settlement switch (ledger, registry, PKI) | `securepay run-switch` | one |
| Merchant point-of-sale terminal | `securepay run-terminal --merchant coffee_shop` | per till |
| Student wallet (authorises payments) | `securepay run-wallet --user 902101` | per student |

## Security properties

* **Confidentiality** — every application frame is encrypted with
  ChaCha20-Poly1305 (libsodium AEAD); the framing layer bounds message sizes.
* **Integrity** — AEAD tags plus strict per-direction monotonic counters
  reject modification, replay *and* reordering; frame timestamps bound delay.
* **Authentication** — mutual X.509 (Ed25519) certificates issued by a private
  campus CA, verified on every connection (chain, validity window, CRL, and
  registry enrolment with an exact key match).
* **Forward secrecy** — fresh X25519 ephemerals per handshake and automatic
  mid-session rekey (a fresh X25519 *inside* the authenticated channel,
  TLS-1.3-KeyUpdate style).
* **Non-repudiation** — merchants sign payment requests, students sign
  authorisations, the switch signs receipts; all three artefacts are stored
  and re-verifiable offline. The switch keeps a hash-chained, switch-signed,
  append-only audit log that is written atomically with each settlement.
* **At-rest protection** — all long-term keys (CA, switch, terminals,
  wallets) live in Argon2id-derived, ChaCha20-Poly1305-encrypted vaults
  (0600, atomic writes, brute-force lockout).

Every claim above is demonstrated live: `securepay attack --all` runs **15
attack cases** (bit-flip, AAD tamper, replay, reorder, stale frames, MITM
amount/key substitution, rogue/expired/revoked certificates, downgrade,
vault brute-force, malformed frames, double-spend) and all 15 must be
blocked — the run is part of CI.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"     # runtime deps are just pynacl + cryptography
```

Python ≥ 3.10. Only two vetted crypto libraries are used: PyNaCl (libsodium)
and `cryptography`.

## Quick start (three terminals)

```bash
# 0. provision a demo network (CA, keys, ledger, roster) — passphrases are
#    generated fresh and printed once; --write-passphrase-files stores them
#    (mode 0600) inside the network dir for the demo
securepay --network-dir network seed --write-passphrase-files

# 1. the switch (pick a port, or omit --port for the default 7440)
securepay --network-dir network run-switch --port 0 \
    --passphrase-file network/switch/switch.pass

# 2. a student wallet (listens for payment requests)
securepay --network-dir network run-wallet --user 902101 --auto-approve \
    --passphrase-file network/wallets/902101.pass

# 3. a merchant terminal (interactive: charge / balance / quit)
securepay --network-dir network run-terminal --merchant coffee_shop \
    --port <switch-port> --passphrase-file network/terminals/coffee_shop.pass
> charge 902101 12.50
PAYMENT_RESULT txn=TXN-… status=SETTLED
```

Or let the orchestrator do all of it (separate OS processes, real sockets):

```bash
securepay demo            # provisions, runs 3 processes, settles 2 payments,
                          # then verifies the audit chain and a receipt offline
securepay rekey-demo      # shows automatic epoch rekey mid-session
securepay attack --all    # runs the 15-case attack simulator (must be 15/15 PASS)
```

## Interactive dashboard (GUI)

```bash
securepay gui                 # opens http://127.0.0.1:8765 in your browser
securepay gui --no-browser    # headless VM: open the printed URL yourself
securepay gui --port 9000     # pick another port
```

A dark security dashboard for the live demonstration, served as **seven real
pages** (each has its own URL, so browser refresh, deep links and the back
button work) plus shared CSS/JS assets. It works fully offline (no CDN
scripts, fonts or services) and is laid out for normal 100% browser zoom,
from desktop down to phone width.

| Page | What it shows (all from real backend state) |
| --- | --- |
| `/` Overview | KPI cards (network provisioned?, switch running and port, registered students/merchants, saved receipts, attack results), network management (provision, start/stop the switch with a 3-step progress strip and confirmation dialogs), and links to the other pages |
| `/payment` | Payment terminal: student, merchant, amount in AED, approve/decline, a transaction confirmation with a copyable transaction ID and settlement status, and a 6-step transaction sequence reflecting the real outcome |
| `/accounts` | Accounts and balances (name, ID, role, balance, active/revoked, search and role filter) plus **enrol a new student** (certificate + encrypted vault + opening balance, with the vault passphrase shown once) and **Add funds** per account |
| `/attacks` | All 15 attacks as rows: name, description, mechanism under test, status, **Run This Attack**, expandable technical details; plus **Run all 15 attacks**, live `n/15 blocked` statistics, search/status filter and **Reset displayed results** |
| `/audit` | Verify the signed audit chain (settlements, student declines, rejections and top-ups), see the **Payment outcomes log**, pick a receipt and verify it offline, with clearly different verified/failed results and raw details |
| `/security` | Cards for confidentiality, integrity, authentication, key exchange, non-repudiation and key storage, each naming its source modules and linking to the attacks that test it (chips turn green/red with the latest result) |
| `/log` | Live switch log with INFO / WARNING / ERROR colouring, level filter, auto-follow that pauses when you scroll up, and a clear-display button; the page fetches only new lines via `GET /api/log?after=<n>` |

### Enrolling students and adding funds

The `/accounts` page wires up the existing CLI machinery for the demo:

* **Enrol student** runs `securepay issue-cert --role student --id … --name …
  --balance … --ca-passphrase-file network/ca.pass --write-passphrase-file
  network/wallets/<id>.pass`. It issues a real X.509 certificate and an
  Argon2id-encrypted wallet vault, appends the student to the registry, and
  creates the ledger account with the opening balance. The generated vault
  passphrase is shown **once** with a copy button (the `.pass` file inside
  the network dir is demo convenience only). The switch loads its registry
  at startup, so if it is running the dashboard stops it for the enrolment
  and restarts it automatically (behind a confirm dialog).
* **Add funds** runs `securepay topup --id … --amount …
  --switch-passphrase-file network/switch/switch.pass`: an admin operation
  authorised by the switch passphrase, applied in one atomic ledger
  transaction, and recorded as a switch-signed `TOPUP` entry in the audit
  chain — verify it on `/audit` with **Verify audit log**.

After an enrolment the student appears in the accounts table and the
`/payment` student picker without a manual reload (both derive from the
dashboard's live state).

### Running attacks one at a time

Every attack row has its own **Run This Attack** button. It calls
`POST /api/attack {"name": "<attack>"}`, which validates the name against the
simulator's `CASES` registry and then runs exactly
`securepay attack <name>` (fixed argument list, no shell). The simulator builds
a fresh throwaway lab for that one case, so the other 14 results are left alone
and your payment network is not touched. **Run all 15 attacks** still runs
`securepay attack --all`.

Result states: *Not Run*, *Running*, **BLOCKED – PASS** (the attack was stopped:
good), **NOT BLOCKED – FAIL** (the attack got through) and *Execution Error*
(the harness itself failed, so nothing is proven). Only one attack run can be in
flight at a time; a second request is refused rather than queued. Results are
kept by the dashboard process, so a page refresh keeps them and never triggers
an action; **Reset displayed results** clears only that display.

The dashboard contains **no protocol logic**. Each button runs the existing
`securepay` commands as separate OS processes over real TCP sockets, so it
exercises exactly the code the CLI and the tests exercise. It is treated as a
sensitive local service: it binds to `127.0.0.1` only, requires a random
per-run token on every API call (including the incremental log endpoint),
rejects any non-loopback `Host` header (DNS-rebinding defence), validates
every identifier, attack name and amount before it reaches a subprocess
argument list (no shell is ever used), serves pages and assets only from a
fixed in-memory table (no filesystem paths derived from URLs), sets a strict
Content-Security-Policy, and builds every page with DOM `textContent` only
(no HTML string insertion). It uses only the Python standard library, so
there are no new dependencies. The dashboard describes SecurePay as a custom
protocol (SP1), not TLS.

### Dashboard troubleshooting

```bash
securepay gui --check     # self-check: Python, libraries, child process, page + API, port
```

* Open exactly `http://127.0.0.1:<port>/` in a browser **on the same machine**.
  Any other host name or IP (a VM address, a forwarded name) is refused on
  purpose, and the refusal page says so.
* If port 8765 is busy (an older dashboard is still running), the new one
  prints that and picks a free port: use the URL it prints, or stop the old
  one with Ctrl-C.
* If no browser tab opens (headless VM, SSH session), start with `--no-browser`
  and open the printed URL yourself. A missing browser never stops the server.
* If a node fails to start, the error message under the button shows the
  node's own last output lines.

## Offline verification (anyone can audit)

```bash
securepay audit verify                 # recompute the hash chain + signatures
securepay audit log                    # settled / declined / rejected payments (chain re-verified)
securepay audit log --event payment_declined   # only payments the student declined
securepay verify-receipt --file network/receipts/<TXN-ID>.json
```

## CLI overview

| Command | Purpose |
| --- | --- |
| `seed` | provision a complete network (CA, nodes, vaults, ledger, roster) |
| `init-ca`, `issue-cert`, `revoke-cert`, `registry` | PKI administration |
| `run-switch`, `run-terminal`, `run-wallet` | run the three nodes |
| `charge`, `pay`, `balance`, `topup` | one-shot payment operations |
| `audit verify`, `audit log`, `verify-receipt` | offline evidence verification and payment-outcome listing |
| `attack [--all\|--list]`, `demo`, `rekey-demo` | demonstration tooling |
| `gui [--port N] [--no-browser]` | interactive local web dashboard |

Money is always an **integer number of fils** (1 AED = 100 fils); floats are
rejected by the canonical serialiser, and SQLite CHECK constraints back the
application-level invariants.

## Repository layout

```
src/securepay/
  config.py      all protocol constants (no magic numbers elsewhere)
  errors.py      exception hierarchy; every error has a wire-safe code
  encoding.py    canonical JSON, validators, money helpers, PAN masking
  framing.py     length-prefixed framing, partial-read safe, size limits
  ratelimit.py   token buckets + persistent unlock lockout
  keystore.py    Argon2id + ChaCha20-Poly1305 encrypted vaults
  pki.py         private CA: Ed25519 X.509 issuance, validation, CRL
  handshake.py   X25519 + Ed25519 + HKDF-SHA256 authenticated key exchange
  channel.py     AEAD record layer, counters, staleness, automatic rekey
  protocol.py    application messages, validation, signature payloads
  audit.py       hash-chained, switch-signed audit log
  ledger.py      SQLite settlement ledger (atomic, idempotent)
  switch.py      the settlement server (sessions, registry, payment flow)
  terminal.py    merchant client
  client.py      student wallet client + offline receipt verification
  bootstrap.py   network provisioning (seed / issue-cert / revoke-cert)
  cli.py         every command above
  gui.py         local web dashboard: seven real pages, stdlib only; drives the CLI
attacks/
    mitm_proxy.py    real TCP MITM proxy with frame-mutation hooks
    simulator.py     the 15 attack cases + in-process lab harness
tests/          unit, session-layer, e2e over real sockets, attacks, dashboard
docs/           ARCHITECTURE.md · DEMO_SCRIPT.md · CONTRIBUTING.md
```

## Quality gates (all green in CI)

```bash
ruff check src tests && ruff format --check src tests   # lint + format
mypy                                                    # typed (strict-adjacent)
bandit -c pyproject.toml -r src                         # SAST
pip-audit -r requirements.txt                           # dependency audit
pytest                                                  # 178 tests
python -m securepay attack --all                        # 15/15 must be PASS
```

## Honest limitations

This is educational software for a course project. In particular: the
demo writes passphrase files for convenience (a real deployment would prompt
interactively); the switch loads its entity registry at startup (revocation
is immediate via the CRL, but *enrolment* needs a restart — the dashboard
restarts the switch automatically when enrolling); key erasure in
Python is best-effort; and no external security audit has been performed.
The dashboard shares the passphrase-file limitation because it launches the
nodes as child processes. See docs/ARCHITECTURE.md §8 for the full list.

## Acknowledgements and citations

Libraries, standards and any AI tools or public code used are listed in
[docs/ACKNOWLEDGEMENTS.md](docs/ACKNOWLEDGEMENTS.md), as the course's academic
integrity policy requires.

## License

MIT — see [LICENSE](LICENSE).
