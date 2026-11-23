# SecurePay Architecture

This document explains what the system does, how each security property is
achieved, which prototype weaknesses were fixed, and what remains outside
the threat model. It is written to be read alongside the code: every claim
names the module and test that enforces it.

## 1. System overview

```
        ┌──────────────────┐        ┌──────────────────┐
        │  Merchant POS    │        │  Student Wallet  │
        │  (terminal.py)   │        │  (client.py)     │
        │  Ed25519 key in  │        │  Ed25519 key in  │
        │  encrypted vault │        │  encrypted vault │
        └────────┬─────────┘        └────────┬─────────┘
      X25519+Ed25519 handshake            X25519+Ed25519 handshake
      ChaCha20-Poly1305 channel            ChaCha20-Poly1305 channel
                 │  signed payment request        ▲
                 ▼                                  │ pushed authorisation
        ┌──────────────────────────────────────────┴─────────┐
        │                Aani Settlement Switch               │
        │  registry (enrolment) · PKI/CRL · rate limiting     │
        │  SQLite ledger + hash-chained signed audit log      │
        │  switch-signed receipts                             │
        └─────────────────────────────────────────────────────┘
```

A payment has three phases:

1. **Request-to-pay** — the merchant's terminal signs
   `{txn, payer, amount, currency, ts, channel-binding}` with its Ed25519
   key and sends it to the switch. The switch validates, verifies the
   signature against the *certificate-registered* merchant key, records the
   request as PENDING (idempotency: `txn_id` is a primary key), and pushes
   an authorisation request to the payer's wallet if online.
2. **Authorisation** — the wallet independently verifies the merchant
   certificate chain and signature, shows the request, and (on approval)
   signs `{txn, payer, merchant, amount, currency, ts, nonce,
   channel-binding}`. The nonce is per-payer monotonic and persisted in the
   wallet vault *before* sending.
3. **Settlement** — inside one SQLite `BEGIN IMMEDIATE` transaction the
   switch checks the PENDING row, enforces the monotonic nonce, debits the
   payer (guarded `UPDATE ... WHERE balance >= ?`), credits the merchant,
   stores both signatures and the receipt, and appends to the signed audit
   log. The receipt (switch-signed) goes to the wallet; the result goes to
   the terminal.

## 2. Cryptographic design

### 2.1 Algorithms (all libsodium / `cryptography`, no hand-rolled crypto)

| Purpose | Primitive | Where |
| --- | --- | --- |
| Signatures (identity + payments) | Ed25519 | `pki.py`, `protocol.py` |
| Key exchange | X25519 (ephemeral-ephemeral) | `handshake.py` |
| Key derivation | HKDF-SHA256 | `handshake.py` |
| Symmetric encryption | ChaCha20-Poly1305 (IETF), 12-byte nonce, 16-byte tag | `channel.py`, `keystore.py` |
| Passphrase KDF | Argon2id (opslimit 3, 64 MiB — libsodium "moderate") | `keystore.py` |
| Identity certificates | X.509, Ed25519 keys, private campus CA, signed CRL | `pki.py` |
| Transcript / audit hashing | SHA-256 | `handshake.py`, `audit.py` |

Justification for this suite: it is the modern libsodium baseline —
AEAD with integrated authentication, an AEAD built for the 96-bit nonce
model, a signature scheme with small keys and deterministic signatures, a
memory-hard KDF, and a certificate format that gives us expiry and
revocation semantics instead of a bespoke TOFU scheme. One AEAD (ChaCha20-
Poly1305) is used everywhere, including at rest, so there is a single
authenticated-encryption code path to review and test.

### 2.2 Handshake (SP1)

Message flow (all messages are canonical JSON inside length-prefixed
frames; `H()` is SHA-256 over length-prefixed canonical messages):

```
C → S  client_hello   {v, suite, id, eph_c, nonce_c, ts}
S → C  server_hello   {v, suite, id, eph_s, nonce_s, ts}
S → C  certificate    {role, cert_pem}
S → C  certificate_verify  Ed25519( "SP1/CV/server" || H(M1..M3) )
S → C  finished       HMAC-SHA256( fk_s, H(M1..M4) )
C → S  certificate    {role, cert_pem}
C → S  certificate_verify  Ed25519( "SP1/CV/client" || H(M1..M6) )
C → S  finished       HMAC-SHA256( fk_c, H(M1..M7) )
```

Key schedule:

```
prk        = HKDF-Extract(salt = nonce_c || nonce_s, ikm = X25519(ecdh))
fk_s/fk_c  = HKDF-Expand(prk, "SP1/finished/server|client")
th_final   = H(M1..M8)
c2s_key    = HKDF-Expand(prk, th_final || "SP1/app/c2s key")
s2c_key    = HKDF-Expand(prk, th_final || "SP1/app/s2c key")
c2s/s2c nonce prefixes = HKDF-Expand(prk, th_final || "SP1/app/… nonce")
session_id = HKDF-Expand(prk, th_final || "SP1/session id")   ← channel binding
```

Security consequences:

* **Full-transcript signatures** — each side signs the hash of *every*
  message so far. Modifying anything (version, suite, ephemeral key,
  nonce) breaks a signature, unlike the prototype, which signed only
  fragments of the hello.
* **Key confirmation** — `finished` is an HMAC under a key derived from
  the ECDH output, so it proves the peer derived the same keys. This is
  what catches ephemeral-key substitution (attack case `mitm-key-
  substitution`) even in the hypothetical case where signatures would
  match.
* **Downgrade protection** — version and suite are exact-match and inside
  the signed transcript (attack case `downgrade`).
* **Handshake replay** — a replayed server flight fails the client's
  `finished` check because the client contributes a fresh ephemeral.
* **Low-order points** — libsodium's `crypto_scalarmult` rejects them; we
  surface that as a `HandshakeError` (tested in `test_handshake.py`).

Certificate verification (`pki.verify_certificate`) performs, in order:
issuer-name match, CA signature over the TBS bytes, validity window at
"now", BasicConstraints `ca=False`, Ed25519 public key, CRL membership
(the CRL itself is signature-checked), then the switch's registry check
(subject, role, exact public key, not revoked). The CRL is **re-read from
disk for every handshake**, so revocation takes effect without a restart
(attack case `revoked-certificate`).

### 2.3 Record layer (channel)

Frame layout inside a length-prefixed message:

```
u32(header_len) || header_json || ciphertext+tag
header_json = {"dir","ep","n","sid","ts"}     ← this is the AEAD AAD
nonce = 4-byte per-direction prefix || 8-byte counter   (never transmitted)
```

Receive-side checks, in order: session id → direction → epoch → counter
(must equal the expected value exactly: both replays and future frames are
rejected) → timestamp freshness (±30 s) → AEAD open (AAD = the exact header
bytes received, which must also be canonical JSON).

**Automatic rekey.** After 1000 messages or 300 s in the current epoch,
the client (the session initiator, so there is no simultaneous-rekey race)
sends a `rekey` control message carrying a fresh X25519 public key —
*inside* the encrypted channel. The server replies with its own fresh
ephemeral under the *old* keys, and both sides install
`HKDF-Expand(HKDF-Extract(prk_prev, x25519_new), th_final || epoch-label)`
with counters restarted at 1. Keys are chained from the handshake PRK, so
an attacker who misses the rekey can never catch up; a session never
approaches nonce reuse (2^48 counters per direction per epoch, far below
any reuse bound). `securepay rekey-demo` shows epochs rotating live.

### 2.4 Key storage (keystore.py)

Vault file format (JSON, atomic write, 0600):

```
{format, version, kdf:"argon2id", kdf_params, cipher:"ChaCha20-Poly1305",
 salt, nonce, aad:{kind,id}, ciphertext}
```

* Argon2id at libsodium "moderate" (3 iterations, 64 MiB) makes offline
  guessing expensive; the parameters are *both* AEAD-authenticated and
  compared against the configured values on load, so rewriting them to
  cheaper values fails (test: `test_kdf_parameter_downgrade_rejected`).
* The vault metadata (owner id, kind) is the AAD: a vault renamed for
  another entity will not open.
* Online guessing is stopped by a persistent failure counter
  (`ratelimit.AttemptTracker`): after 5 wrong passphrases the vault is
  locked for 5 minutes *even for the correct passphrase* (attack case
  `vault-bruteforce`); the counter state survives restarts and a corrupt
  counter file fails closed.
* Card data: the wallet stores only a random opaque token plus a masked
  PAN (`****-****-****-1234`). The full PAN is never written anywhere and
  the CVV is never generated, collected, or transmitted.

### 2.5 Ledger and audit

SQLite schema highlights (`ledger.py`):

* `accounts.balance_minor INTEGER CHECK (balance_minor >= 0)` — the
  database itself refuses negative balances.
* `transactions.txn_id TEXT PRIMARY KEY` — persistent idempotency: a
  replayed request or authorisation for a settled txn is refused
  (`duplicate_txn`).
* `payer_nonces.last_nonce` — per-payer strictly monotonic nonce for
  cross-session replay defence.
* Debit/credit/nonce/receipt/audit all happen inside one
  `BEGIN IMMEDIATE` transaction, serialised by a process-wide lock: a
  crash leaves no partial state, and two concurrent sessions cannot
  interleave a balance check with a debit (no lost-update double spend).

The audit log (`audit.py`) is a hash chain: each entry's `hash_this`
covers `u32(seq) || u32(ts) || event || hash_prev || canonical(payload)`,
and each entry is signed with the switch's long-term Ed25519 key.
`securepay audit verify` recomputes the whole chain and checks every
signature offline (tests mutate/delete rows and assert detection).

**Top-ups.** `securepay topup --id <id> --amount <amt>
--switch-passphrase-file <path>` credits an existing account as an
*administrative* operation: the switch passphrase authorises it (the
operator proves possession of the switch vault key, exactly the key that
signs the audit chain), and `Ledger.credit` applies the guarded balance
update and appends a `TOPUP` audit entry **inside one `BEGIN IMMEDIATE`
transaction**, signed by the switch's long-term key — never a throwaway
key — so `securepay audit verify` keeps passing and every top-up is
provable afterwards. Unknown accounts, revoked entities and non-positive
or malformed amounts are refused before any state changes. Top-ups never
touch the payment path: no payment request, wallet or receipt is involved.

**Student declines.** A refusal is as provable as an approval. When the
student answers "no", the wallet signs a `payment_decline` message
(`WalletClient.decline`) under its **own domain tag** (`SP1/PAYMENT-DECLINE/v1`,
so a decline signature can never be replayed as an authorisation or vice
versa), over the exact transaction fields, a decision timestamp and the
wallet's session id (channel binding). The switch (`_handle_decline`)
checks that the wallet is the named payer, that the request is still
`PENDING` and matches its stored copy, and verifies the signature against
the enrolled key. `Ledger.decline_payment` then marks the request
`REJECTED` and appends a switch-signed **`payment_declined`** audit entry
(carrying the student's signature) inside one `BEGIN IMMEDIATE`
transaction. No money moves and no payer nonce is consumed. The wallet
gets an `auth_rejected` confirmation with reason `declined_by_payer`, and
the merchant is pushed a `payment_result` (`REJECTED`, same reason) at once
instead of waiting for a timeout. A settled payment cannot be declined, and
a declined one can never be authorised later. The status stays `REJECTED`
(no schema change, so existing ledgers keep working); the audit event
tells a student decline (`payment_declined`) apart from a switch-side
rejection (`payment_rejected`). `securepay audit log` lists every settled,
declined and rejected payment after re-verifying the chain.

### 2.6 Protocol-message signing (protocol.py)

All signatures are over **domain-tagged canonical JSON**:

* merchant request: `"SP1/PAYMENT-REQUEST/v1" || {fields…, channel_binding}`
* payer authorisation: `"SP1/PAYMENT-AUTH/v1" || {fields…, client_nonce, channel_binding}`
* switch receipt: `"SP1/RECEIPT/v1" || {receipt fields}`

`channel_binding` is the signer's session id with the switch. A captured
artefact is therefore useless in another session (attack case
`replay-new-session` shows *both* defences firing: `bad_signature` for the
captured artefact, `duplicate_txn` for a re-signed one). Domain tags stop
one purpose's signature being replayed as another's.

### 2.7 Abuse control

Per-session token bucket (30-message burst, 10 msg/s refill); per-message
validation with wire-safe error codes (detailed reasons are logged locally,
never sent); merchant identity binding (a terminal may only charge under
its own registered id); wallet identity binding (a wallet may only
authorise its own payments); request-to-pay TTL of 120 s.

## 3. Prototype weaknesses fixed

The submitted notebook ("MACS902_secure_payment_fixed.ipynb") was reviewed
line by line. Every weakness found is fixed and regression-tested:

| # | Prototype weakness | Fix in this repo |
| --- | --- | --- |
| 1 | GUI (customtkinter) inside a notebook | proper CLI package (`cli.py`), 3 runnable nodes over real TCP |
| 2 | `socket.socketpair()` "VM-to-VM" transport, single process | real TCP server (`switch.py`) + subprocess demo (`securepay demo`) |
| 3 | one 64,000-char cell | 20 modules, 131 tests, CI |
| 4 | handshake signs only fragments (client signs just its hello); no key confirmation; `session_id` unrelated to the exchange; payments not bound to the channel | full-transcript signatures, `finished` MAC, session id from HKDF, channel binding in every payment signature |
| 5 | `recv(65535)` framing; no size limits; partial reads unsafe | `framing.py`: 4-byte length prefix, 1 MiB cap, read-exactly loop (attack case `malformed-frame`) |
| 6 | merchant authentication = shared HMAC secret (switch can forge; no merchant non-repudiation) | merchant Ed25519 certificates + signatures over the payment fields |
| 7 | **no txn-id dedup implemented** — the notebook's own "cross-session replay" test asserts a message the code never produces (that test cell crashes) | persistent `txn_id` PK + per-payer monotonic nonce, demonstrated by `replay-new-session` and `double-spend` |
| 8 | switch signing key stored unencrypted; AES-GCM at rest vs ChaCha20-Poly1305 in flight, undocumented | every long-term key in an Argon2id+ChaCha20-Poly1305 vault; one AEAD everywhere, documented |
| 9 | hard-coded roster, shared merchant secrets, in-memory balances | registry.json + SQLite ledger, provisioning CLI, no secrets in code |
| 10 | no certificates/expiry/revocation; lockout only for the admin token; no audit log; unsigned receipts | X.509 + CRL (re-read per handshake), wallet unlock lockout, hash-chained signed audit log, switch-signed receipts |
| 11 | `__import__("hmac")` hacks, broad `except Exception` (swallows wrong-passphrase), magic numbers | typed modules, precise exception hierarchy with wire-safe codes, all constants in `config.py` |

## 4. Threat model

**In scope (T-1 … T-12), all with a passing attack case or test:**

* T-1 network attacker: eavesdrop, modify, inject, reorder, delay frames
* T-2 MITM during handshake (key substitution, rogue "switch")
* T-3 replay of frames, requests, authorisations, receipts — same or new
  session
* T-4 stolen vault *file* (offline guessing, parameter tampering)
* T-5 compromised/rogue merchant or student certificate (revocation,
  expiry, enrolment)
* T-6 protocol downgrade attempts
* T-7 malicious peer flooding (rate limits, frame caps, input validation)
* T-8 double-spend / idempotency attacks (same txn twice, concurrent
  sessions)
* T-9 ledger tampering by a local privileged user (detected by the audit
  chain, assuming the switch's private key is not also stolen)
* T-10 amount tampering in flight
* T-11 brute-force passphrase guessing online
* T-12 crash mid-payment (atomic transactions)

**Out of scope / assumptions:**

* The switch host is trusted while running: it necessarily sees plaintext
  transaction data (it is the payee/payer hub) and holds its own signing
  key. A malicious *operator* is only detectable afterwards via receipts
  and the audit log, not preventable.
* No protection against a stolen *unlocked* wallet (the private key is in
  memory while the CLI runs); lockout covers offline files and the unlock
  path only.
* Client machines are assumed not compromised at OS level (keyloggers,
  memory scraping).
* Denial-of-service at the network/OS level (SYN floods etc.) is out of
  scope; application-level flooding is rate-limited.
* The registry (enrolment) is loaded at switch start; adding entities
  requires a restart (revocation does not — the CRL is re-read per
  handshake).

## 5. Data model

* Money: integer minor units (fils). `encoding.parse_amount_minor`
  enforces ≤ 2 decimals; floats are uncanonicalisable, so they can never
  enter a signed payload or the ledger.
* Registry entry: `{id, role, name, cert_pem, public_key, serial,
  card_token?, pan_masked?, revoked}` — public data only.
* Transaction row: `{txn_id PK, payer, merchant, amount, currency,
  status PENDING|SETTLED|REJECTED|EXPIRED, created_ts, settled_ts,
  session_id, client_nonce, merchant_sig, payer_sig, receipt}`.
* Receipt: switch-signed `{txn, payer, merchant, amount, currency, ts,
  session_id, status, ledger_seq, pan_masked, card_token, switch_sig}`.

## 6. Key lifecycle

* Provisioning generates every key locally (`pki.generate_signing_key`,
  libsodium CSPRNG); nothing secret ever crosses the network.
* Leaf certificates: 365 days, 5-minute backdate for clock skew; CA: 10
  years. `issue-cert` / `revoke-cert` manage the fleet; the CRL is signed
  and re-read per handshake.
* Session keys: fresh per handshake, rotated at most every 1000 messages /
  300 s; zeroised best-effort on close (Python cannot guarantee erasure —
  stated honestly, see §8).
* Wallet nonce: persisted *before* the authorisation is sent, so even a
  crash cannot reuse a nonce.

## 7. Testing and assurance

* 178 pytest tests: unit (encoding, framing, keystore, PKI, ledger, audit,
  protocol), session-layer (handshake and channel over real TCP sockets),
  end-to-end payments (switch thread + real client sockets, including
  insufficient funds, expiry, rate limiting, role separation), and the
  full 15-case attack suite (`tests/test_attacks.py` runs the 15 cases
  together and each one individually), plus the dashboard's validation,
  HTTP hardening and an end-to-end payment flow (`tests/test_gui.py`).
* The attack simulator (`attacks/simulator.py`) provisions a fresh throwaway
  network per case and drives attacks through a **real TCP MITM proxy**
  (`attacks/mitm_proxy.py`) with frame-level mutation hooks; a case passes
  only when the attack is blocked *for the intended reason*.
* CI (`.github/workflows/ci.yml`): Python 3.10 + 3.12 × ruff (lint +
  format) × mypy × bandit × pip-audit × pytest × attack suite.
* Static typing: full annotations on the package; the mypy profile enforces
  `disallow_untyped_defs`/`disallow_incomplete_defs`/`no_implicit_optional`.
  PyNaCl ships no stubs, so `call-overload`/`arg-type` noise from its
  untyped bindings is disabled in `pyproject.toml` (documented there);
  runtime checks cover those boundaries.

## 8. Honest limitations

1. Python `bytes` are immutable and the interpreter is garbage-collected:
   key zeroisation (`keystore.zeroise`) is best-effort, not guaranteed.
2. The demo writes passphrase files (mode 0600) so child processes can be
   launched without a TTY — a convenience that a real deployment would
   replace with interactive prompts or a secret manager.
3. Single-process switch: the ledger lock serialises writes; a
   multi-process deployment would need SQLite WAL or PostgreSQL.
4. Registry changes (new entities) require a switch restart. The dashboard's
   enrolment flow handles this explicitly: if the switch is running it is
   stopped before `issue-cert` and restarted afterwards.
5. Client handshake completion is optimistic (TLS 1.3 style): a
   server-side rejection of the client's flight surfaces as a closed
   connection, not a typed error — the attack cases assert on the
   observable outcome (no session, no data flows).
6. No forward secrecy for *stored* data: vaults are encrypted with a key
   derived from the passphrase; compromise of the passphrase reveals the
   key.
7. Type checking is "strict-adjacent", not `strict = true`: the `arg-type`
   and `call-overload` codes are disabled because PyNaCl ships no stubs
   (see §7); those boundaries are covered by runtime checks and tests.
8. The web dashboard (`gui.py`) is a convenience layer for a single local
   user: loopback-only, token-protected, serialised actions (attack runs use
   their own throwaway labs and a non-blocking one-at-a-time guard). It is
   served as seven real pages plus fixed in-memory assets, with an
   incremental log endpoint (`/api/log?after=`); no filesystem path is ever
   derived from a URL. It is not designed to be exposed to a network.
9. Educational software: no external security audit, no formal proofs,
   no constant-time guarantees beyond those of libsodium/OpenSSL.

## 9. Module guide

See README "Repository layout" for the map; each module's docstring states
which security properties it provides and each public function is typed
and tested. `config.py` is the single source of truth for every protocol
constant; `config.temporary()` is the only sanctioned way to weaken one
(whitelisted, restored even on exception) and is used exclusively by the
tests and the throwaway attack labs.
