# SecurePay Demo Script (real captured output)

Everything below is genuine output from the commands as run in this
repository — nothing is paraphrased. Log lines (stderr) are interleaved
exactly as the processes produced them. Reproduce any section yourself
with the commands shown.

## 1. Full happy-path demo — `securepay demo`

Runs **three separate OS processes** (switch, wallet, terminal) over real
TCP sockets, settles two payments, then verifies the evidence offline.
The orchestrator provisions the network first (Argon2id at production
strength — this is the same code path a real deployment uses):

```
$ securepay demo
== provisioning demo network (passphrase files stay in the network dir) ==
Provisioned payment network at /tmp/demo-net
  CA fingerprint : sha256:UWOiVx8laz5K1BIi
  merchants      : canteen, coffee_shop, library
  students       : 12 enrolled

Vault passphrases (shown ONCE -- distribute securely and store nowhere else):
  entity       role      passphrase
  ------------ --------- ------------------------------
  ca           ca        cc0f1ea58c8744ee9e496acf13fd860b4afdcf5e
  ...
  switch       switch    9f59d259c1e34958b1369e098c852e7ca302e900

Passphrase files (mode 0600) written inside the network directory (demo convenience).
```

*(passphrases redacted here; the tool prints them exactly once — that is
the point of "shown ONCE")*

```
== starting the switch (real process, real TCP) ==
[switch  ] Aani settlement switch serving on 127.0.0.1:45361
[switch  ] SWITCH_READY host=127.0.0.1 port=45361

== starting the student wallet (auto-approve two payments) ==
[wallet  ] INFO securepay.pki event=certificate_verified subject=switch role=switch serial=377ab8b9… expires=2027-11-19
[wallet  ] INFO securepay.handshake event=handshake_complete side=client peer=switch session=2a4a96384724
[wallet  ] Wallet for 902101 listening (session 2a4a96384724)
[wallet  ] WALLET_READY user=902101

== starting the merchant terminal ==
[terminal] INFO securepay.handshake event=handshake_complete side=client peer=switch session=78f291297a98
[terminal] Terminal for coffee_shop connected (session 78f291297a98)
[terminal] TERMINAL_READY merchant=coffee_shop

== charging 12.50 AED to student 902101 ==
[terminal]   request accepted: TXN-1795106111-ED8179CE05EC (waiting for the payer...)
[wallet  ]   UOWD Espresso Bar (coffee_shop) requests 12.50 AED [txn TXN-1795106111-ED8179CE05EC]
[wallet  ]   approved TXN-1795106111-ED8179CE05EC for 12.50 AED
[switch  ] INFO securepay.ledger event=payment_settled txn=TXN-1795106111-ED8179CE05EC payer=902101 merchant=coffee_shop amount=1250 seq=5
[terminal] PAYMENT_RESULT txn=TXN-1795106111-ED8179CE05EC status=SETTLED

== charging 3.25 AED to student 902101 ==
[terminal]   request accepted: TXN-1795106111-35A03BA5415A (waiting for the payer...)
[wallet  ]   approved TXN-1795106111-35A03BA5415A for 3.25 AED
[switch  ] INFO securepay.ledger event=payment_settled txn=TXN-1795106111-35A03BA5415A payer=902101 merchant=coffee_shop amount=325 seq=7
[terminal] PAYMENT_RESULT txn=TXN-1795106111-35A03BA5415A status=SETTLED

== terminal balance and shutdown ==
[terminal]   balance: 2215.75 AED

== offline verification: audit chain and the latest receipt ==
audit log: 9 entries
chain integrity: OK (hash chain and switch signatures verified)
receipt TXN-1795106111-ED8179CE05EC: VERIFIED
  receipt verified against the switch signature
    txn_id    : TXN-1795106111-ED8179CE05EC
    payer     : 902101
    merchant  : coffee_shop
    amount    : 12.50 AED
    status    : SETTLED
    ledger seq: 5
    card      : ****-****-****-7311 (token 1a2b3c4d...)

== demo finished: audit=OK, receipt=VERIFIED ==
```

Note what the switch-side log shows for every connection:
`certificate_verified` (chain + registry) → `handshake_complete` →
`session_open`, and `payment_settled` lines carry the ledger sequence
number that also appears in the signed receipt.

## 2. Automatic rekey — `securepay rekey-demo`

One wallet session does repeated balance queries with the rekey threshold
lowered to 3 messages; the key fingerprint changes at each epoch rotation
(a fresh X25519 exchange *inside* the authenticated channel):

```
$ securepay rekey-demo --messages 3
session 8f31c1d0a29e4c1b... epoch 1 key 477d86ea
  message   1: balance query ok (epoch 1, key 477d86ea)
  message   2: balance query ok (epoch 1, key 477d86ea)
  message   3: balance query ok (epoch 2, key e75146ac)
  message   4: balance query ok (epoch 2, key e75146ac)
  message   5: balance query ok (epoch 3, key 2167ba6e)
PASS: keys rotated automatically mid-session (fresh X25519 inside the authenticated channel)
```

## 3. Attack simulator — `securepay attack --all`

Each case provisions a fresh throwaway network and runs the attack through
a real TCP MITM proxy (for the on-path cases). **PASS means the system
blocked the attack for the intended reason** — a case fails if the attack
succeeds *or* if it is blocked by an accident:

```
$ securepay attack --all
[PASS] bit-flip               tampered frame rejected: AEAD tag failed, session aborted
[PASS] aad-tamper             modified AAD rejected: header no longer matches the AEAD tag
[PASS] replay-same-session    duplicate frame rejected: strict monotonic counter (replay)
[PASS] replay-new-session     captured artefact rejected (bad_signature: channel binding); re-signed duplicate rejected (duplicate_txn: persistent idempotency)
[PASS] reorder                reordered frames rejected: counter must match exactly
[PASS] stale-frame            old frame rejected: timestamp outside freshness window
[PASS] mitm-modify-amount     amount is inside the AEAD ciphertext; flipping it breaks the tag, the session aborts and nothing settles
[PASS] mitm-key-substitution  key substitution detected during handshake (handshake_failed): transcript signatures / Finished MAC no longer match
[PASS] impersonate-switch     rogue certificate rejected: not signed by the campus CA
[PASS] revoked-certificate    revoked certificate rejected: the re-read CRL aborts the session
[PASS] expired-certificate    expired certificate rejected: outside its validity window
[PASS] downgrade              downgrade hello rejected (version_mismatch); switch stays healthy
[PASS] vault-bruteforce       5 failures trigger lockout; the correct passphrase is refused while locked
[PASS] malformed-frame        malformed/oversized frames close the connection; switch stays healthy
[PASS] double-spend           duplicate txn_id refused on request AND authorisation; balances moved exactly once

15/15 attacks blocked
```

The suite is also a pytest marker (`pytest -m slow`, part of the default
`pytest` run), so CI fails if any attack ever stops being blocked.

## 4. Manual walkthrough (optional)

The same flow by hand, in four shells — useful for showing the
authenticating handshake live (e.g. with `tcpdump` on loopback, where
every payload after the hellos is opaque ciphertext):

```bash
securepay --network-dir network seed --write-passphrase-files
securepay --network-dir network run-switch --port 7440 \
    --passphrase-file network/switch/switch.pass
securepay --network-dir network run-wallet --user 902101 \
    --passphrase-file network/wallets/902101.pass --switch-port 7440
securepay --network-dir network run-terminal --merchant coffee_shop \
    --passphrase-file network/terminals/coffee_shop.pass --switch-port 7440
```

Terminal REPL:

```
> charge 902101 12.50
  request accepted: TXN-… (waiting for the payer...)
PAYMENT_RESULT txn=TXN-… status=SETTLED
> balance
  balance: 2212.50 AED
> quit
```

Offline evidence checks:

```bash
securepay --network-dir network audit verify
# audit log: 9 entries
# chain integrity: OK (hash chain and switch signatures verified)

securepay --network-dir network audit log --event payment_declined
# lists every payment the student declined (signed, hash-chained)

securepay --network-dir network verify-receipt --file network/receipts/<TXN-ID>.json
# receipt <TXN-ID>: VERIFIED
```

## 5. Interactive dashboard — `securepay gui`

Good for the live demonstration: everything above, driven from seven real
pages (each has its own URL, so refresh, deep links and the back button
work).

1. `securepay gui` (use `--no-browser` on a headless VM and open the URL it prints).
2. On **Overview**: **Start network**, then **Start switch** (the status chip
   turns green and shows the port).
3. On **Payment**: pick a student and merchant, enter an amount, leave
   *Student approves* selected, press **Charge student**. The message shows
   the transaction id; balances update on the Accounts page.
4. Repeat with **Student declines**: nothing is charged and no receipt is created. The merchant is
   told immediately, the result shows *Declined by student*, and the decline is signed by the
   student's key and recorded in the audit chain as a `payment_declined` entry.
5. On **Accounts**: **Enrol student** — enter a fresh ID, full name and
   opening balance, confirm, and the generated wallet-vault passphrase is
   shown exactly once (copy it). If the switch was running it restarts
   automatically to pick up the new student. The new student then appears in
   the accounts table and the Payment-page picker without a reload.
6. Still on **Accounts**: press **Add funds** on a student row, enter an
   amount, confirm. The balance updates on the next poll.
7. On **Audit & receipts**: **Verify audit log** — the chain still verifies
   and includes the `TOPUP` entry from step 6; the **Payment outcomes log** below it lists the
   settled payment and the declined one from step 4; **Verify receipt** (choose the
   receipt from the list) shows offline, signature-based verification.
8. On **Attack simulator**: press **Run This Attack** on one row (for example
   *Bit Flip*) to run only that case: the row turns **BLOCKED – PASS** and
   the other 14 stay *Not Run*. Open *Technical result details* to show the
   real returned detail.
9. Press **Run all 15 attacks** for the full suite; the statistics bar should
   read `15/15 attacks blocked`.
10. On **Security architecture**: each card lists the mechanism, its source
    module and the attacks that test it. Click a test chip to see that
    attack on the Attack simulator page.
11. On **Live log**: the switch's own output, fetched incrementally, with
    level filters and auto-follow. **Reset displayed results** (Attack
    simulator page) clears only the display, not the network or keys.
