from __future__ import annotations

import argparse
import contextlib
import getpass
import os
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nacl.signing import SigningKey, VerifyKey

from securepay import __version__, config
from securepay.errors import SecurePayError


def _network_paths(args: argparse.Namespace) -> config.NetworkPaths:
    return config.NetworkPaths(root=Path(args.network_dir).resolve())


def _get_passphrase(value: str | None, file: str | None, purpose: str) -> str:
    if value:
        return value
    if file:
        return Path(file).read_text(encoding="utf-8").strip()
    if sys.stdin.isatty():
        return getpass.getpass(f"Passphrase for {purpose}: ")
    raise SecurePayError(
        f"passphrase required for {purpose} (use --passphrase or --passphrase-file)"
    )


def _fmt_amount(minor: int) -> str:
    from securepay.encoding import format_amount

    return f"{format_amount(minor)} {config.CURRENCY}"


def _print_receipt(receipt: dict[str, object]) -> None:
    print(f"    txn_id    : {receipt['txn_id']}")
    print(f"    payer     : {receipt['payer_id']}")
    print(f"    merchant  : {receipt['merchant_id']}")
    print(f"    amount    : {_fmt_amount(int(receipt['amount_minor']))}")
    print(f"    status    : {receipt['status']}")
    print(f"    ledger seq: {receipt['ledger_seq']}")
    pan = str(receipt["pan_masked"])
    token = str(receipt["card_token"])[:8]
    print(f"    card      : {pan} (token {token}...)")


def cmd_init_ca(args: argparse.Namespace) -> int:
    from securepay.bootstrap import provision_network

    paths = _network_paths(args)
    if paths.ca_cert.exists() and not args.force:
        print(f"CA already exists at {paths.ca_cert} (use --force to replace)")
        return 1
    passphrase = args.passphrase or _get_passphrase(None, None, "the new CA")
    network = provision_network(paths.root, students=[], merchants=[], ca_passphrase=passphrase)
    print(f"CA created: {paths.ca_cert}")
    print(f"CA fingerprint: {network.ca_fingerprint}")
    return 0


def cmd_issue_cert(args: argparse.Namespace) -> int:
    from securepay.bootstrap import issue_entity_certificate

    paths = _network_paths(args)
    ca_passphrase = _get_passphrase(args.ca_passphrase, args.ca_passphrase_file, "the CA")
    switch_passphrase = _get_passphrase(
        args.switch_passphrase,
        args.switch_passphrase_file,
        "the switch vault (admin authorisation)",
    )
    passphrase = issue_entity_certificate(
        paths,
        ca_passphrase,
        role=args.role,
        entity_id=args.id,
        name=args.name or args.id,
        opening_balance=args.balance,
        switch_passphrase=switch_passphrase,
    )
    print(f"Issued {args.role} certificate for {args.id}")
    print("Vault passphrase (shown ONCE, store it securely):")
    print(f"  {passphrase}")
    if args.write_passphrase_file:
        from securepay.bootstrap import write_passphrase_file

        pass_dir = paths.terminals_dir if args.role == config.ROLE_MERCHANT else paths.wallets_dir
        pass_path = pass_dir / f"{args.id}.pass"
        write_passphrase_file(pass_path, passphrase)
        print(f"Passphrase file (mode 0600) written to {pass_path} (demo convenience).")
    print(f"VAULT_PASSPHRASE {passphrase}")
    return 0


def cmd_revoke_cert(args: argparse.Namespace) -> int:
    from securepay.bootstrap import revoke_entity_certificate

    paths = _network_paths(args)
    ca_passphrase = _get_passphrase(args.ca_passphrase, args.ca_passphrase_file, "the CA")
    serial = revoke_entity_certificate(paths, ca_passphrase, args.id)
    print(f"Revoked {args.id} (serial {serial:#x}); CRL rewritten at {paths.crl}")
    print("Existing connections stay open; new handshakes are refused.")
    return 0


def cmd_seed(args: argparse.Namespace) -> int:
    from securepay.bootstrap import DEFAULT_MERCHANTS, DEFAULT_STUDENTS, provision_network

    paths = _network_paths(args)
    if paths.registry.exists() and not args.force:
        print(f"Network already provisioned at {paths.root} (use --force to replace)")
        return 1
    if args.force and paths.root.exists():
        shutil.rmtree(paths.root)
    merchants = [
        {"id": m["id"], "name": m["name"], "balance": m["balance"]}
        for m in DEFAULT_MERCHANTS
        if not args.merchants or m["id"] in args.merchants
    ]
    students = [
        {"id": s["id"], "name": s["name"], "balance": s["balance"]}
        for s in DEFAULT_STUDENTS
        if not args.students or s["id"] in args.students
    ]
    network = provision_network(paths.root, students=students, merchants=merchants)
    print(f"Provisioned payment network at {paths.root}")
    print(f"  CA fingerprint : {network.ca_fingerprint}")
    print(f"  merchants      : {', '.join(m['id'] for m in merchants)}")
    print(f"  students       : {len(students)} enrolled")
    print()
    print("Vault passphrases (shown ONCE -- distribute securely and store nowhere else):")
    print(f"  {'entity':<12} {'role':<9} passphrase")
    print(f"  {'-' * 12} {'-' * 9} {'-' * 30}")
    print(f"  {'ca':<12} {'ca':<9} {network.ca_passphrase}")
    for entity_id in sorted(network.passphrases):
        role = "switch" if entity_id == config.SWITCH_ID else "node"
        print(f"  {entity_id:<12} {role:<9} {network.passphrases[entity_id]}")
    if args.write_passphrase_files:
        from securepay.bootstrap import write_passphrase_file

        write_passphrase_file(paths.root / "ca.pass", network.ca_passphrase)
        write_passphrase_file(
            paths.switch_dir / "switch.pass", network.passphrases[config.SWITCH_ID]
        )
        for merchant in merchants:
            write_passphrase_file(
                paths.terminals_dir / f"{merchant['id']}.pass",
                network.passphrases[merchant["id"]],
            )
        for student in students:
            write_passphrase_file(
                paths.wallets_dir / f"{student['id']}.pass",
                network.passphrases[student["id"]],
            )
        print()
        print(
            "Passphrase files (mode 0600) written inside the network directory (demo convenience)."
        )
    return 0


def cmd_registry(args: argparse.Namespace) -> int:
    import json

    from securepay.ledger import Ledger
    from securepay.pki import cert_fingerprint, read_cert

    paths = _network_paths(args)
    if not paths.registry.exists():
        print(f"No network found at {paths.root} -- run `securepay seed` first")
        return 1
    registry = json.loads(paths.registry.read_text(encoding="utf-8"))
    ca = read_cert(paths.ca_cert)
    print(f"CA: {cert_fingerprint(ca)}")
    print(f"{'id':<12} {'role':<9} {'name':<28} {'revoked':<8} serial")
    for entity in registry["entities"]:
        print(
            f"{entity['id']:<12} {entity['role']:<9} {entity['name'][:28]:<28} "
            f"{'YES' if entity.get('revoked') else 'no':<8} {entity['serial']:#x}"
        )
    if paths.ledger.exists():
        ledger = Ledger(paths.ledger, _dummy_signer())
        try:
            print()
            print(f"{'account':<12} {'role':<9} {'balance':>14}")
            for account in ledger.accounts():
                print(
                    f"{account['account_id']:<12} {account['role']:<9} "
                    f"{_fmt_amount(account['balance_minor']):>14}"
                )
        finally:
            ledger.close()
    return 0


def _dummy_signer() -> SigningKey:
    from nacl.signing import SigningKey

    return SigningKey.generate()


def cmd_run_switch(args: argparse.Namespace) -> int:
    from securepay.switch import SwitchCore, SwitchServer

    paths = _network_paths(args)
    if not paths.registry.exists():
        print(f"No network found at {paths.root} -- run `securepay seed` first")
        return 1
    passphrase = _get_passphrase(args.passphrase, args.passphrase_file, "the switch vault")
    core = SwitchCore(paths, passphrase)
    server = SwitchServer(core, args.host, args.port)
    print(f"Aani settlement switch serving on {server.host}:{server.port}")
    print(f"SWITCH_READY host={server.host} port={server.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.stop()
        core.ledger.close()
    return 0


def cmd_run_terminal(args: argparse.Namespace) -> int:
    from securepay.terminal import TerminalClient

    paths = _network_paths(args)
    passphrase = _get_passphrase(args.passphrase, args.passphrase_file, f"terminal {args.merchant}")
    terminal = TerminalClient(
        paths, args.merchant, passphrase, host=args.switch_host, port=args.switch_port
    )
    print(f"Terminal for {args.merchant} connected (session {terminal.session_id[:12]})")
    print("TERMINAL_READY " + f"merchant={args.merchant}", flush=True)
    print("Commands: charge <payer> <amount> [currency] | balance | quit")
    try:
        for line in sys.stdin:
            parts = line.split()
            if not parts:
                continue
            command, rest = parts[0].lower(), parts[1:]
            if command == "quit":
                break
            try:
                if command == "charge" and len(rest) >= 2:
                    from securepay.encoding import parse_amount_minor

                    amount = parse_amount_minor(rest[1])
                    currency = rest[2].upper() if len(rest) > 2 else config.CURRENCY
                    txn = terminal.request_payment(rest[0], amount, currency=currency)
                    print(f"  request accepted: {txn} (waiting for the payer...)")
                    result = terminal.await_result(txn, wait_seconds=args.wait)
                    _print_terminal_result(result, paths)
                elif command == "balance":
                    report = terminal.balance()
                    print(f"  balance: {_fmt_amount(report['balance_minor'])}")
                else:
                    print("  usage: charge <payer> <amount> [currency] | balance | quit")
            except SecurePayError as exc:
                print(f"  declined: {exc.code} ({exc.message})")
    finally:
        terminal.close()
    return 0


def _print_terminal_result(result: dict[str, object], paths: config.NetworkPaths) -> None:
    from securepay.client import save_receipt

    status = result.get("status")
    print(f"PAYMENT_RESULT txn={result.get('txn_id')} status={status}", flush=True)
    if status == "SETTLED" and isinstance(result.get("receipt"), dict):
        receipt = dict(result["receipt"])
        path = save_receipt(paths, receipt)
        print(f"  settled -- receipt saved to {path}")
    elif status == "REJECTED":
        print(f"  reason: {result.get('reason_code')}")


def cmd_charge(args: argparse.Namespace) -> int:
    from securepay.encoding import parse_amount_minor
    from securepay.terminal import TerminalClient

    paths = _network_paths(args)
    passphrase = _get_passphrase(args.passphrase, args.passphrase_file, f"terminal {args.merchant}")
    amount = parse_amount_minor(args.amount)
    terminal = TerminalClient(
        paths, args.merchant, passphrase, host=args.switch_host, port=args.switch_port
    )
    try:
        txn = terminal.request_payment(args.payer, amount, currency=args.currency)
        print(f"request accepted: {txn} (waiting for the payer...)")
        result = terminal.await_result(txn, wait_seconds=args.wait)
        _print_terminal_result(result, paths)
        return 0 if result.get("status") == "SETTLED" else 1
    finally:
        terminal.close()


def _pick_request(
    requests: list[dict[str, object]],
    txn_id: str | None,
    expect_merchant: str | None,
    expect_amount_minor: int | None,
) -> dict[str, object] | None:
    for request in requests:
        if txn_id and request.get("txn_id") != txn_id:
            continue
        if expect_merchant and request.get("merchant_id") != expect_merchant:
            continue
        if (
            expect_amount_minor is not None
            and int(request.get("amount_minor", -1)) != expect_amount_minor
        ):
            continue
        return request
    return None


def cmd_pay(args: argparse.Namespace) -> int:
    from securepay.client import WalletClient
    from securepay.encoding import parse_amount_minor

    paths = _network_paths(args)
    passphrase = _get_passphrase(args.passphrase, args.passphrase_file, f"wallet {args.user}")
    expect_amount = parse_amount_minor(args.expect_amount) if args.expect_amount else None
    wallet = WalletClient(
        paths, args.user, passphrase, host=args.switch_host, port=args.switch_port
    )
    try:
        requests = wallet.pending_requests()
        if not requests:
            print(f"no pending payment requests for {args.user}")
            return 1
        request = _pick_request(requests, args.txn_id, args.expect_merchant, expect_amount)
        if request is None:
            print("no request matches the given filters (--txn-id / --expect-*)")
            return 1
        wallet_pending_display(request)
        if not args.yes:
            answer = input("approve? [y/N] ").strip().lower()
            if answer != "y":
                wallet.decline(request)
                print(f"payment declined -- nothing was charged ({request['txn_id']})")
                print("the decline was signed by your key and recorded in the audit log")
                return 1
        receipt = wallet.authorise(
            request, expect_amount_minor=expect_amount, expect_merchant=args.expect_merchant
        )
        print("payment settled -- switch-signed receipt:")
        _print_receipt(receipt)
        print(f"saved to {paths.receipt(str(receipt['txn_id']))}")
        return 0
    finally:
        wallet.close()


def cmd_run_wallet(args: argparse.Namespace) -> int:
    from securepay.client import WalletClient
    from securepay.encoding import parse_amount_minor

    paths = _network_paths(args)
    passphrase = _get_passphrase(args.passphrase, args.passphrase_file, f"wallet {args.user}")
    expect_amount = parse_amount_minor(args.expect_amount) if args.expect_amount else None
    wallet = WalletClient(
        paths, args.user, passphrase, host=args.switch_host, port=args.switch_port
    )
    print(f"Wallet for {args.user} listening (session {wallet.session_id[:12]})")
    print(f"WALLET_READY user={args.user}", flush=True)
    try:
        for _approval in range(args.count):
            message = wallet.channel.recv(timeout=300.0)
            if message.get("type") != "authorisation_request":
                continue
            wallet_pending_display(message)
            if not args.auto_approve:
                answer = input("approve? [y/N] ").strip().lower()
                if answer != "y":
                    try:
                        wallet.decline(message)
                    except SecurePayError as exc:
                        print(f"  decline could not be recorded: {exc.code} ({exc.message})")
                        continue
                    print(f"  declined {message['txn_id']} (nothing was charged)")
                    print(f"WALLET_DECLINED txn={message['txn_id']}", flush=True)
                    continue
            receipt = wallet.authorise(
                message,
                expect_amount_minor=expect_amount,
                expect_merchant=args.expect_merchant,
            )
            print(f"  approved {receipt['txn_id']} for {_fmt_amount(int(receipt['amount_minor']))}")
            print(f"WALLET_APPROVED txn={receipt['txn_id']}", flush=True)
    except KeyboardInterrupt:
        print()
    finally:
        wallet.close()
    return 0


def wallet_pending_display(request: dict[str, object]) -> None:
    from securepay.encoding import format_amount

    print(
        f"  {request['merchant_name']} ({request['merchant_id']}) requests "
        f"{format_amount(int(request['amount_minor']))} {request['currency']}"
        f" [txn {request['txn_id']}]"
    )


def cmd_topup(args: argparse.Namespace) -> int:
    import json

    from securepay.encoding import format_amount, parse_amount_minor
    from securepay.keystore import load_vault
    from securepay.ledger import Ledger

    paths = _network_paths(args)
    if not paths.registry.exists():
        print(f"No network found at {paths.root} -- run `securepay seed` first")
        return 1
    registry = json.loads(paths.registry.read_text(encoding="utf-8"))
    entity = next((e for e in registry["entities"] if e["id"] == args.id), None)
    if entity is None:
        print(f"error: unknown_entity: {args.id} is not in the registry")
        return 1
    if entity.get("revoked"):
        print(f"error: entity_revoked: {args.id} has been revoked")
        return 1
    if entity["role"] == config.ROLE_SWITCH:
        print(f"error: invalid_role: cannot top up the {args.id} account")
        return 1

    amount_minor = parse_amount_minor(args.amount)
    if amount_minor <= 0:
        print("error: invalid_amount: the top-up amount must be greater than 0")
        return 1

    switch_passphrase = _get_passphrase(
        args.passphrase, args.switch_passphrase_file, "the switch vault (admin authorisation)"
    )
    switch_vault = load_vault(
        paths.switch_vault,
        switch_passphrase,
        expected_aad={"kind": "switch", "id": config.SWITCH_ID},
    )
    from nacl.signing import SigningKey

    ledger = Ledger(paths.ledger, SigningKey(bytes.fromhex(switch_vault["seed"])))
    try:
        old_minor, new_minor = ledger.credit(args.id, amount_minor)
    finally:
        ledger.close()
    print(f"Topped up {args.id} by {_fmt_amount(amount_minor)}")
    print(
        f"TOPUP_OK id={args.id} amount_minor={amount_minor}"
        f" old_minor={old_minor} new_minor={new_minor}"
    )
    print(f"  old balance : {format_amount(old_minor)} {config.CURRENCY}")
    print(f"  new balance : {format_amount(new_minor)} {config.CURRENCY}")
    return 0


def cmd_balance(args: argparse.Namespace) -> int:
    from securepay.ledger import Ledger

    paths = _network_paths(args)
    if args.admin:
        ledger = Ledger(paths.ledger, _dummy_signer())
        try:
            for account in ledger.accounts():
                amount = _fmt_amount(account["balance_minor"])
                print(f"{account['account_id']:<12} {account['role']:<9} {amount:>14}")
        finally:
            ledger.close()
        return 0
    if args.user:
        from securepay.client import WalletClient

        passphrase = _get_passphrase(args.passphrase, args.passphrase_file, f"wallet {args.user}")
        wallet = WalletClient(
            paths, args.user, passphrase, host=args.switch_host, port=args.switch_port
        )
        try:
            report = wallet.balance()
            print(f"{args.user} balance: {_fmt_amount(report['balance_minor'])}")
        finally:
            wallet.close()
        return 0
    if args.merchant:
        from securepay.terminal import TerminalClient

        passphrase = _get_passphrase(
            args.passphrase, args.passphrase_file, f"terminal {args.merchant}"
        )
        terminal = TerminalClient(
            paths, args.merchant, passphrase, host=args.switch_host, port=args.switch_port
        )
        try:
            report = terminal.balance()
            print(f"{args.merchant} balance: {_fmt_amount(report['balance_minor'])}")
        finally:
            terminal.close()
        return 0
    print("specify --user, --merchant, or --admin")
    return 1


def _switch_verify_key(paths: config.NetworkPaths) -> VerifyKey:
    from nacl.signing import VerifyKey

    from securepay.pki import read_cert, verify_certificate

    cert = read_cert(paths.switch_cert)
    from securepay.pki import load_crl

    identity = verify_certificate(cert, read_cert(paths.ca_cert), load_crl(paths.crl))
    if identity.subject_id != config.SWITCH_ID:
        raise SecurePayError("switch certificate has the wrong identity")
    return VerifyKey(identity.public_key)


def cmd_audit(args: argparse.Namespace) -> int:
    from securepay.audit import AuditLog

    paths = _network_paths(args)
    if not paths.ledger.exists():
        print(f"No ledger found at {paths.ledger}")
        return 1
    verify_key = _switch_verify_key(paths)
    result = AuditLog.verify_file(paths.ledger, verify_key)
    print(f"audit log: {result.entries} entries")
    if result.ok:
        print("chain integrity: OK (hash chain and switch signatures verified)")
        return 0
    print("chain integrity: FAILED")
    for failure in result.failures:
        print(f"  - {failure}")
    return 1


_LOG_OUTCOMES = {
    "payment_settled": "SETTLED",
    "payment_declined": "DECLINED_BY_STUDENT",
    "payment_rejected": "REJECTED",
    "entity_enrolled": "ENROLLED",
}


def cmd_audit_log(args: argparse.Namespace) -> int:
    import time

    from securepay.audit import EVENTS, AuditLog
    from securepay.encoding import format_amount

    paths = _network_paths(args)
    if not paths.ledger.exists():
        print(f"No ledger found at {paths.ledger}")
        return 1
    wanted = frozenset(args.event) if args.event else frozenset(_LOG_OUTCOMES)
    unknown = wanted - EVENTS
    if unknown:
        print(f"unknown audit event(s): {', '.join(sorted(unknown))}")
        return 1
    verify_key = _switch_verify_key(paths)
    verdict = AuditLog.verify_file(paths.ledger, verify_key)
    entries = AuditLog.read_file(paths.ledger, wanted)
    if args.limit:
        entries = entries[-args.limit :]
    integrity = "OK" if verdict.ok else "FAILED"
    print(f"audit log: {verdict.entries} entries, chain integrity: {integrity}")
    print(f"showing {len(entries)} matching entr{'y' if len(entries) == 1 else 'ies'}")
    for entry in entries:
        payload = entry.payload
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(entry.ts))
        amount = payload.get("amount_minor", payload.get("opening_balance_minor"))
        parts = [
            f"seq={entry.seq}",
            f"time={when.replace(' ', 'T')}Z",
            f"event={entry.event}",
            f"outcome={_LOG_OUTCOMES.get(entry.event, '-')}",
            f"txn={payload.get('txn_id', '-')}",
            f"payer={payload.get('payer_id', payload.get('entity_id', '-'))}",
            f"merchant={payload.get('merchant_id', '-')}",
            f"amount={format_amount(amount) if isinstance(amount, int) else '-'}",
            f"reason={payload.get('reason_code', '-')}",
        ]
        print("  " + " ".join(parts))
    return 0 if verdict.ok else 1


def cmd_verify_receipt(args: argparse.Namespace) -> int:
    from securepay.client import load_receipt_file, verify_receipt_artefact

    paths = _network_paths(args)
    receipt = load_receipt_file(Path(args.file))
    verify_key = _switch_verify_key(paths)
    ledger_path = paths.ledger if paths.ledger.exists() else None
    ok, detail = verify_receipt_artefact(receipt, verify_key, ledger_path=ledger_path)
    print(f"receipt {receipt.get('txn_id')}: {'VERIFIED' if ok else 'INVALID'}")
    print(f"  {detail}")
    if ok:
        _print_receipt(receipt)
    return 0 if ok else 1


def cmd_attack(args: argparse.Namespace) -> int:
    from securepay.attacks.simulator import CASES, run_all, run_case

    if args.list:
        for name, (description, _case) in CASES.items():
            print(f"{name:<22} {description}")
        return 0
    if args.all or not args.name:
        results = run_all(fast=not args.production_kdf)
    else:
        results = [run_case(args.name, fast=not args.production_kdf)]
    print()
    width = max(len(r.name) for r in results)
    for result in results:
        marker = "PASS" if result.passed else "FAIL"
        print(f"[{marker}] {result.name:<{width}}  {result.detail}")
    passed = sum(1 for r in results if r.passed)
    print(f"\n{passed}/{len(results)} attacks blocked")
    return 0 if passed == len(results) else 1


def cmd_rekey_demo(args: argparse.Namespace) -> int:
    import tempfile

    from securepay.attacks.simulator import Lab
    from securepay.client import WalletClient

    with (
        tempfile.TemporaryDirectory(prefix="securepay-rekey-"),
        config.temporary(REKEY_AFTER_MESSAGES=args.messages),
    ):
        lab = Lab(fast=not args.production_kdf)
        try:
            with lab._kdf():
                wallet = WalletClient(
                    lab.paths,
                    "902101",
                    lab.network.passphrases["902101"],
                    host=config.DEFAULT_HOST,
                    port=lab.port,
                )
            try:
                fp = wallet.channel.key_fingerprint()
                print(f"session {wallet.session_id[:16]}... epoch 1 key {fp}")
                for i in range(1, args.messages * 2 + 1):
                    wallet.balance()
                    epoch = wallet.channel.epoch
                    print(
                        f"  message {i:>3}: balance query ok"
                        f" (epoch {epoch}, key {wallet.channel.key_fingerprint()})"
                    )
                    if epoch >= 3:
                        break
                if wallet.channel.epoch < 2:
                    print("FAIL: epoch never rotated")
                    return 1
                print(
                    "PASS: keys rotated automatically mid-session"
                    " (fresh X25519 inside the authenticated channel)"
                )
                return 0
            finally:
                wallet.close()
        finally:
            lab.stop()
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    orchestrator = _DemoOrchestrator(args)
    return orchestrator.run()


class _DemoProcess:

    def __init__(self, name: str, cmd: list[str], env: dict[str, str]) -> None:
        self.name = name
        self.lines: list[str] = []
        self._queue: list[str] = []
        self._lock = threading.Lock()
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        try:
            for line in self.proc.stdout:
                with self._lock:
                    self._queue.append(line.rstrip("\n"))
        except (OSError, ValueError):
            pass

    def pending_lines(self) -> list[str]:
        with self._lock:
            lines, self._queue = self._queue, []
            return lines

    def send(self, text: str) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.write(text + "\n")
            self.proc.stdin.flush()

    def stop(self, timeout: float = 5.0) -> None:
        if self.proc.poll() is None:
            if self.proc.stdin is not None:
                with contextlib.suppress(OSError):
                    self.proc.stdin.close()
            self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    @property
    def returncode(self) -> int | None:
        return self.proc.poll()


class _DemoOrchestrator:

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.paths = _network_paths(args)
        self.procs: dict[str, _DemoProcess] = {}
        self.env = os.environ.copy()
        src_root = Path(__file__).resolve().parent.parent
        self.env["PYTHONPATH"] = str(src_root) + os.pathsep + self.env.get("PYTHONPATH", "")
        self.python = sys.executable

    def _securepay(self, *cli_args: str) -> list[str]:
        return [
            self.python,
            "-u",
            "-m",
            "securepay",
            "--network-dir",
            str(self.paths.root),
            *cli_args,
        ]

    def _drain(self) -> None:
        for name, proc in self.procs.items():
            for line in proc.pending_lines():
                print(f"[{name:<8}] {line}")

    def _wait_for(self, name: str, pattern: str, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            proc = self.procs[name]
            for line in proc.pending_lines():
                print(f"[{name:<8}] {line}")
                if pattern in line:
                    return line
            if proc.returncode is not None:
                raise SecurePayError(f"{name} exited early (code {proc.returncode})")
            time.sleep(0.1)
        raise SecurePayError(f"timed out waiting for {name} to print {pattern!r}")

    def run(self) -> int:
        args = self.args
        if args.fresh and self.paths.root.exists():
            shutil.rmtree(self.paths.root)
        if not self.paths.registry.exists():
            print("== provisioning demo network (passphrase files stay in the network dir) ==")
            seed = subprocess.run(
                self._securepay(
                    "seed",
                    "--write-passphrase-files",
                ),
                check=False,
                env=self.env,
            )
            if seed.returncode != 0:
                return 1
            print()

        print("== starting the switch (real process, real TCP) ==")
        self.procs["switch"] = _DemoProcess(
            "switch",
            self._securepay(
                "run-switch",
                "--host",
                config.DEFAULT_HOST,
                "--port",
                "0",
                "--passphrase-file",
                str(self.paths.switch_dir / "switch.pass"),
            ),
            self.env,
        )
        ready = self._wait_for("switch", "SWITCH_READY", timeout=20.0)
        host, port = _parse_ready(ready)

        print()
        print("== starting the student wallet (auto-approve two payments) ==")
        self.procs["wallet"] = _DemoProcess(
            "wallet",
            self._securepay(
                "run-wallet",
                "--user",
                "902101",
                "--auto-approve",
                "--count",
                "2",
                "--passphrase-file",
                str(self.paths.wallets_dir / "902101.pass"),
                "--switch-host",
                host,
                "--switch-port",
                str(port),
            ),
            self.env,
        )
        self._wait_for("wallet", "WALLET_READY", timeout=20.0)

        print()
        print("== starting the merchant terminal ==")
        self.procs["terminal"] = _DemoProcess(
            "terminal",
            self._securepay(
                "run-terminal",
                "--merchant",
                "coffee_shop",
                "--passphrase-file",
                str(self.paths.terminals_dir / "coffee_shop.pass"),
                "--switch-host",
                host,
                "--switch-port",
                str(port),
            ),
            self.env,
        )
        self._wait_for("terminal", "TERMINAL_READY", timeout=20.0)

        print()
        print("== charging 12.50 AED to student 902101 ==")
        self.procs["terminal"].send("charge 902101 12.50")
        self._wait_for("terminal", "PAYMENT_RESULT", timeout=30.0)

        print()
        print("== charging 3.25 AED to student 902101 ==")
        self.procs["terminal"].send("charge 902101 3.25")
        self._wait_for("terminal", "PAYMENT_RESULT", timeout=30.0)

        print()
        print("== terminal balance and shutdown ==")
        self.procs["terminal"].send("balance")
        self.procs["terminal"].send("quit")
        time.sleep(1.0)
        self._drain()

        print()
        print("== offline verification: audit chain and the latest receipt ==")
        self.procs["wallet"].stop()
        self.procs["terminal"].stop()
        self.procs["switch"].stop()
        self._drain()

        audit = subprocess.run(
            self._securepay("audit", "verify"),
            check=False,
            env=self.env,
            text=True,
            capture_output=True,
        )
        print(audit.stdout, end="")

        receipts = (
            sorted(self.paths.receipts_dir.glob("*.json"))
            if self.paths.receipts_dir.exists()
            else []
        )
        if receipts:
            verify = subprocess.run(
                self._securepay("verify-receipt", "--file", str(receipts[-1])),
                check=False,
                env=self.env,
                text=True,
                capture_output=True,
            )
            print(verify.stdout, end="")
            receipt_ok = verify.returncode == 0
        else:
            print("no receipts found -- demo payment did not settle")
            receipt_ok = False

        print()
        print(
            f"== demo finished: audit={'OK' if audit.returncode == 0 else 'FAILED'},"
            f" receipt={'VERIFIED' if receipt_ok else 'FAILED'} =="
        )
        return 0 if audit.returncode == 0 and receipt_ok else 1


def _parse_ready(line: str) -> tuple[str, int]:
    fields = dict(part.split("=", 1) for part in line.split() if "=" in part)
    return fields.get("host", config.DEFAULT_HOST), int(fields.get("port", 0))


def cmd_gui(args: argparse.Namespace) -> int:
    from securepay.gui import selftest, serve

    if args.check:
        return selftest(Path(args.network_dir))
    return serve(Path(args.network_dir), port=args.port, open_browser=not args.no_browser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securepay",
        description="SecurePay: campus card-payment network (MACS 902 project)",
    )
    parser.add_argument("--version", action="version", version=f"securepay {__version__}")
    parser.add_argument(
        "--network-dir",
        default="network",
        help="network directory (default: ./network)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(parser: argparse.ArgumentParser) -> None:
        parser.set_defaults(func=None)

    p = subparsers.add_parser("init-ca", help="create the campus CA")
    p.add_argument("--passphrase", default=None)
    p.add_argument("--force", action="store_true")
    common(p)
    p.set_defaults(func=cmd_init_ca)

    p = subparsers.add_parser("issue-cert", help="issue a certificate + vault")
    p.add_argument("--role", required=True, choices=[config.ROLE_MERCHANT, config.ROLE_STUDENT])
    p.add_argument("--id", required=True)
    p.add_argument("--name", default=None)
    p.add_argument("--balance", default="0.00", help="opening balance, e.g. 100.00")
    p.add_argument("--passphrase", default=None, help="vault passphrase (generated if omitted)")
    p.add_argument("--ca-passphrase", default=None)
    p.add_argument("--ca-passphrase-file", default=None)
    p.add_argument(
        "--switch-passphrase",
        default=None,
        help="switch vault passphrase (signs the enrolment audit entry)",
    )
    p.add_argument(
        "--switch-passphrase-file",
        default=None,
        help="file holding the switch vault passphrase",
    )
    p.add_argument(
        "--write-passphrase-file",
        default=None,
        metavar="PATH",
        help="also store the vault passphrase in a 0600 file (demo convenience)",
    )
    common(p)
    p.set_defaults(func=cmd_issue_cert)

    p = subparsers.add_parser("revoke-cert", help="revoke an entity's certificate")
    p.add_argument("--id", required=True)
    p.add_argument("--ca-passphrase", default=None)
    p.add_argument("--ca-passphrase-file", default=None)
    common(p)
    p.set_defaults(func=cmd_revoke_cert)

    p = subparsers.add_parser("seed", help="provision a complete demo network")
    p.add_argument("--force", action="store_true")
    p.add_argument("--write-passphrase-files", action="store_true")
    p.add_argument("--merchants", nargs="*", default=None, help="subset of merchant ids")
    p.add_argument("--students", nargs="*", default=None, help="subset of student ids")
    common(p)
    p.set_defaults(func=cmd_seed)

    p = subparsers.add_parser("registry", help="list enrolled entities and balances")
    common(p)
    p.set_defaults(func=cmd_registry)

    p = subparsers.add_parser("run-switch", help="run the settlement switch")
    p.add_argument("--host", default=config.DEFAULT_HOST)
    p.add_argument("--port", type=int, default=config.DEFAULT_SWITCH_PORT)
    p.add_argument("--passphrase", default=None)
    p.add_argument("--passphrase-file", default=None)
    common(p)
    p.set_defaults(func=cmd_run_switch)

    def add_client_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("--switch-host", default=config.DEFAULT_HOST)
        p.add_argument("--switch-port", type=int, default=config.DEFAULT_SWITCH_PORT)
        p.add_argument("--passphrase", default=None)
        p.add_argument("--passphrase-file", default=None)

    p = subparsers.add_parser("run-terminal", help="interactive merchant terminal")
    p.add_argument("--merchant", required=True)
    p.add_argument("--wait", type=float, default=30.0)
    add_client_options(p)
    common(p)
    p.set_defaults(func=cmd_run_terminal)

    p = subparsers.add_parser("charge", help="single-shot merchant charge")
    p.add_argument("--merchant", required=True)
    p.add_argument("--payer", required=True)
    p.add_argument("--amount", required=True, help="amount, e.g. 12.50")
    p.add_argument("--currency", default=config.CURRENCY)
    p.add_argument("--wait", type=float, default=30.0)
    add_client_options(p)
    common(p)
    p.set_defaults(func=cmd_charge)

    p = subparsers.add_parser("pay", help="approve a pending request from the wallet")
    p.add_argument("--user", required=True)
    p.add_argument("--expect-amount", default=None, help="refuse requests for other amounts")
    p.add_argument("--expect-merchant", default=None, help="refuse requests from others")
    p.add_argument("--txn-id", default=None)
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    add_client_options(p)
    common(p)
    p.set_defaults(func=cmd_pay)

    p = subparsers.add_parser("run-wallet", help="listen for payment requests")
    p.add_argument("--user", required=True)
    p.add_argument("--auto-approve", action="store_true")
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--expect-merchant", default=None)
    p.add_argument("--expect-amount", default=None)
    add_client_options(p)
    common(p)
    p.set_defaults(func=cmd_run_wallet)

    p = subparsers.add_parser("balance", help="query a balance")
    p.add_argument("--user", default=None)
    p.add_argument("--merchant", default=None)
    p.add_argument("--admin", action="store_true", help="dump the whole ledger (local)")
    p.add_argument("--switch-host", default=config.DEFAULT_HOST)
    p.add_argument("--switch-port", type=int, default=config.DEFAULT_SWITCH_PORT)
    p.add_argument("--passphrase", default=None)
    p.add_argument("--passphrase-file", default=None)
    common(p)
    p.set_defaults(func=cmd_balance)

    p = subparsers.add_parser(
        "topup", help="credit an existing account (admin, audited by the switch)"
    )
    p.add_argument("--id", required=True, help="the account to credit (student or merchant)")
    p.add_argument("--amount", required=True, help="amount to add, e.g. 50.00")
    p.add_argument(
        "--passphrase",
        default=None,
        help="switch vault passphrase (admin authorisation)",
    )
    p.add_argument(
        "--switch-passphrase-file",
        default=None,
        help="file holding the switch vault passphrase",
    )
    common(p)
    p.set_defaults(func=cmd_topup)

    p = subparsers.add_parser("audit", help="audit log operations")
    audit_sub = p.add_subparsers(dest="audit_command", required=True)
    verify_p = audit_sub.add_parser("verify", help="verify the hash chain + signatures")
    verify_p.set_defaults(func=cmd_audit)
    log_p = audit_sub.add_parser(
        "log", help="list settled / declined / rejected payments from the audit log"
    )
    log_p.add_argument(
        "--event",
        action="append",
        help="only this audit event (repeatable), e.g. payment_declined",
    )
    log_p.add_argument("--limit", type=int, default=0, help="show only the last N entries")
    log_p.set_defaults(func=cmd_audit_log)
    common(p)
    p.set_defaults(func=cmd_audit)

    p = subparsers.add_parser("verify-receipt", help="verify a saved receipt offline")
    p.add_argument("--file", required=True)
    common(p)
    p.set_defaults(func=cmd_verify_receipt)

    p = subparsers.add_parser("attack", help="run an attack case (or --all)")
    p.add_argument("name", nargs="?", default=None)
    p.add_argument("--all", action="store_true")
    p.add_argument("--list", action="store_true")
    p.add_argument("--production-kdf", action="store_true", help="use full Argon2id (slow)")
    common(p)
    p.set_defaults(func=cmd_attack)

    p = subparsers.add_parser("rekey-demo", help="demonstrate automatic rekeying")
    p.add_argument("--messages", type=int, default=4)
    p.add_argument("--production-kdf", action="store_true")
    common(p)
    p.set_defaults(func=cmd_rekey_demo)

    p = subparsers.add_parser("gui", help="interactive web dashboard (localhost only)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    p.add_argument("--check", action="store_true", help="self-check the dashboard and exit")
    common(p)
    p.set_defaults(func=cmd_gui)

    p = subparsers.add_parser("demo", help="full three-process happy-path demo")
    p.add_argument("--fresh", action="store_true", help="re-provision the network first")
    common(p)
    p.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    config.setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    func: Callable[[argparse.Namespace], int] | None = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 1
    try:
        return func(args)
    except SecurePayError as exc:
        print(f"error: {exc.code}: {exc.message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
