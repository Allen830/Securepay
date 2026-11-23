from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import webbrowser
from collections import deque
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import IO, Any

from securepay import config

__all__ = ["Controller", "GuiError", "selftest", "serve"]

_AMOUNT_RE = re.compile(r"^\d{1,7}(\.\d{1,2})?$")
_ID_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")
_TXN_RE = re.compile(r"^TXN-[0-9A-Za-z-]{1,64}$")
_ID_NAME_RE = re.compile(r"^[a-z0-9-]{1,40}$")
_PORT_RE = re.compile(r"port=(\d+)")
_MAX_BODY = 4096
_LOG_LINE_RE = re.compile(r"^\d{2}:\d{2}:\d{2} (INFO|WARNING|ERROR|DEBUG)\b")
_ATTACK_ROW_RE = re.compile(r"^\[(PASS|FAIL)\] (\S+)\s+(.*)$", re.MULTILINE)
_ATTACK_TIMEOUT_ONE = 120.0
_ATTACK_TIMEOUT_ALL = 300.0
_ENROL_TIMEOUT = 120.0
_ALL = "*"

_ATTACK_META: dict[str, tuple[str, str, str]] = {
    "bit-flip": ("ChaCha20-Poly1305 authentication tag", "Integrity", "integrity"),
    "aad-tamper": (
        "AEAD associated data (frame header is authenticated)",
        "Integrity",
        "integrity",
    ),
    "replay-same-session": ("Strict monotonic message counter", "Integrity", "integrity"),
    "replay-new-session": (
        "Channel-bound Ed25519 signatures + persistent txn_id / per-payer nonce",
        "Non-repudiation",
        "nonrepudiation",
    ),
    "reorder": ("Exact-match message counter (no gaps, no reordering)", "Integrity", "integrity"),
    "stale-frame": ("Frame timestamp freshness window (30 s)", "Integrity", "integrity"),
    "mitm-modify-amount": (
        "Amount sits inside the AEAD ciphertext; authorisation is Ed25519-signed",
        "Integrity",
        "integrity",
    ),
    "mitm-key-substitution": (
        "Full-transcript Ed25519 signatures + Finished MAC",
        "Authentication",
        "keyexchange",
    ),
    "impersonate-switch": (
        "X.509 chain validation against the private campus CA",
        "Authentication",
        "authentication",
    ),
    "revoked-certificate": (
        "Signed CRL, re-read on every handshake",
        "Authentication",
        "authentication",
    ),
    "expired-certificate": (
        "X.509 validity window check",
        "Authentication",
        "authentication",
    ),
    "downgrade": (
        "Exact protocol version / cipher suite inside the signed transcript",
        "Authentication",
        "keyexchange",
    ),
    "vault-bruteforce": (
        "Argon2id vault + persistent unlock lockout",
        "Confidentiality",
        "keystorage",
    ),
    "malformed-frame": (
        "Length-prefixed framing with size cap; fail-closed parsing",
        "Integrity",
        "integrity",
    ),
    "double-spend": (
        "Persistent txn_id primary key + atomic ledger transaction",
        "Integrity",
        "nonrepudiation",
    ),
}

_TRACE_LINE_RE = re.compile(r"^(Traceback \(most recent call last\)|\w+(Error|Exception)\b)")


class GuiError(Exception):
    pass


class _LogDeque(deque[str]):

    def __init__(self, maxlen: int | None = None) -> None:
        super().__init__(maxlen=maxlen)
        self.total = 0
        self._guard = threading.Lock()

    def append(self, item: str) -> None:
        with self._guard:
            super().append(item)
            self.total += 1

    def snapshot(self, last: int) -> tuple[list[str], int]:
        with self._guard:
            return list(self)[-last:], self.total

    def after(self, position: int) -> tuple[list[str], int, bool]:
        with self._guard:
            kept = len(self)
            start = position if position > 0 else 0
            if start < self.total - kept:
                return list(self), self.total, True
            return list(self)[max(0, kept - (self.total - start)) :], self.total, False


class _Proc:

    def __init__(self, argv: list[str], ready: str | None, sink: deque[str]) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "securepay", *argv],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        self.lines: list[str] = []
        self.ready_event = threading.Event()
        self._ready = ready
        self._sink = sink
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        stream: IO[str] | None = self.proc.stdout
        if stream is None:
            return
        for raw in stream:
            line = raw.rstrip()
            self.lines.append(line)
            self._sink.append(line)
            if self._ready and self._ready in line:
                self.ready_event.set()

    def wait_ready(self, what: str, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while not self.ready_event.wait(timeout=0.2):
            if self.proc.poll() is not None:
                self.ready_event.wait(timeout=0.5)
                if self.ready_event.is_set():
                    return
                raise GuiError(f"{what} exited early: {self.tail()}")
            if time.monotonic() >= deadline:
                raise GuiError(f"{what} did not become ready in {timeout:.0f}s: {self.tail()}")

    def tail(self, count: int = 3) -> str:
        return " | ".join(self.lines[-count:]) or "no output"

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class Controller:

    def __init__(self, network_dir: Path) -> None:
        self.paths = config.NetworkPaths(root=network_dir.resolve())
        self.log = _LogDeque(maxlen=3000)
        self._switch: _Proc | None = None
        self._port: int | None = None
        self._busy = threading.Lock()
        self._attack_lock = threading.Lock()
        self._attack_running: str | None = None
        self._attack_results: dict[str, dict[str, Any]] = {}

    def _base(self) -> list[str]:
        return ["--network-dir", str(self.paths.root)]

    def _log_event(self, level: str, message: str) -> None:
        self.log.append(f"{time.strftime('%H:%M:%S')} {level:<7} {message}")

    def _cli(self, *args: str, timeout: float = 60.0, to_log: bool = False) -> tuple[int, str]:
        proc = subprocess.run(
            [sys.executable, "-u", "-m", "securepay", *self._base(), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        raw = (proc.stdout + proc.stderr).strip()
        if to_log:
            for ln in raw.splitlines():
                if _LOG_LINE_RE.match(ln):
                    self.log.append(ln.rstrip())
                elif _TRACE_LINE_RE.match(ln):
                    self._log_event("ERROR", "event=attack_process_crash " + ln.strip()[:300])
        kept = [ln for ln in raw.splitlines() if not _LOG_LINE_RE.match(ln)]
        return proc.returncode, ("\n".join(kept).strip() or raw)

    def _registry(self) -> list[dict[str, Any]]:
        if not self.paths.registry.exists():
            return []
        data = json.loads(self.paths.registry.read_text(encoding="utf-8"))
        return list(data["entities"])

    def _entity(self, entity_id: str, role: str) -> dict[str, Any]:
        if not _ID_RE.match(entity_id):
            raise GuiError("invalid identifier")
        for entity in self._registry():
            if entity["id"] == entity_id and entity["role"] == role:
                return entity
        raise GuiError(f"unknown {role}: {entity_id}")

    def _pass_file(self, kind_dir: Path, entity_id: str) -> str:
        path = kind_dir / f"{entity_id}.pass"
        if not path.exists():
            raise GuiError("no passphrase file; provision with the dashboard or `seed`")
        return str(path)

    def _switch_running(self) -> bool:
        return self._switch is not None and self._switch.proc.poll() is None

    def state(self) -> dict[str, Any]:
        entities = self._registry()
        balances: dict[str, str] = {}
        if entities and self.paths.ledger.exists():
            code, out = self._cli("balance", "--admin", timeout=30)
            if code == 0:
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        balances[parts[0]] = f"{parts[2]} {parts[3]}"
        receipts: list[str] = []
        receipt_info: list[dict[str, Any]] = []
        receipts_total = 0
        if self.paths.receipts_dir.exists():
            files = sorted(
                self.paths.receipts_dir.glob("TXN-*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            receipts_total = len(files)
            receipts = [p.stem for p in files[:20]]
            receipt_info = [self._receipt_summary(p) for p in files[:20]]
        return {
            "provisioned": bool(entities),
            "switch_running": self._switch_running(),
            "switch_port": self._port if self._switch_running() else None,
            "entities": [
                {
                    "id": e["id"],
                    "role": e["role"],
                    "name": e["name"],
                    "revoked": bool(e.get("revoked")),
                    "balance": balances.get(e["id"], ""),
                }
                for e in entities
            ],
            "receipts": receipts,
            "receipt_info": receipt_info,
            "receipts_total": receipts_total,
            "attacks": self.attack_state(),
        }

    @staticmethod
    def _receipt_summary(path: Path) -> dict[str, Any]:
        info: dict[str, Any] = {"txn": path.stem}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return info
        if isinstance(data, dict):
            for src, dst in (
                ("payer_id", "payer"),
                ("merchant_id", "merchant"),
                ("status", "status"),
                ("ledger_seq", "ledger_seq"),
                ("amount_minor", "amount_minor"),
            ):
                if isinstance(data.get(src), (str, int)):
                    info[dst] = data[src]
        return info

    def provision(self) -> dict[str, Any]:
        if self.paths.registry.exists():
            raise GuiError("network already provisioned")
        code, out = self._cli("seed", "--write-passphrase-files", timeout=180)
        return {"ok": code == 0, "output": out[-1500:]}

    def start_switch(self) -> dict[str, Any]:
        if not self.paths.registry.exists():
            raise GuiError("provision the network first")
        if self._switch_running():
            raise GuiError("switch is already running")
        pass_file = self._pass_file(self.paths.switch_dir, config.SWITCH_ID)
        proc = _Proc(
            [*self._base(), "run-switch", "--port", "0", "--passphrase-file", pass_file],
            "SWITCH_READY",
            self.log,
        )
        try:
            proc.wait_ready("switch", timeout=45)
        except GuiError:
            proc.stop()
            raise
        match = _PORT_RE.search(" ".join(proc.lines))
        if not match:
            proc.stop()
            raise GuiError("could not read the switch port")
        self._switch, self._port = proc, int(match.group(1))
        return {"ok": True, "port": self._port}

    def stop_switch(self) -> dict[str, Any]:
        if self._switch is not None:
            self._switch.stop()
        self._switch, self._port = None, None
        return {"ok": True}

    def charge(self, payer: str, merchant: str, amount: str, approve: bool) -> dict[str, Any]:
        self._entity(payer, "student")
        self._entity(merchant, "merchant")
        if not _AMOUNT_RE.match(amount):
            raise GuiError("amount must look like 12.50 (max 2 decimals)")
        if not self._switch_running() or self._port is None:
            raise GuiError("start the switch first")
        port = str(self._port)
        wallet = _Proc(
            [
                *self._base(), "run-wallet", "--user", payer, "--switch-port", port,
                "--passphrase-file", self._pass_file(self.paths.wallets_dir, payer),
                "--expect-merchant", merchant, "--expect-amount", amount,
                *(["--auto-approve"] if approve else []),
            ],
            "WALLET_READY",
            self.log,
        )
        try:
            wallet.wait_ready("wallet", timeout=45)
            if not approve and wallet.proc.stdin is not None:
                wallet.proc.stdin.write("n\n")
                wallet.proc.stdin.flush()
            code, out = self._cli(
                "charge", "--merchant", merchant, "--payer", payer, "--amount", amount,
                "--switch-port", port, "--wait", "30" if approve else "8",
                "--passphrase-file", self._pass_file(self.paths.terminals_dir, merchant),
                timeout=60,
            )
        finally:
            deadline = time.monotonic() + 3
            while wallet.proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.1)
            wallet.stop()
        match = re.search(r"PAYMENT_RESULT txn=(\S+) status=(\S+)", out)
        return {
            "ok": code == 0,
            "status": match.group(2) if match else "NOT_SETTLED",
            "txn": match.group(1) if match else None,
            "output": out[-1500:],
        }

    def enrol_student(
        self, student_id: str, name: str, balance: str, *, restart_switch: bool = True
    ) -> dict[str, Any]:
        if not self.paths.registry.exists():
            raise GuiError("provision the network first (use Start network below)")
        if not _ID_RE.match(student_id):
            raise GuiError("student ID must be 1-32 letters, digits or underscores")
        if any(e["id"] == student_id for e in self._registry()):
            self._log_event(
                "WARNING", f"event=enrolment_refused id={student_id} reason=duplicate_id"
            )
            raise GuiError(f"id {student_id} is already in the registry (any role)")
        clean_name = name.strip()
        if not clean_name or len(clean_name) > 64 or "\n" in clean_name or "\r" in clean_name:
            raise GuiError("full name must be 1-64 characters on one line")
        if not _AMOUNT_RE.match(balance) or float(balance) <= 0:
            raise GuiError("opening balance must look like 100.00 and be greater than 0")
        if not (self.paths.root / "ca.pass").exists():
            raise GuiError(
                "network/ca.pass is missing; re-provision from the dashboard "
                "(it writes the passphrase files)"
            )

        switch_pass = self._pass_file(self.paths.switch_dir, config.SWITCH_ID)

        was_running = self._switch_running()
        if was_running:
            self.stop_switch()
        try:
            code, out = self._cli(
                "issue-cert",
                "--role", "student",
                "--id", student_id,
                "--name", clean_name,
                "--balance", balance,
                "--ca-passphrase-file", str(self.paths.root / "ca.pass"),
                "--switch-passphrase-file", switch_pass,
                "--write-passphrase-file",
                str(self.paths.wallets_dir / f"{student_id}.pass"),
                timeout=_ENROL_TIMEOUT,
            )
        finally:
            restart_error = None
            if was_running and restart_switch:
                try:
                    self.start_switch()
                except GuiError as exc:
                    restart_error = str(exc)
        passphrase = None
        if code == 0:
            match = re.search(r"^VAULT_PASSPHRASE (\S+)$", out, re.MULTILINE)
            passphrase = match.group(1) if match else None
        result: dict[str, Any] = {"ok": code == 0, "output": out[-1500:], "passphrase": passphrase}
        if code != 0:
            result["error"] = out[-1500:] or "issue-cert failed"
        if restart_error is not None:
            result["restart_error"] = restart_error
        return result

    def topup(self, entity_id: str, amount: str) -> dict[str, Any]:
        if not _AMOUNT_RE.match(amount) or float(amount) <= 0:
            raise GuiError("amount must look like 50.00 and be greater than 0")
        if not self.paths.registry.exists():
            raise GuiError("provision the network first")
        entity = None
        for candidate in self._registry():
            if candidate["id"] == entity_id:
                entity = candidate
                break
        if entity is None:
            raise GuiError(f"unknown account: {entity_id}")
        if entity.get("revoked"):
            raise GuiError(f"{entity_id} has been revoked; top-ups are refused")
        if entity["role"] not in ("student", "merchant"):
            raise GuiError("only student and merchant accounts can be topped up")
        switch_pass = self._pass_file(self.paths.switch_dir, config.SWITCH_ID)
        code, out = self._cli(
            "topup",
            "--id", entity_id,
            "--amount", amount,
            "--switch-passphrase-file", switch_pass,
            timeout=60,
        )
        match = re.search(
            r"TOPUP_OK id=(\S+) amount_minor=(\d+) old_minor=(\d+) new_minor=(\d+)", out
        )
        result: dict[str, Any] = {"ok": code == 0, "output": out[-1500:]}
        if match:
            result["old_balance"] = match.group(3)
            result["new_balance"] = match.group(4)
        elif code != 0:
            result["error"] = out[-1500:] or "topup failed"
        return result

    @staticmethod
    def _cases() -> dict[str, str]:
        from securepay.attacks.simulator import CASES

        return {name: description for name, (description, _case) in CASES.items()}

    def attack_catalogue(self) -> list[dict[str, str]]:
        rows = []
        for name, description in self._cases().items():
            mechanism, prop, feature = _ATTACK_META.get(name, ("", "", ""))
            rows.append(
                {
                    "name": name,
                    "description": description,
                    "mechanism": mechanism,
                    "property": prop,
                    "feature": feature,
                }
            )
        return rows

    def attack_state(self) -> dict[str, Any]:
        return {
            "running": self._attack_running,
            "results": dict(self._attack_results),
            "catalogue": self.attack_catalogue(),
        }

    @staticmethod
    def _attack_result(name: str, passed: bool, detail: str, seconds: float) -> dict[str, Any]:
        if detail.startswith("harness error"):
            status = "error"
        else:
            status = "blocked" if passed else "not_blocked"
        return {
            "name": name,
            "status": status,
            "passed": passed,
            "detail": detail,
            "seconds": round(seconds, 2),
            "finished": time.strftime("%H:%M:%S"),
        }

    def _begin_attack(self, marker: str) -> None:
        if not self._attack_lock.acquire(blocking=False):
            raise GuiError("an attack run is already in progress; wait for it to finish")
        self._attack_running = marker

    def _end_attack(self) -> None:
        self._attack_running = None
        self._attack_lock.release()

    def run_attack(self, name: str) -> dict[str, Any]:
        if not isinstance(name, str) or not _ID_NAME_RE.match(name) or name not in self._cases():
            raise GuiError("unknown attack")
        self._begin_attack(name)
        started = time.monotonic()
        try:
            try:
                _code, out = self._cli("attack", name, timeout=_ATTACK_TIMEOUT_ONE, to_log=True)
            except subprocess.TimeoutExpired:
                result = self._attack_result(
                    name, False, f"harness error: timed out after {_ATTACK_TIMEOUT_ONE:.0f}s", 0.0
                )
                result["output"] = ""
                self._attack_results[name] = result
                self._log_event(
                    "ERROR", f"event=attack_error name={name} detail={result['detail']}"
                )
                return {"ok": False, **result}
            rows = [r for r in _ATTACK_ROW_RE.findall(out) if r[1] == name]
            seconds = time.monotonic() - started
            if len(rows) != 1:
                result = self._attack_result(
                    name, False, "harness error: no result line: " + out[-400:], seconds
                )
            else:
                result = self._attack_result(name, rows[0][0] == "PASS", rows[0][2], seconds)
            result["output"] = out[-1500:]
            self._attack_results[name] = result
            return {"ok": result["status"] == "blocked", **result}
        finally:
            self._end_attack()

    def attacks(self) -> dict[str, Any]:
        self._begin_attack(_ALL)
        started = time.monotonic()
        try:
            try:
                code, out = self._cli("attack", "--all", timeout=_ATTACK_TIMEOUT_ALL, to_log=True)
            except subprocess.TimeoutExpired:
                self._log_event("ERROR", "event=attack_suite_timeout")
                raise GuiError("the attack suite timed out") from None
            seconds = time.monotonic() - started
            known = self._cases()
            rows = [
                {"passed": r[0] == "PASS", "name": r[1], "detail": r[2]}
                for r in _ATTACK_ROW_RE.findall(out)
                if r[1] in known
            ]
            for row in rows:
                result = self._attack_result(
                    str(row["name"]), bool(row["passed"]), str(row["detail"]), 0.0
                )
                result["seconds"] = None
                result["output"] = (
                    f"{'PASS' if row['passed'] else 'FAIL'} {row['name']}: {row['detail']}"
                )
                self._attack_results[str(row["name"])] = result
            return {
                "ok": code == 0,
                "rows": rows,
                "seconds": round(seconds, 2),
                "summary": next(
                    (ln for ln in reversed(out.splitlines()) if re.search(r"\d+/\d+ attacks", ln)),
                    out.strip().splitlines()[-1] if out.strip() else "",
                ),
            }
        finally:
            self._end_attack()

    def reset_attack_results(self) -> dict[str, Any]:
        if self._attack_running is not None:
            raise GuiError("an attack run is in progress; wait for it to finish")
        self._attack_results.clear()
        return {"ok": True}

    def audit(self) -> dict[str, Any]:
        code, out = self._cli("audit", "verify")
        return {"ok": code == 0, "output": out[-1500:]}

    def audit_log(self) -> dict[str, Any]:
        code, out = self._cli("audit", "log", "--limit", "50")
        entries: list[dict[str, str]] = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("seq="):
                continue
            row = dict(part.split("=", 1) for part in line.split(" ") if "=" in part)
            entries.append(row)
        entries.reverse()
        return {"ok": code == 0, "output": out[-1500:], "entries": entries}

    def verify_receipt(self, txn: str) -> dict[str, Any]:
        if not _TXN_RE.match(txn):
            raise GuiError("invalid transaction id")
        path = self.paths.receipt(txn)
        if not path.exists():
            raise GuiError("no such receipt")
        code, out = self._cli("verify-receipt", "--file", str(path))
        return {"ok": code == 0, "output": out[-1500:]}

    def close(self) -> None:
        self.stop_switch()


_ROUTES = {
    "provision": lambda c, b: c.provision(),
    "start-switch": lambda c, b: c.start_switch(),
    "stop-switch": lambda c, b: c.stop_switch(),
    "charge": lambda c, b: c.charge(
        str(b.get("payer", "")),
        str(b.get("merchant", "")),
        str(b.get("amount", "")),
        bool(b.get("approve", True)),
    ),
    "enrol-student": lambda c, b: c.enrol_student(
        str(b.get("id", "")),
        str(b.get("name", "")),
        str(b.get("balance", "")),
    ),
    "topup": lambda c, b: c.topup(str(b.get("id", "")), str(b.get("amount", ""))),
    "attacks": lambda c, b: c.attacks(),
    "attack": lambda c, b: c.run_attack(str(b.get("name", ""))),
    "attacks-reset": lambda c, b: c.reset_attack_results(),
    "audit": lambda c, b: c.audit(),
    "audit-log": lambda c, b: c.audit_log(),
    "verify-receipt": lambda c, b: c.verify_receipt(str(b.get("txn", ""))),
}

_UNSERIALISED = frozenset({"attack", "attacks", "attacks-reset"})


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, controller: Controller, host: str, port: int) -> None:
        super().__init__((host, port), _Handler)
        self.controller = controller
        self.token = secrets.token_urlsafe(24)
        self.action_lock = threading.Lock()

    @property
    def loopback_hosts(self) -> set[str]:
        port = self.server_address[1]
        return {f"127.0.0.1:{port}", f"localhost:{port}"}


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.server.loopback_hosts

    def _token_ok(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-Token", ""), self.server.token)

    def do_GET(self) -> None:
        if not self._host_ok():
            port = self.server.server_address[1]
            self._send(
                403,
                (
                    "SecurePay dashboard: refused. It only answers on the loopback address.\n"
                    f"Open exactly  http://127.0.0.1:{port}/  in a browser running on this "
                    "machine (not via a VM/host IP or a forwarded name).\n"
                ).encode(),
                "text/plain; charset=utf-8",
            )
            return
        path = self.path.split("?", 1)[0]
        if path == "/api/state" and self._token_ok():
            self._json(200, self.server.controller.state())
            return
        if path == "/api/log":
            if not self._token_ok():
                self._json(403, {"error": "forbidden"})
                return
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            raw = next(
                (
                    v
                    for k, v in (p.split("=", 1) for p in query.split("&") if "=" in p)
                    if k == "after"
                ),
                "0",
            )
            try:
                after = int(raw)
            except ValueError:
                self._json(400, {"error": "after must be an integer"})
                return
            lines, total, dropped = self.server.controller.log.after(max(0, after))
            self._json(200, {"lines": lines, "total": total, "dropped": dropped})
            return
        asset = _ASSETS.get(path)
        if asset is not None:
            self._send(200, asset.encode(), asset.ctype)
            return
        page = _PAGES.get(path)
        if page is not None:
            self._send(
                200,
                page.replace("__TOKEN__", self.server.token).encode(),
                "text/html; charset=utf-8",
            )
            return
        self._json(403 if path.startswith("/api") else 404, {"error": "not allowed"})

    def do_POST(self) -> None:
        route = self.path.removeprefix("/api/")
        if not self._host_ok() or not self._token_ok():
            self._json(403, {"error": "forbidden"})
            return
        handler = _ROUTES.get(route)
        if handler is None:
            self._json(404, {"error": "unknown action"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > _MAX_BODY:
                raise GuiError("request too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise GuiError("invalid request")
            if route in _UNSERIALISED:
                self._json(200, handler(self.server.controller, body))
            else:
                with self.server.action_lock:
                    self._json(200, handler(self.server.controller, body))
        except (GuiError, ValueError) as exc:
            self._json(400, {"error": str(exc)})
        except subprocess.TimeoutExpired:
            self._json(400, {"error": "the command timed out"})


def _bind(controller: Controller, port: int) -> _Server:
    try:
        return _Server(controller, "127.0.0.1", port)
    except OSError as exc:
        if port == 0:
            raise
        print(
            f"Port {port} is not available ({exc.strerror}). Another dashboard is probably "
            "still running in another terminal: stop it with Ctrl-C. Using a free port instead."
        )
        return _Server(controller, "127.0.0.1", 0)


def _open_browser(url: str) -> None:

    def _go() -> None:
        try:
            webbrowser.open(url)
        except Exception:
            return

    threading.Thread(target=_go, daemon=True).start()


def serve(network_dir: Path, port: int = 8765, open_browser: bool = True) -> int:
    controller = Controller(network_dir)
    try:
        server = _bind(controller, port)
    except OSError as exc:
        print(f"Cannot start the dashboard: {exc}")
        return 1
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"SecurePay dashboard: {url}  (Ctrl-C to stop)")
    print("Open that exact address in a browser on this machine if none opens by itself.")
    if open_browser:
        _open_browser(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.server_close()
        controller.close()
    return 0


def selftest(network_dir: Path) -> int:
    import http.client

    failures = 0

    def step(name: str, fn: Callable[[], str]) -> None:
        nonlocal failures
        try:
            print(f"[PASS] {name}: {fn()}")
        except Exception as exc:
            failures += 1
            print(f"[FAIL] {name}: {exc}")

    def python_ok() -> str:
        return f"{sys.version.split()[0]} ({sys.executable})"

    def lib(module: str) -> str:
        mod = __import__(module)
        return str(getattr(mod, "__version__", "ok"))

    def child() -> str:
        out = subprocess.run(
            [sys.executable, "-u", "-m", "securepay", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return out.stdout.strip() or "ok"

    def http_roundtrip() -> str:
        controller = Controller(network_dir)
        server = _Server(controller, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
            conn.request("GET", "/")
            home = conn.getresponse()
            body = home.read().decode()
            if home.status != 200 or "SecurePay" not in body:
                raise RuntimeError(f"home page request returned HTTP {home.status}")
            token = body.split('name="tok" content="', 1)[1].split('"', 1)[0]
            for path in _PAGES:
                conn.request("GET", path)
                page = conn.getresponse()
                text = page.read().decode()
                if page.status != 200 or "SecurePay" not in text:
                    raise RuntimeError(f"page {path} returned HTTP {page.status}")
                page_token = text.split('name="tok" content="', 1)[1].split('"', 1)[0]
                if page_token != token:
                    raise RuntimeError(f"page {path} has a different token")
            for path in _ASSETS:
                conn.request("GET", path)
                asset = conn.getresponse()
                asset.read()
                if asset.status != 200:
                    raise RuntimeError(f"asset {path} returned HTTP {asset.status}")
            conn.request("GET", "/no-such-page")
            missing = conn.getresponse()
            missing.read()
            if missing.status != 404:
                raise RuntimeError(f"unknown path returned HTTP {missing.status}")
            conn.request("GET", "/api/state", headers={"X-Token": token})
            state = conn.getresponse()
            state.read()
            if state.status != 200:
                raise RuntimeError(f"state request returned HTTP {state.status}")
            conn.request("GET", "/api/log?after=0", headers={"X-Token": token})
            log = conn.getresponse()
            log.read()
            if log.status != 200:
                raise RuntimeError(f"log request returned HTTP {log.status}")
            conn.request("GET", "/api/log?after=0")
            unauth = conn.getresponse()
            unauth.read()
            if unauth.status != 403:
                raise RuntimeError(f"unauthenticated /api/log returned HTTP {unauth.status}")
            return (
                f"{len(_PAGES)} pages, {len(_ASSETS)} assets, state + incremental log OK "
                f"on port {server.server_address[1]}"
            )
        finally:
            server.shutdown()
            server.server_close()

    def port_free() -> str:
        probe = _Server(Controller(network_dir), "127.0.0.1", 8765)
        probe.server_close()
        return "default port 8765 is free"

    step("python", python_ok)
    step("PyNaCl (libsodium)", lambda: lib("nacl"))
    step("cryptography", lambda: lib("cryptography"))
    step("securepay runs as a child process", child)
    step("dashboard serves pages + API", http_roundtrip)
    step("default port", port_free)
    print("self-check: " + ("all good" if failures == 0 else f"{failures} problem(s) found"))
    return 0 if failures == 0 else 1


class _Asset:

    __slots__ = ("body", "ctype")

    def __init__(self, body: str, ctype: str) -> None:
        self.body = body
        self.ctype = ctype

    def encode(self) -> bytes:
        return self.body.encode("utf-8")


_CSS = r"""
:root{
 --bg:#0a111d;--bg2:#0d1626;--panel:#111b2d;--panel2:#15223a;--line:#22324d;--line2:#2c4064;
 --ink:#e7eef9;--mute:#93a4bf;--faint:#64779a;
 --accent:#2dd4bf;--accent2:#22d3ee;--accent-ink:#04201c;
 --ok:#34d399;--ok-bg:rgba(52,211,153,.12);--bad:#f87171;--bad-bg:rgba(248,113,113,.12);
 --warn:#fbbf24;--warn-bg:rgba(251,191,36,.12);--idle-bg:rgba(147,164,191,.10);
 --r:12px;--r-sm:8px;
 --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
 --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:130px}
html,body{overflow-x:clip}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
h1,h2,h3,h4,p{margin:0}
button,input,select{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--accent2);outline-offset:2px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
svg.i{width:1.15em;height:1.15em;flex:none;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;vertical-align:-.2em}
code,.mono{font-family:var(--mono)}


.top{position:sticky;top:0;z-index:30;background:rgba(10,17,29,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.top-in{max-width:1320px;margin:auto;padding:12px 24px;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px;margin-right:auto}
.logo{width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,#0f766e,#0e7490);display:grid;place-items:center;color:#d6fff8;font-size:22px}
.brand h1{font-size:19px;letter-spacing:-.01em;line-height:1.2}
.brand p{color:var(--mute);font-size:13px}
.chips{max-width:100%;display:flex;gap:8px;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border:1px solid var(--line2);border-radius:99px;font-size:12.5px;color:var(--mute);background:var(--bg2);white-space:nowrap}
.chip b{color:var(--ink);font-weight:600}
.dot{width:8px;height:8px;border-radius:50%;background:var(--faint);flex:none}
.chip.ok{border-color:rgba(52,211,153,.45)}.chip.ok .dot{background:var(--ok);box-shadow:0 0 0 3px var(--ok-bg)}
.chip.warn{border-color:rgba(251,191,36,.45)}.chip.warn .dot{background:var(--warn);box-shadow:0 0 0 3px var(--warn-bg)}
.chip.bad{border-color:rgba(248,113,113,.45)}.chip.bad .dot{background:var(--bad)}
.chip.demo{border-style:dashed;color:var(--accent2)}
nav.tabs{max-width:1320px;margin:auto;padding:0 24px 10px;display:flex;gap:4px;overflow-x:auto;scrollbar-width:none}
nav.tabs a{color:var(--mute);text-decoration:none;font-size:13.5px;padding:5px 12px;border-radius:99px;white-space:nowrap;transition:background .15s,color .15s}
nav.tabs a:hover{background:var(--panel2);color:var(--ink)}
nav.tabs a[aria-current=page]{background:rgba(45,212,191,.14);color:var(--accent);font-weight:600}


main{max-width:1320px;margin:auto;padding:22px 24px 60px;display:grid;grid-template-columns:minmax(0,1fr);gap:22px}main>*,.grid2>*,.grid3>*{min-width:0}
section.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:20px;scroll-margin-top:118px}
.sec-h{display:flex;align-items:flex-start;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.sec-h h2{font-size:17px;letter-spacing:-.005em;display:flex;align-items:center;gap:9px}
.sec-h h2 .i{color:var(--accent)}
.sec-h p{color:var(--mute);font-size:13.5px;flex-basis:100%}
.sec-h .grow{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.grid2{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:22px}
.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}


.kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:14px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:16px;transition:border-color .15s,transform .15s;min-width:0}
.kpi:hover{border-color:var(--line2);transform:translateY(-1px)}
.kpi .l{color:var(--mute);font-size:12.5px;display:flex;align-items:center;gap:7px;text-transform:uppercase;letter-spacing:.05em}
.kpi .v{font-size:23px;font-weight:650;margin-top:6px;letter-spacing:-.01em;overflow-wrap:anywhere}
.kpi .s{color:var(--faint);font-size:12.5px;margin-top:2px}
.kpi.ok .v{color:var(--ok)}.kpi.warn .v{color:var(--warn)}.kpi.bad .v{color:var(--bad)}.kpi.idle .v{color:var(--ink)}


.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:9px 15px;border-radius:var(--r-sm);border:1px solid var(--accent);background:var(--accent);color:var(--accent-ink);font-weight:600;cursor:pointer;transition:filter .15s,background .15s,border-color .15s,transform .05s;white-space:nowrap}
.btn:hover:not(:disabled){filter:brightness(1.08)}
.btn:active:not(:disabled){transform:translateY(1px)}
.btn.sec{background:transparent;color:var(--accent2);border-color:var(--line2)}
.btn.sec:hover:not(:disabled){border-color:var(--accent2);background:rgba(34,211,238,.07)}
.btn.danger{background:transparent;color:var(--bad);border-color:rgba(248,113,113,.5)}
.btn.danger:hover:not(:disabled){background:var(--bad-bg)}
.btn.sm{padding:6px 11px;font-size:13px}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn.busy{cursor:progress}
.spin{width:1em;height:1em;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:sp .8s linear infinite;flex:none}
@keyframes sp{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spin{animation-duration:2.4s}html{scroll-behavior:auto}*{transition:none!important}}
label.f{display:block;color:var(--mute);font-size:12.5px;margin:0 0 5px}
.field{margin-bottom:14px}
select,input[type=text],input[type=search]{width:100%;padding:9px 11px;border:1px solid var(--line2);border-radius:var(--r-sm);background:var(--bg2);min-height:40px}
select:hover,input:hover{border-color:var(--faint)}
.amt{display:flex;align-items:stretch}
.amt span{display:grid;place-items:center;padding:0 12px;border:1px solid var(--line2);border-right:0;border-radius:var(--r-sm) 0 0 var(--r-sm);background:var(--panel2);color:var(--mute);font-size:13px}
.amt input{border-radius:0 var(--r-sm) var(--r-sm) 0}
.seg{display:grid;grid-template-columns:1fr 1fr;border:1px solid var(--line2);border-radius:var(--r-sm);overflow:hidden}
.seg label{position:relative;display:flex;align-items:center;justify-content:center;gap:8px;padding:9px;cursor:pointer;color:var(--mute);transition:background .15s,color .15s;margin:0;font-size:14px}
.seg input{position:absolute;opacity:0;pointer-events:none}
.seg label:has(input:checked){background:var(--ok-bg);color:var(--ok)}
.seg label:last-child:has(input:checked){background:var(--bad-bg);color:var(--bad)}
.seg label:has(input:focus-visible){outline:2px solid var(--accent2);outline-offset:-2px}
.hint{color:var(--faint);font-size:12.5px;margin-top:6px}
.err{color:var(--bad);font-size:12.5px;margin-top:6px;min-height:1.2em}


.steps{display:flex;gap:10px;margin:2px 0 16px;flex-wrap:wrap}
.step{flex:1 1 150px;display:flex;gap:10px;align-items:center;padding:10px 12px;border:1px solid var(--line);border-radius:var(--r-sm);background:var(--bg2);min-width:0}
.step .n{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;font-size:13px;font-weight:700;background:var(--idle-bg);color:var(--mute);flex:none}
.step b{display:block;font-size:13.5px;font-weight:600}.step small{color:var(--faint);font-size:12px}
.step.done{border-color:rgba(52,211,153,.4)}.step.done .n{background:var(--ok-bg);color:var(--ok)}
.step.active{border-color:rgba(251,191,36,.5)}.step.active .n{background:var(--warn-bg);color:var(--warn)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.note{margin-top:14px;padding:10px 12px;border-radius:var(--r-sm);border:1px solid var(--line);background:var(--bg2);font-size:13.5px;color:var(--mute);display:none;gap:9px;align-items:flex-start}
.note.show{display:flex}.note.ok{border-color:rgba(52,211,153,.45);color:var(--ok);background:var(--ok-bg)}
.note.bad{border-color:rgba(248,113,113,.45);color:var(--bad);background:var(--bad-bg)}.note.warn{border-color:rgba(251,191,36,.45);color:var(--warn);background:var(--warn-bg)}


.seq{list-style:none;margin:18px 0 0;padding:0;display:grid;gap:0}
.seq li{display:grid;grid-template-columns:28px 1fr;gap:12px;position:relative;padding-bottom:12px}
.seq li:last-child{padding-bottom:0}
.seq li::before{content:"";position:absolute;left:13px;top:28px;bottom:0;width:2px;background:var(--line)}
.seq li:last-child::before{display:none}
.seq .b{width:28px;height:28px;border-radius:50%;display:grid;place-items:center;font-size:12.5px;font-weight:700;background:var(--idle-bg);color:var(--mute);border:1px solid var(--line2)}
.seq b{font-size:14px;font-weight:600;display:block}.seq small{color:var(--faint);font-size:12.5px;display:block}
.seq li.done .b{background:var(--ok-bg);color:var(--ok);border-color:rgba(52,211,153,.5)}
.seq li.fail .b{background:var(--bad-bg);color:var(--bad);border-color:rgba(248,113,113,.5)}
.seq li.work .b{background:var(--warn-bg);color:var(--warn);border-color:rgba(251,191,36,.5)}
.seq li.skip{opacity:.5}
.result{margin-top:16px;border:1px solid var(--line);border-radius:var(--r);padding:16px;background:var(--bg2);display:none}
.result.show{display:block}
.result.ok{border-color:rgba(52,211,153,.5);background:linear-gradient(180deg,var(--ok-bg),transparent 70%),var(--bg2)}
.result.bad{border-color:rgba(248,113,113,.5)}.result.warn{border-color:rgba(251,191,36,.5)}
.result h3{font-size:16px;display:flex;align-items:center;gap:9px}
.result.ok h3{color:var(--ok)}.result.bad h3{color:var(--bad)}.result.warn h3{color:var(--warn)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;margin:12px 0 0;font-size:13.5px}
.kv dt{color:var(--mute)}.kv dd{margin:0;min-width:0;overflow-wrap:anywhere}
.txn{display:inline-flex;align-items:center;gap:8px;flex-wrap:wrap}
.txn code{background:var(--panel2);border:1px solid var(--line);padding:2px 8px;border-radius:6px;font-size:12.5px;overflow-wrap:anywhere}
.pp{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px;padding:12px;border:1px solid rgba(251,191,36,.5);background:var(--warn-bg);border-radius:var(--r-sm)}
.pp code{background:#070d17;border:1px solid var(--line);padding:4px 10px;border-radius:6px;font:13px/1.4 var(--mono);overflow-wrap:anywhere;color:#f3dc9c}


.tools{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.tools .s{flex:1 1 200px;position:relative}
.tools .s .i{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--faint);pointer-events:none}
.tools .s input{padding-left:34px}
.tools select{width:auto;min-width:140px}
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:var(--r-sm)}
table{width:100%;border-collapse:collapse;font-size:14px;min-width:640px}
th,td{padding:10px 14px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--mute);background:var(--bg2);font-weight:600}
tbody tr{transition:background .12s}tbody tr:hover{background:var(--panel2)}tbody tr:last-child td{border-bottom:0}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid var(--line2);color:var(--mute)}
.pill.ok{color:var(--ok);border-color:rgba(52,211,153,.4);background:var(--ok-bg)}.pill.bad{color:var(--bad);border-color:rgba(248,113,113,.4);background:var(--bad-bg)}.pill.warn{color:var(--warn);border-color:rgba(251,191,36,.4);background:var(--warn-bg)}
.empty{padding:26px 16px;text-align:center;color:var(--mute);font-size:14px}
.empty .i{font-size:26px;color:var(--faint);display:block;margin:0 auto 6px}


.legend{display:flex;gap:10px;align-items:flex-start;padding:11px 14px;border:1px solid rgba(34,211,238,.3);background:rgba(34,211,238,.06);border-radius:var(--r-sm);color:var(--mute);font-size:13.5px;margin-bottom:14px}
.legend .i{color:var(--accent2);margin-top:3px}.legend b{color:var(--ink)}
.stats{display:grid;grid-template-columns:auto 1fr;gap:6px 22px;align-items:center;margin-bottom:14px;padding:14px 16px;background:var(--bg2);border:1px solid var(--line);border-radius:var(--r-sm)}
.stats .big{font-size:26px;font-weight:700;letter-spacing:-.01em;line-height:1.1}
.stats .big small{font-size:13px;color:var(--mute);font-weight:500;margin-left:6px}
.stats .big.ok{color:var(--ok)}.stats .big.bad{color:var(--bad)}
.meter{display:flex;height:10px;border-radius:99px;overflow:hidden;background:var(--idle-bg);grid-column:1/-1}
.meter i{display:block;transition:width .3s}.meter .m-ok{background:var(--ok)}.meter .m-bad{background:var(--bad)}.meter .m-err{background:var(--warn)}
.counts{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;color:var(--mute);justify-content:flex-end}
.counts b{color:var(--ink)}
.alist{display:grid;gap:10px}
.arow{border:1px solid var(--line);border-left-width:4px;border-radius:var(--r-sm);background:var(--bg2);padding:13px 14px;transition:border-color .15s,background .15s}
.arow:hover{background:var(--panel2)}.arow{scroll-margin-top:130px}
.arow.s-blocked{border-left-color:var(--ok)}.arow.s-not_blocked{border-left-color:var(--bad)}.arow.s-running,.arow.s-error{border-left-color:var(--warn)}.arow.s-idle{border-left-color:var(--line2)}
.ahead{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:6px 16px;align-items:center}
.aname{display:flex;align-items:baseline;gap:9px;flex-wrap:wrap}
.aname b{font-size:15px}.aname code{font-size:12px;color:var(--faint)}
.adesc{color:var(--mute);font-size:13.5px;margin-top:2px}
.amech{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:7px;font-size:12.5px;color:var(--faint)}
.tag{padding:1px 8px;border-radius:99px;border:1px solid var(--line2);font-size:11.5px;color:var(--accent2);background:rgba(34,211,238,.06)}
.badge{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border-radius:99px;font-size:12.5px;font-weight:700;letter-spacing:.01em;white-space:nowrap;border:1px solid var(--line2);color:var(--mute);background:var(--idle-bg)}
.badge.ok{color:var(--ok);background:var(--ok-bg);border-color:rgba(52,211,153,.5)}
.badge.bad{color:var(--bad);background:var(--bad-bg);border-color:rgba(248,113,113,.5)}
.badge.warn{color:var(--warn);background:var(--warn-bg);border-color:rgba(251,191,36,.5)}
details.d{margin-top:10px;border-top:1px dashed var(--line);padding-top:8px}
details.d summary{cursor:pointer;color:var(--accent2);font-size:13px;list-style:none;display:flex;align-items:center;gap:6px;width:max-content}
details.d summary::-webkit-details-marker{display:none}
details.d summary .i{transition:transform .15s}details.d[open] summary .i{transform:rotate(90deg)}
pre{margin:8px 0 0;padding:11px 13px;background:#070d17;border:1px solid var(--line);border-radius:var(--r-sm);color:#c5d6ee;overflow:auto;max-height:260px;font:12.5px/1.55 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere}


.warnbar{display:flex;gap:10px;padding:11px 14px;border:1px solid rgba(251,191,36,.35);background:var(--warn-bg);border-radius:var(--r-sm);color:#f3dc9c;font-size:13.5px;margin-bottom:16px}
.sc{text-decoration:none;background:var(--bg2);border:1px solid var(--line);border-radius:var(--r);padding:16px;display:flex;flex-direction:column;gap:10px;transition:border-color .15s;min-width:0}
.sc:hover{border-color:var(--line2)}
.sc .h{display:flex;align-items:center;gap:11px}
.sc .ic{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;background:rgba(45,212,191,.12);color:var(--accent);font-size:20px;flex:none}
.sc h3{font-size:15px;line-height:1.25}.sc .p{font-size:11.5px;color:var(--mute);text-transform:uppercase;letter-spacing:.06em}
.sc ul{margin:0;padding-left:18px;color:var(--mute);font-size:13.5px;display:grid;gap:4px}
.sc li::marker{color:var(--accent)}
.sc .src{font-size:12px;color:var(--faint)}
.tested{margin-top:auto;padding-top:10px;border-top:1px dashed var(--line)}
.tested small{display:block;color:var(--faint);font-size:12px;margin-bottom:6px}
.tchips{display:flex;gap:6px;flex-wrap:wrap}
.tchip{border:1px solid var(--line2);background:transparent;border-radius:99px;padding:2px 9px;font:12px var(--mono);color:var(--mute);cursor:pointer;display:inline-flex;gap:6px;align-items:center;transition:border-color .15s,color .15s}
.tchip:hover{border-color:var(--accent2);color:var(--ink)}
.tchip.ok{color:var(--ok);border-color:rgba(52,211,153,.5)}.tchip.bad{color:var(--bad);border-color:rgba(248,113,113,.5)}.tchip.warn{color:var(--warn);border-color:rgba(251,191,36,.5)}
.libs{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-top:16px}
.lib{border:1px solid var(--line);border-radius:var(--r-sm);padding:13px 15px;background:var(--bg2);font-size:13.5px;color:var(--mute)}
.lib b{color:var(--ink);display:block;margin-bottom:3px}
.tip{border-bottom:1px dotted var(--mute);cursor:help;position:relative;color:inherit}
.tip::after{content:attr(data-tip);position:absolute;left:0;visibility:hidden;bottom:calc(100% + 8px);width:max-content;max-width:min(300px,80vw);padding:8px 10px;border-radius:var(--r-sm);background:#050a12;border:1px solid var(--line2);color:var(--ink);font:12.5px/1.45 var(--sans);text-transform:none;letter-spacing:0;font-weight:400;opacity:0;pointer-events:none;transform:translateY(3px);transition:opacity .15s,transform .15s;z-index:20;white-space:normal}
.tip:hover::after,.tip:focus::after{opacity:1;transform:none;visibility:visible}


.vbox{border:1px solid var(--line);border-radius:var(--r-sm);padding:15px;background:var(--bg2);display:flex;flex-direction:column;gap:12px;min-width:0}
.vbox h3{font-size:15px;display:flex;gap:8px;align-items:center}.vbox h3 .i{color:var(--accent)}
.vbox p.d{color:var(--mute);font-size:13.5px}
.vres{display:none;border-radius:var(--r-sm);padding:13px;border:1px solid var(--line)}
.vres.show{display:block}.vres.ok{border-color:rgba(52,211,153,.5);background:var(--ok-bg)}.vres.bad{border-color:rgba(248,113,113,.5);background:var(--bad-bg)}
.vres .t{display:flex;align-items:center;gap:8px;font-weight:700;font-size:15px}
.vres.ok .t{color:var(--ok)}.vres.bad .t{color:var(--bad)}


.logbox{background:#070d17;border:1px solid var(--line);border-radius:var(--r-sm);height:380px;overflow:auto;font:12.5px/1.6 var(--mono)}
.ll{display:grid;grid-template-columns:72px 76px 1fr;gap:10px;padding:2px 12px;border-bottom:1px solid rgba(34,50,77,.4);align-items:baseline}
.ll:hover{background:rgba(255,255,255,.03)}
.ll .t{color:var(--faint)}.ll .lv{font-weight:700;font-size:11.5px;letter-spacing:.05em}.ll .m{overflow-wrap:anywhere;color:#c5d6ee;white-space:pre-wrap}
.ll.INFO .lv{color:var(--accent2)}.ll.WARNING .lv{color:var(--warn)}.ll.WARNING .m{color:#f3dc9c}.ll.ERROR .lv{color:var(--bad)}.ll.ERROR .m{color:#fbb4b4}.ll.DEBUG .lv{color:var(--faint)}
.fchips{display:flex;gap:6px;flex-wrap:wrap}
.fchip{border:1px solid var(--line2);background:transparent;border-radius:99px;padding:3px 11px;font-size:12.5px;color:var(--mute);cursor:pointer}
.fchip[aria-pressed=true]{background:var(--panel2);color:var(--ink);border-color:var(--accent2)}


#toasts{position:fixed;right:18px;bottom:18px;display:grid;gap:8px;z-index:60;max-width:min(380px,calc(100vw - 36px))}
.toast{display:flex;gap:10px;align-items:flex-start;padding:11px 14px;border-radius:var(--r-sm);background:#0b1424;border:1px solid var(--line2);box-shadow:0 10px 30px rgba(0,0,0,.45);font-size:13.5px;animation:ti .2s ease-out}
.toast.ok{border-color:rgba(52,211,153,.55)}.toast.ok .i{color:var(--ok)}.toast.bad{border-color:rgba(248,113,113,.55)}.toast.bad .i{color:var(--bad)}.toast.warn{border-color:rgba(251,191,36,.55)}.toast.warn .i{color:var(--warn)}
@keyframes ti{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
dialog{border:1px solid var(--line2);border-radius:var(--r);background:var(--panel);color:var(--ink);padding:22px;max-width:min(440px,calc(100vw - 32px));width:100%}
dialog::backdrop{background:rgba(3,7,13,.7)}
dialog h3{font-size:17px;margin-bottom:8px}dialog p{color:var(--mute);font-size:14px}
dialog .row{justify-content:flex-end;margin-top:20px}
footer{max-width:1320px;margin:auto;padding:0 24px 30px;color:var(--faint);font-size:12.5px}


@media (max-width:1100px){.kpis{grid-template-columns:repeat(3,minmax(0,1fr))}.grid3{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:820px){.grid2{grid-template-columns:1fr}.libs{grid-template-columns:1fr}.ahead{grid-template-columns:minmax(0,1fr) auto}.ahead .act{grid-column:1/-1}.ahead .act .btn{width:100%}}
@media (max-width:620px){
 .top-in,nav.tabs,main,footer{padding-left:16px;padding-right:16px}
 .kpis,.grid3{grid-template-columns:1fr 1fr}.grid3{grid-template-columns:1fr}
 section.card{padding:16px}.stats{grid-template-columns:1fr}.counts{justify-content:flex-start}
 .ahead{grid-template-columns:1fr}.ll{grid-template-columns:62px 1fr}.ll .lv{display:none}
 .sec-h .grow{margin-left:0}.btn{padding:10px 14px}
}
"""

_SHARED_JS = r"""
"use strict";
const T=document.querySelector('meta[name=tok]').content,$=id=>document.getElementById(id);
const NS='http://www.w3.org/2000/svg';
const PAGE=document.documentElement.dataset.page;
const S={st:null,busy:new Set(),netMsg:null,reachable:true};


function icon(n,cls){const s=document.createElementNS(NS,'svg');s.setAttribute('class','i'+(cls?' '+cls:''));s.setAttribute('aria-hidden','true');const u=document.createElementNS(NS,'use');u.setAttribute('href','#i-'+n);s.append(u);return s;}
function h(tag,attrs,...kids){const e=document.createElement(tag);for(const[k,v]of Object.entries(attrs||{})){if(v==null||v===false)continue;if(k==='class')e.className=v;else if(k==='text')e.textContent=v;else if(k.startsWith('on'))e.addEventListener(k.slice(2),v);else e.setAttribute(k,v===true?'':v);}for(const c of kids.flat()){if(c==null||c===false)continue;e.append(c.nodeType?c:document.createTextNode(String(c)));}return e;}
const spinner=()=>h('span',{class:'spin','aria-hidden':'true'});
const same=(()=>{const sig={};return(key,val)=>{const j=JSON.stringify(val);if(sig[key]===j)return true;sig[key]=j;return false;};})();
function tip(text,term){return h('span',{class:'tip',tabindex:'0','data-tip':text},term);}

async function api(p,b){
 const r=await fetch('/api/'+p,{method:b===undefined?'GET':'POST',headers:{'X-Token':T,'Content-Type':'application/json'},body:b===undefined?undefined:JSON.stringify(b)});
 let j;try{j=await r.json();}catch(e){j={error:'unexpected response from the dashboard ('+r.status+')'};}
 if(!r.ok&&!j.error)j.error='request failed ('+r.status+')';return j;
}
function toast(msg,kind){const t=h('div',{class:'toast '+(kind||'')},icon(kind==='ok'?'check':kind==='bad'?'x':kind==='warn'?'alert':'info'),h('div',{text:msg}));$('toasts').append(t);setTimeout(()=>t.remove(),kind==='bad'?7000:4200);}
function copy(text,label){
 const done=()=>toast((label||'Copied')+' to clipboard','ok');
 if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(text).then(done,fallback);}else fallback();
 function fallback(){const ta=h('textarea',{style:'position:fixed;opacity:0'});ta.value=text;document.body.append(ta);ta.select();try{document.execCommand('copy');done();}catch(e){toast('Copy failed: select the text manually','bad');}ta.remove();}
}
function confirmDlg(title,body,yes){return new Promise(res=>{const d=$('dlg');$('dlg-t').textContent=title;$('dlg-b').textContent=body;$('dlg-yes').textContent=yes||'Confirm';
 const fin=v=>{d.close();$('dlg-yes').onclick=$('dlg-no').onclick=null;d.oncancel=null;res(v);};
 $('dlg-yes').onclick=()=>fin(true);$('dlg-no').onclick=()=>fin(false);d.oncancel=e=>{e.preventDefault();fin(false);};
 if(typeof d.showModal==='function')d.showModal();else res(window.confirm(title+'\n'+body));});}
function promptDlg(title,body,yes){
 return confirmDlg(title,body,yes);}
function note(id,msg,kind){const e=$(id);e.className='note'+(msg?' show ':' ')+(kind||'');e.replaceChildren(...(msg?[icon(kind==='ok'?'check':kind==='bad'?'x':kind==='warn'?'alert':'info'),h('div',{text:msg})]:[]));}
async function guarded(key,btn,fn){
 if(S.busy.has(key))return;S.busy.add(key);const old=btn?[...btn.childNodes]:[];if(btn){btn.disabled=true;btn.classList.add('busy');btn.replaceChildren(spinner(),h('span',{text:'Working…'}));}
 try{await fn();}catch(e){toast(String(e&&e.message||e),'bad');S.reachable=false;}
 finally{S.busy.delete(key);if(btn){btn.classList.remove('busy');btn.replaceChildren(...old);}await refresh();}
}


const chip=(k,l,v)=>h('span',{class:'chip '+k},k==='demo'?icon('server'):h('span',{class:'dot'}),l+': ',h('b',{text:v}));
function renderHeader(){
 const s=S.st,prov=S.busy.has('prov');
 const net=!S.reachable?['bad','Dashboard unreachable']:prov?['warn','Provisioning…']:s.provisioned?['ok','Provisioned']:['','Not provisioned'];
 const sw=s.switch_running?['ok','Running'+(s.switch_port?' · port '+s.switch_port:'')]:['','Stopped'];
 if(!same('chips',[net,sw,location.host]))$('chips').replaceChildren(chip(net[0],'Network',net[1]),chip(sw[0],'Switch',sw[1]),chip('demo','Local demo',location.host));
}


async function refresh(){
 let s;try{s=await api('state');}catch(e){S.reachable=false;if(S.st)renderHeader();return;}
 if(s.error)return;S.reachable=true;S.st=s;
 renderHeader();
 if(typeof render==='function')render();
}
window.addEventListener('pageshow',()=>{refresh();});
"""

_SVG_SYMBOLS = """<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/></symbol>
<symbol id="i-key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M11 12l8-8M16 7l3 3M14 9l2 2"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></symbol>
<symbol id="i-x" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></symbol>
<symbol id="i-alert" viewBox="0 0 24 24"><path d="M12 4l9 16H3L12 4z"/><path d="M12 10v4M12 17h.01"/></symbol>
<symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></symbol>
<symbol id="i-user" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 20c1-4 4-6 8-6s7 2 8 6"/></symbol>
<symbol id="i-store" viewBox="0 0 24 24"><path d="M4 9l1.5-5h13L20 9M4 9h16M4 9v11h16V9M9 20v-6h6v6"/></symbol>
<symbol id="i-receipt" viewBox="0 0 24 24"><path d="M6 3h12v18l-3-2-3 2-3-2-3 2V3z"/><path d="M9 8h6M9 12h6"/></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 012-2h9"/></symbol>
<symbol id="i-play" viewBox="0 0 24 24"><path d="M8 5l11 7-11 7V5z"/></symbol>
<symbol id="i-reset" viewBox="0 0 24 24"><path d="M4 12a8 8 0 108-8H7"/><path d="M7 1v6H1" transform="translate(2 0)"/></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/></symbol>
<symbol id="i-link" viewBox="0 0 24 24"><path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1"/></symbol>
<symbol id="i-server" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></symbol>
<symbol id="i-net" viewBox="0 0 24 24"><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5l-6 5.5M12 11.5l6 5.5"/></symbol>
<symbol id="i-chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></symbol>
<symbol id="i-pen" viewBox="0 0 24 24"><path d="M4 20l1-4L16 5l3 3L8 19l-4 1zM14 7l3 3"/></symbol>
<symbol id="i-cert" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M7 9h6M7 12h4M15 16l-1 5 3-2 3 2-1-5"/></symbol>
<symbol id="i-swap" viewBox="0 0 24 24"><path d="M7 4L3 8l4 4M3 8h14M17 12l4 4-4 4M21 16H7"/></symbol>
<symbol id="i-vault" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="12" cy="12" r="3.5"/><path d="M12 8.5v1.5M12 14v1.5M8.5 12H10M14 12h1.5"/></symbol>
<symbol id="i-term" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/></symbol>
<symbol id="i-dot" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/></symbol>
<symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
<symbol id="i-card" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 10h18M7 15h4"/></symbol>
</defs></svg>"""

_NAV = [
    ("/", "Overview"),
    ("/payment", "Payment"),
    ("/accounts", "Accounts"),
    ("/attacks", "Attack simulator"),
    ("/audit", "Audit &amp; receipts"),
    ("/security", "Security architecture"),
    ("/log", "Live log"),
]


def _head(title: str, page: str) -> str:
    return (
        "<!doctype html>\n"
        '<html lang="en" data-page="' + page + '"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="tok" content="__TOKEN__">\n'
        '<meta name="color-scheme" content="dark">\n'
        "<title>" + title + "</title>\n"
        '<link rel="stylesheet" href="/assets/app.css">\n'
        '<script src="/assets/app.js"></script>\n'
        "</head><body>\n"
    )


def _chrome(path: str, body: str) -> str:
    nav = ""
    for href, label in _NAV:
        current = ' aria-current="page"' if href == path else ""
        nav += f'<a href="{href}"{current}>{label}</a>'
    return (
        _SVG_SYMBOLS
        + "\n"
        + '<header class="top">\n'
        + ' <div class="top-in">\n'
        + '  <div class="brand"><div class="logo"><svg class="i"><use href="#i-shield"/></svg></div>\n'
        + "   <div><h1>SecurePay</h1><p>Campus Payment Security Dashboard</p></div></div>\n"
        + '  <div class="chips" id="chips" aria-live="polite"></div>\n'
        + " </div>\n"
        + ' <nav class="tabs" aria-label="Sections">\n'
        + "  "
        + nav
        + "\n"
        + " </nav>\n"
        + "</header>\n\n"
        + body
        + "\n"
        + "<footer>SecurePay · MACS 902 Modern Cryptography · local demonstration only. "
        + "The dashboard listens on 127.0.0.1, requires a per-run token and runs the existing CLI; "
        + "it contains no cryptographic code of its own.</footer>\n\n"
        + '<div id="toasts" aria-live="polite"></div>\n'
        + '<dialog id="dlg"><h3 id="dlg-t"></h3><p id="dlg-b"></p><div class="row">'
        + '<button class="btn sec" id="dlg-no">Cancel</button><button class="btn" id="dlg-yes">'
        + "Confirm</button></div></dialog>\n"
        + "</body></html>\n"
    )


def _page_home() -> str:
    body = """<main>
 <div class="kpis" id="overview"></div>

 <section class="card" id="network">
  <div class="sec-h"><h2><svg class="i"><use href="#i-net"/></svg>Network management</h2>
   <p>Provision the demo campus network once (private CA, certificates, encrypted key vaults, ledger), then start the settlement switch.</p></div>
  <div class="steps" id="steps"></div>
  <div class="row">
   <button class="btn" id="b-prov"><svg class="i"><use href="#i-shield"/></svg>Start network</button>
   <button class="btn sec" id="b-start"><svg class="i"><use href="#i-play"/></svg>Start settlement switch</button>
   <button class="btn danger" id="b-stop"><svg class="i"><use href="#i-x"/></svg>Stop switch</button>
  </div>
  <div class="note" id="m-net" role="status"></div>
 </section>

 <section class="card">
  <div class="sec-h"><h2><svg class="i"><use href="#i-term"/></svg>Where to go next</h2>
   <p>Every page works on its own URL: refresh, deep links and the back button behave like a normal site.</p></div>
  <div class="grid3">
   <a class="sc" href="/payment"><div class="h"><div class="ic"><svg class="i"><use href="#i-store"/></svg></div><div><h3>Payment terminal</h3><div class="p">Charge a student</div></div></div><ul><li>Signed request, wallet approval, atomic settlement</li><li>Live 6-step transaction sequence</li></ul></a>
   <a class="sc" href="/accounts"><div class="h"><div class="ic"><svg class="i"><use href="#i-user"/></svg></div><div><h3>Accounts</h3><div class="p">Enrol &amp; top up</div></div></div><ul><li>Balances from the real ledger</li><li>Enrol a new student with an opening balance</li><li>Add funds (audited by the switch)</li></ul></a>
   <a class="sc" href="/attacks"><div class="h"><div class="ic"><svg class="i"><use href="#i-alert"/></svg></div><div><h3>Attack simulator</h3><div class="p">15 live attacks</div></div></div><ul><li>Run one case or the whole suite</li><li>Fresh throwaway lab per run</li></ul></a>
  </div>
 </section>
</main>
<script>
"use strict";
function renderKpis(){
 const s=S.st,ents=s.entities,stu=ents.filter(e=>e.role==='student'),mer=ents.filter(e=>e.role==='merchant');
 const A=s.attacks,cat=A.catalogue,res=A.results;let b=0,f=0,e=0;
 for(const c of cat){const r=res[c.name];if(!r)continue;if(r.status==='blocked')b++;else if(r.status==='not_blocked')f++;else e++;}
 const run=b+f+e,rev=ents.filter(e=>e.revoked).length;
 const k=[
  ['net','Network',s.provisioned?'Provisioned':'Not provisioned',s.provisioned?'CA, certificates and ledger exist':'Run provisioning first',s.provisioned?'ok':'idle'],
  ['server','Switch',s.switch_running?'Running':'Stopped',s.switch_running?'Listening on 127.0.0.1:'+s.switch_port:'Settlement switch is not accepting connections',s.switch_running?'ok':'warn'],
  ['user','Students',String(stu.length),rev?rev+' revoked':'registered wallets','idle'],
  ['store','Merchants',String(mer.length),'registered terminals','idle'],
  ['receipt','Receipts',String(s.receipts_total),s.receipts_total?'signed, saved by wallets':'none yet','idle'],
  ['shield','Attacks blocked',run?b+'/'+cat.length:'Not run',run?(f?f+' NOT blocked':e?e+' error(s)':run<cat.length?run+' of '+cat.length+' run':'all attacks stopped'):'Open the Attack simulator page',run?(f?'bad':e?'warn':'ok'):'idle']
 ];
 if(same('kpis',k))return;
 $('overview').replaceChildren(...k.map(([ic,l,v,sub,cls])=>h('div',{class:'kpi '+cls},h('div',{class:'l'},icon(ic),l),h('div',{class:'v',text:v}),h('div',{class:'s',text:sub}))));
}
function renderNetwork(){
 const s=S.st,prov=S.busy.has('prov'),start=S.busy.has('start');
 const stp=[
  ['1','Provision network',s.provisioned?'done':prov?'active':'','CA, keys, ledger'],
  ['2','Start switch',s.switch_running?'done':(start?'active':''),s.switch_running?'port '+s.switch_port:'settlement server'],
  ['3','Ready for payments',s.provisioned&&s.switch_running?'done':'','take a payment on the Payment page']
 ];
 if(!same('steps',[stp,prov])){$('steps').replaceChildren(...stp.map(([n,t,st,sub])=>h('div',{class:'step '+st},h('span',{class:'n'},st==='done'?icon('check'):n),h('div',{},h('b',{text:t}),h('small',{text:sub})))));}
 const dis=(id,d)=>{if(!S.busy.has(id.slice(2)))$(id).disabled=d;};
 dis('b-prov',s.provisioned||prov);dis('b-start',!s.provisioned||s.switch_running||start);dis('b-stop',!s.switch_running);
}
function render(){renderKpis();renderNetwork();}
$('b-prov').onclick=async e=>{
 const btn=e.currentTarget;
 if(!await confirmDlg('Start network?','This creates the private campus CA, certificates, encrypted key vaults, demo passphrase files and the ledger in the network directory. It runs once and can take a little while.','Start network'))return;
 note('m-net','Provisioning: generating CA, keys and ledger\u2026 this can take a while.','warn');
 await guarded('prov',btn,async()=>{const r=await api('provision',{});
  if(r.error)note('m-net',r.error,'bad');else if(r.ok){note('m-net','Network provisioned. Next: start the settlement switch.','ok');toast('Network provisioned','ok');}else note('m-net','Provisioning failed: '+(r.output||'unknown error'),'bad');});
};
$('b-start').onclick=e=>guarded('start',e.currentTarget,async()=>{note('m-net','Starting the settlement switch (unlocking its key vault)\u2026','warn');
 const r=await api('start-switch',{});if(r.error)note('m-net',r.error,'bad');else{note('m-net','Switch listening on 127.0.0.1:'+r.port,'ok');toast('Switch started on port '+r.port,'ok');}});
$('b-stop').onclick=async e=>{
 const btn=e.currentTarget;
 if(!await confirmDlg('Stop the settlement switch?','Payments cannot be taken until it is started again. Balances and receipts are kept.','Stop switch'))return;
 await guarded('stop',btn,async()=>{await api('stop-switch',{});note('m-net','Switch stopped.','');toast('Switch stopped','warn');});
};
refresh();setInterval(refresh,2000);
</script>"""
    return _head("SecurePay · Overview", "home") + _chrome("/", body)


def _page_payment() -> str:
    body = """<main>
 <div class="grid2">
  <section class="card" id="payment">
   <div class="sec-h"><h2><svg class="i"><use href="#i-store"/></svg>Payment terminal</h2>
    <p>The merchant terminal sends a signed request over a real TCP session; the student's wallet independently verifies and signs the approval.</p></div>
   <div class="field"><label class="f" for="payer">Student</label><select id="payer"></select></div>
   <div class="field"><label class="f" for="merchant">Merchant terminal</label><select id="merchant"></select></div>
   <div class="field"><label class="f" for="amount">Payment amount</label>
    <div class="amt"><span>AED</span><input type="text" id="amount" value="12.50" inputmode="decimal" autocomplete="off" aria-describedby="amount-err"></div>
    <div class="err" id="amount-err"></div></div>
   <div class="field"><label class="f" id="dec-l">Student decision</label>
    <div class="seg" role="radiogroup" aria-labelledby="dec-l">
     <label><input type="radio" name="dec" value="1" checked><svg class="i"><use href="#i-check"/></svg>Student approves</label>
     <label><input type="radio" name="dec" value="0"><svg class="i"><use href="#i-x"/></svg>Student declines</label></div></div>
   <button class="btn" id="b-charge" style="width:100%"><svg class="i"><use href="#i-lock"/></svg>Charge student</button>
   <div class="hint" id="charge-hint"></div>
   <div class="result" id="result" role="status" aria-live="polite"></div>
  </section>
  <section class="card">
   <div class="sec-h"><h2><svg class="i"><use href="#i-swap"/></svg>Transaction sequence</h2>
    <p>What happens on each payment. Step status reflects the real outcome of the last charge.</p></div>
   <ol class="seq" id="seq"></ol>
  </section>
 </div>
</main>
<script>
"use strict";
const S2={payRes:null};
const SEQ=[
 ['Merchant initiates a payment request','Terminal signs the request (Ed25519) and sends it to the switch'],
 ['Student wallet receives the request','Switch pushes it to the payer\\u2019s wallet; wallet verifies merchant certificate and signature'],
 ['Student approves or declines','Approval or decline is signed by the student\\u2019s key and bound to this session'],
 ['Settlement switch processes the payment','Atomic ledger transaction: nonce check, debit, credit'],
 ['Signed receipt is generated','Switch signs the receipt and returns it'],
 ['Audit record is maintained','Hash-chained, switch-signed audit entry appended (settlement, decline or rejection)']
];
function fill(sel,items,emptyText){const v=sel.value;sel.replaceChildren(...(items.length?items:[['',emptyText]]).map(([val,txt])=>new Option(txt,val)));if(v&&items.some(i=>i[0]===v))sel.value=v;}
function renderForms(){
 const s=S.st,stu=s.entities.filter(e=>e.role==='student'&&!e.revoked),mer=s.entities.filter(e=>e.role==='merchant'&&!e.revoked);
 if(!same('payer',stu))fill($('payer'),stu.map(e=>[e.id,e.name+' ('+e.id+')'+(e.balance?' \\u00b7 '+e.balance:'')]),'Provision the network first');
 if(!same('merch',mer))fill($('merchant'),mer.map(e=>[e.id,e.name]),'Provision the network first');
 const ready=s.provisioned&&s.switch_running;
 $('b-charge').disabled=!ready||S.busy.has('charge');
 $('charge-hint').textContent=ready?'':(s.provisioned?'Start the settlement switch (Overview page) to enable payments.':'Provision the network and start the switch to enable payments.');
}
function renderSeq(){
 const r=S2.payRes,pend=S.busy.has('charge');let st=SEQ.map(()=>'');
 if(pend)st=SEQ.map(()=>'work');
 else if(r){
  if(r.status==='SETTLED')st=SEQ.map(()=>'done');
  else if(r.declined)st=['done','done','fail','skip','skip',r.recorded?'done':'skip'];
 }
 if(same('seq',[st]))return;
 $('seq').replaceChildren(...SEQ.map(([t,sub],i)=>h('li',{class:st[i]},h('span',{class:'b'},st[i]==='done'?icon('check'):st[i]==='fail'?icon('x'):String(i+1)),h('div',{},h('b',{text:t}),h('small',{text:sub})))));
}
function renderResult(){
 const r=S2.payRes,box=$('result');
 if(!r){box.className='result';box.replaceChildren();return;}
 if(same('res',r))return;
 const settled=r.status==='SETTLED';
 const cls=settled?'ok':r.declined?'warn':'bad';
 const kids=[h('h3',{},icon(settled?'check':r.declined?'alert':'x'),settled?'Payment settled':r.declined?'Declined by student, nothing was charged':'Payment not settled')];
 const kv=h('dl',{class:'kv'});
 if(r.declined&&r.recorded)kv.append(h('dt',{text:'Audit log'}),h('dd',{text:'Decline signed by the student and recorded (payment_declined)'}));
 kv.append(h('dt',{text:'Student'}),h('dd',{text:r.payer}),h('dt',{text:'Merchant'}),h('dd',{text:r.merchant}),h('dt',{text:'Amount'}),h('dd',{text:r.amount+' AED'}),h('dt',{text:'Settlement status'}),h('dd',{},h('span',{class:'pill '+(settled?'ok':r.declined?'warn':'bad'),text:r.declined?'DECLINED':r.status})));
 if(r.txn)kv.append(h('dt',{text:'Transaction ID'}),h('dd',{},h('span',{class:'txn'},h('code',{text:r.txn}),h('button',{class:'btn sec sm',type:'button','aria-label':'Copy transaction ID',onclick:()=>copy(r.txn,'Transaction ID')},icon('copy'),'Copy'))));
 kids.push(kv);
 if(settled)kids.push(h('div',{class:'row',style:'margin-top:12px'},h('button',{class:'btn sec sm',type:'button',onclick:()=>{location.href='/audit?receipt='+encodeURIComponent(r.txn);}},icon('cert'),'Verify this receipt')));
 else{
  if(r.declined&&r.recorded)kids.push(h('div',{class:'row',style:'margin-top:12px'},h('button',{class:'btn sec sm',type:'button',onclick:()=>{location.href='/audit';}},icon('cert'),'View in audit log')));
  kids.push(h('details',{class:'d'},h('summary',{},icon('chev'),'Technical output'),h('pre',{text:r.output||'(no output)'})));}
 box.className='result show '+cls;box.replaceChildren(...kids);
}
function render(){renderForms();renderSeq();renderResult();}
const AMT=/^\\d{1,7}(\\.\\d{1,2})?$/;
$('amount').addEventListener('input',()=>{$('amount-err').textContent='';});
$('b-charge').onclick=e=>{
 const amount=$('amount').value.trim(),approve=document.querySelector('input[name=dec]:checked').value==='1';
 if(!AMT.test(amount)){$('amount-err').textContent='Enter an amount like 12.50 (up to 7 digits, max 2 decimals).';$('amount').focus();return;}
 const payer=$('payer').value,merchant=$('merchant').value;
 S2.payRes=null;renderResult();
 return guarded('charge',e.currentTarget,async()=>{
  const r=await api('charge',{payer,merchant,amount,approve});
  if(r.error){S2.payRes={status:'ERROR',payer,merchant,amount,output:r.error};toast(r.error,'bad');return;}
  S2.payRes={status:r.status,txn:r.txn,payer,merchant,amount,output:r.output,declined:!approve&&r.status!=='SETTLED',recorded:/declined_by_payer/.test(r.output||'')};
  toast(r.status==='SETTLED'?'Payment settled':approve?'Payment not settled':'Declined, nothing charged',r.status==='SETTLED'?'ok':approve?'bad':'warn');
 });
};
refresh();setInterval(refresh,2000);
</script>"""
    return _head("SecurePay · Payment", "payment") + _chrome("/payment", body)


def _page_accounts() -> str:
    body = """<main>
 <section class="card" id="enrol">
  <div class="sec-h"><h2><svg class="i"><use href="#i-user"/></svg>Enrol a new student</h2>
   <p>Issues a real certificate and encrypted wallet vault through <code>securepay issue-cert</code>, with an opening balance on the ledger. The vault passphrase is generated fresh and shown below exactly once.</p></div>
  <div class="grid2">
   <div>
    <div class="field"><label class="f" for="enr-id">Student ID</label>
     <input type="text" id="enr-id" maxlength="32" placeholder="e.g. 902201" autocomplete="off" aria-describedby="enr-id-err">
     <div class="err" id="enr-id-err"></div></div>
    <div class="field"><label class="f" for="enr-name">Full name</label>
     <input type="text" id="enr-name" maxlength="64" placeholder="e.g. Noor Al-Sayed" autocomplete="off" aria-describedby="enr-name-err">
     <div class="err" id="enr-name-err"></div></div>
    <div class="field"><label class="f" for="enr-bal">Opening balance</label>
     <div class="amt"><span>AED</span><input type="text" id="enr-bal" value="250.00" inputmode="decimal" autocomplete="off" aria-describedby="enr-bal-err"></div>
     <div class="err" id="enr-bal-err"></div>
     <div class="hint">The switch loads its registry at startup, so if it is running it is stopped for the enrolment and restarted automatically afterwards.</div></div>
    <button class="btn" id="b-enrol" style="width:100%"><svg class="i"><use href="#i-plus"/></svg>Enrol student</button>
   </div>
   <div class="result" id="enrol-res" role="status" aria-live="polite"></div>
  </div>
 </section>

 <section class="card" id="accounts">
  <div class="sec-h"><h2><svg class="i"><use href="#i-card"/></svg>Accounts and balances</h2><p>Read from the settlement ledger and enrolment registry. Top-ups are admin operations recorded in the switch-signed audit chain.</p></div>
  <div class="tools">
   <div class="s"><svg class="i"><use href="#i-search"/></svg><input type="search" id="acct-q" placeholder="Search by name, ID or role" aria-label="Search accounts"></div>
   <select id="acct-role" aria-label="Filter by role"><option value="">All roles</option><option value="student">Students</option><option value="merchant">Merchants</option></select>
  </div>
  <div class="tw"><table><thead><tr><th>Account name</th><th>Account ID</th><th>Role</th><th class="n">Balance</th><th>Status</th><th></th></tr></thead><tbody id="accts"></tbody></table></div>
 </section>
</main>
<script>
"use strict";
const IDRE=/^[A-Za-z0-9_]{1,32}$/,AMTRE=/^\\d{1,7}(\\.\\d{1,2})?$/;
function err(id,msg){$(id).textContent=msg||'';}
function enrolValidate(id,name,bal){
 let ok=true;
 if(!IDRE.test(id)){err('enr-id-err','1-32 letters, digits or underscores.');ok=false;}else err('enr-id-err','');
 const nm=name.trim();
 if(!nm||nm.length>64){err('enr-name-err','Enter a name of 1-64 characters.');ok=false;}else err('enr-name-err','');
 if(!AMTRE.test(bal)||parseFloat(bal)<=0){err('enr-bal-err','Enter an amount like 250.00 (greater than 0).');ok=false;}else err('enr-bal-err','');
 return ok;
}
function renderEnrolResult(r){
 const box=$('enrol-res');
 if(!r){box.className='result';box.replaceChildren();return;}
 const kids=[h('h3',{},icon(r.ok?'check':r.error?'x':'alert'),r.ok?'Student enrolled':r.error?'Enrolment failed':'Enrolment problem')];
 if(r.ok&&r.passphrase!=null){
  const kv=h('dl',{class:'kv'});
  kv.append(h('dt',{text:'Student ID'}),h('dd',{},h('code',{text:r.id})),h('dt',{text:'Name'}),h('dd',{text:r.name}),h('dt',{text:'Opening balance'}),h('dd',{text:r.balance+' AED'}));
  kids.push(kv);
  kids.push(h('div',{class:'pp'},icon('alert'),h('div',{},h('b',{text:'Vault passphrase (shown ONCE): '}),
   h('code',{text:r.passphrase}),' ',
   h('button',{class:'btn sec sm',type:'button',onclick:()=>copy(r.passphrase,'Passphrase')},icon('copy'),'Copy'))));
  kids.push(h('p',{class:'hint',text:'Store this passphrase securely \\u2014 it unlocks the student\\u2019s wallet vault and is needed to approve payments. The .pass file written inside the network directory is demo convenience only.'}));
  if(r.restarted)kids.push(h('p',{class:'hint',text:'The switch was running, so it was stopped for the enrolment and restarted (new port ' + r.restarted + ').'}));
  else if(r.restart_error)kids.push(h('p',{class:'hint',text:'Warning: the switch could not be restarted automatically: '+r.restart_error}));
 }else if(r.ok){
  kids.push(h('p',{class:'hint',text:'Enrolled, but the passphrase line was not found in the command output; it is stored in the wallet .pass file inside the network directory.'}));
 }else{
  kids.push(h('pre',{text:r.error||r.output||'unknown error'}));
 }
 box.className='result show '+(r.ok?'ok':r.error?'bad':'warn');box.replaceChildren(...kids);
}
$('b-enrol').onclick=async e=>{
 const btn=e.currentTarget,old=[...btn.childNodes];
 const id=$('enr-id').value.trim(),name=$('enr-name').value,bal=$('enr-bal').value.trim();
 if(!enrolValidate(id,name,bal))return;
 if(!await confirmDlg('Enrol student '+id+'?','This issues a certificate and encrypted wallet vault for '+name.trim()+' with an opening balance of '+bal+' AED, and appends the student to the registry. If the switch is running it will be restarted automatically.','Enrol student'))return;
 S.busy.add('enrol');btn.disabled=true;btn.classList.add('busy');btn.replaceChildren(spinner(),h('span',{text:'Working…'}));
 let out=null;
 try{
  const r=await api('enrol-student',{id,name:name.trim(),balance:bal});
  if(r.error){out={ok:false,error:r.error,id,name:name.trim(),balance:bal};toast(r.error,'bad');}
  else{out={ok:r.ok,error:r.error,output:r.output,id,name:name.trim(),balance:bal,passphrase:r.passphrase,restarted:r.restarted||null,restart_error:r.restart_error||null};
   if(r.ok)toast('Student '+id+' enrolled','ok');else toast('Enrolment failed','bad');}
 }catch(ex){out={ok:false,error:String(ex&&ex.message||ex),id};toast('Could not reach the dashboard: '+ex,'bad');}
 finally{S.busy.delete('enrol');btn.classList.remove('busy');btn.replaceChildren(...old);renderEnrolResult(out);await refresh();}
};
function topupDialog(entity){
 return new Promise(res=>{
  const d=h('dialog',{},h('h3',{},icon('plus'),'Add funds: '+entity.name),
   h('p',{},h('code',{text:entity.id}),' \\u00b7 current balance ',h('b',{text:entity.balance||'\\u2014'})),
   h('div',{class:'field',style:'margin-top:10px'},h('label',{class:'f',for:'tp-amt'},'Amount to add (AED)'),
    h('div',{class:'amt'},h('span',{text:'AED'}),h('input',{type:'text',id:'tp-amt',value:'50.00',inputmode:'decimal',autocomplete:'off'})),h('div',{class:'err',id:'tp-err'})),
   h('div',{class:'row'},h('button',{class:'btn sec',type:'button',id:'tp-no'},'Cancel'),h('button',{class:'btn',type:'button',id:'tp-yes'},'Add funds')));
  document.body.append(d);
  const finish=v=>{d.close();d.remove();res(v);};
  d.querySelector('#tp-no').onclick=()=>finish(null);
  d.querySelector('#tp-yes').onclick=()=>{
   const amt=d.querySelector('#tp-amt').value.trim();
   if(!AMTRE.test(amt)||parseFloat(amt)<=0){d.querySelector('#tp-err').textContent='Enter an amount like 50.00 (greater than 0).';return;}
   finish(amt);
  };
  d.addEventListener('cancel',ev=>{ev.preventDefault();finish(null);});
  if(typeof d.showModal==='function')d.showModal();else{const amt=window.prompt('Amount to add (AED) for '+entity.id);finish(amt&&AMTRE.test(amt.trim())?amt.trim():null);}
 });
}
async function doTopup(entity){
 const amount=await topupDialog(entity);
 if(!amount)return;
 if(!await confirmDlg('Add '+amount+' AED to '+entity.id+'?','The credit is applied by an admin operation authorised with the switch passphrase and recorded in the switch-signed audit chain (verify it on the Audit page).','Add funds'))return;
 await guarded('topup-'+entity.id,null,async()=>{
  const r=await api('topup',{id:entity.id,amount});
  if(r.error){toast(r.error,'bad');return;}
  if(r.ok){toast('Topped up '+entity.id+': '+((r.old_balance/100).toFixed(2))+' \\u2192 '+((r.new_balance/100).toFixed(2))+' AED','ok');}
  else toast('Top-up failed','bad');
 });
}
function renderAccounts(){
 const s=S.st,q=$('acct-q').value.trim().toLowerCase(),role=$('acct-role').value;
 const rows=s.entities.filter(e=>e.role!=='switch'&&e.balance).filter(e=>(!role||e.role===role)&&(!q||[e.name,e.id,e.role].join(' ').toLowerCase().includes(q)));
 if(same('accts',[rows.map(r=>[r.id,r.balance]),q,role]))return;
 if(!rows.length){$('accts').replaceChildren(h('tr',{},h('td',{colspan:'6'},h('div',{class:'empty'},icon('user'),s.provisioned?(q||role?'No accounts match this filter.':'No account balances available.'):'No accounts yet. Provision the demo network to create students and merchants.'))));return;}
 $('accts').replaceChildren(...rows.map(e=>h('tr',{},
  h('td',{text:e.name}),h('td',{},h('code',{text:e.id})),h('td',{text:e.role[0].toUpperCase()+e.role.slice(1)}),h('td',{class:'n',text:e.balance}),
  h('td',{},h('span',{class:'pill '+(e.revoked?'bad':'ok'),text:e.revoked?'Revoked':'Active'})),
  h('td',{},e.revoked?null:h('button',{class:'btn sec sm',type:'button','aria-label':'Add funds to '+e.id,onclick:()=>doTopup(e)},icon('plus'),'Add funds')))));
}
function render(){renderAccounts();}
['enr-id','enr-name','enr-bal'].forEach(id=>$(id).addEventListener('input',()=>{err(id+'-err','');}));
$('acct-q').addEventListener('input',()=>S.st&&renderAccounts());$('acct-role').addEventListener('change',()=>S.st&&renderAccounts());
refresh();setInterval(refresh,2000);
</script>"""
    return _head("SecurePay · Accounts", "accounts") + _chrome("/accounts", body)


def _page_attacks() -> str:
    body = """<main>
 <section class="card" id="attacks">
  <div class="sec-h"><h2><svg class="i"><use href="#i-alert"/></svg>Attack simulator</h2>
   <p>Each attack runs against a fresh throwaway lab (real TCP, real switch, real MITM proxy) through <code>securepay attack &lt;name&gt;</code>. Your payment network is never touched.</p>
   <div class="grow">
    <button class="btn" id="b-att"><svg class="i"><use href="#i-play"/></svg>Run all 15 attacks</button>
    <button class="btn sec" id="b-attreset"><svg class="i"><use href="#i-reset"/></svg>Reset displayed results</button>
   </div></div>
  <div class="legend"><svg class="i"><use href="#i-info"/></svg><div><b>How to read the result.</b> <b>BLOCKED &ndash; PASS</b> means the attack was attempted and the security mechanism stopped it (good). <b>NOT BLOCKED &ndash; FAIL</b> means the attack got through (bad). <b>Execution Error</b> means the test harness itself failed, so nothing is proven either way.</div></div>
  <div class="stats" id="astats"></div>
  <div class="tools">
   <div class="s"><svg class="i"><use href="#i-search"/></svg><input type="search" id="att-q" placeholder="Search attacks, mechanisms or properties" aria-label="Search attacks"></div>
   <select id="att-f" aria-label="Filter by status"><option value="">All statuses</option><option value="idle">Not run</option><option value="blocked">Blocked &ndash; pass</option><option value="not_blocked">Not blocked &ndash; fail</option><option value="error">Execution error</option></select>
  </div>
  <div class="alist" id="alist"></div>
 </section>
</main>
<script>
"use strict";
const SA={openD:new Set(),attackLocal:null};
const AST={
 idle:{label:'Not Run',cls:'',icon:'dot'},
 running:{label:'Running',cls:'warn',icon:null},
 blocked:{label:'BLOCKED \\u2013 PASS',cls:'ok',icon:'check'},
 not_blocked:{label:'NOT BLOCKED \\u2013 FAIL',cls:'bad',icon:'x'},
 error:{label:'Execution Error',cls:'warn',icon:'alert'}
};
const pretty=n=>n.split('-').map(w=>w[0].toUpperCase()+w.slice(1)).join(' ');
function attackSummary(){
 const A=S.st.attacks,cat=A.catalogue,res=A.results;let b=0,f=0,e=0;
 for(const c of cat){const r=res[c.name];if(!r)continue;if(r.status==='blocked')b++;else if(r.status==='not_blocked')f++;else e++;}
 return{total:cat.length,blocked:b,failed:f,errors:e,run:b+f+e};
}
function attackStatus(c){
 const A=S.st.attacks;
 if(A.running===c.name||A.running==='*'||SA.attackLocal===c.name||SA.attackLocal==='*')return'running';
 const r=A.results[c.name];return r?r.status:'idle';
}
function anyAttackBusy(){return !S.st||!!(S.st.attacks.running||SA.attackLocal);}
function renderAttacks(){
 const A=S.st.attacks,cat=A.catalogue,sm=attackSummary(),busy=anyAttackBusy();
 const q=$('att-q').value.trim().toLowerCase(),f=$('att-f').value;
 if(!same('astats',[sm,busy])){
  const pct=n=>(sm.total?(n/sm.total*100):0)+'%';
  $('astats').replaceChildren(
   h('div',{class:'big '+(sm.failed?'bad':sm.run&&sm.blocked===sm.total?'ok':''),text:sm.blocked+'/'+sm.total},h('small',{text:'attacks blocked'})),
   h('div',{class:'counts'},h('span',{},h('b',{text:sm.blocked}),' blocked'),h('span',{},h('b',{text:sm.failed}),' not blocked'),h('span',{},h('b',{text:sm.errors}),' errors'),h('span',{},h('b',{text:sm.total-sm.run}),' not run')),
   h('div',{class:'meter',role:'img','aria-label':sm.blocked+' blocked, '+sm.failed+' not blocked, '+sm.errors+' errors, '+(sm.total-sm.run)+' not run'},h('i',{class:'m-ok',style:'width:'+pct(sm.blocked)}),h('i',{class:'m-bad',style:'width:'+pct(sm.failed)}),h('i',{class:'m-err',style:'width:'+pct(sm.errors)})));
 }
 const stat=cat.map(c=>attackStatus(c));
 const list=cat.filter((c,i)=>(!f||stat[i]===f)&&(!q||[c.name,pretty(c.name),c.description,c.mechanism,c.property].join(' ').toLowerCase().includes(q)));
 const key=[list.map(c=>[c.name,attackStatus(c),A.results[c.name]]),busy,q,f];
 $('b-att').disabled=busy;$('b-attreset').disabled=busy||!Object.keys(A.results).length;
 if(same('alist',key))return;
 const rows=list.map(c=>{
  const st=attackStatus(c),a=AST[st],r=A.results[c.name],open=SA.openD.has(c.name);
  const badge=h('span',{class:'badge '+a.cls},st==='running'?spinner():icon(a.icon),a.label);
  const det=h('details',{class:'d'},h('summary',{},icon('chev'),'Technical result details'));
  if(open)det.open=true;det.addEventListener('toggle',()=>{det.open?SA.openD.add(c.name):SA.openD.delete(c.name);});
  if(r){
   const kv=h('dl',{class:'kv'},h('dt',{text:'Returned detail'}),h('dd',{text:r.detail}),h('dt',{text:'Finished'}),h('dd',{text:r.finished}));
   if(r.seconds!=null)kv.append(h('dt',{text:'Duration'}),h('dd',{text:r.seconds+' s'}));
   kv.append(h('dt',{text:'Command'}),h('dd',{},h('code',{text:'securepay attack '+c.name})));
   det.append(kv,h('pre',{text:r.output||''}));
  }else det.append(h('p',{class:'hint',text:'No result yet. Press \\u201cRun This Attack\\u201d to execute only this case.'}));
  return h('article',{class:'arow s-'+st,id:'atk-'+c.name},
   h('div',{class:'ahead'},
    h('div',{},h('div',{class:'aname'},h('b',{text:pretty(c.name)}),h('code',{text:c.name})),h('div',{class:'adesc',text:c.description}),
     h('div',{class:'amech'},icon('lock'),h('span',{},'Tests: ',c.mechanism),h('span',{class:'tag',text:c.property}))),
    badge,
    h('div',{class:'act'},h('button',{class:'btn sec sm',type:'button',disabled:busy,'aria-label':'Run This Attack: '+pretty(c.name),onclick:()=>runOne(c.name)},st==='running'?spinner():icon('play'),'Run This Attack'))),det);
 });
 $('alist').replaceChildren(...(rows.length?rows:[h('div',{class:'empty'},icon('search'),'No attacks match your search or filter.')]));
}
async function runOne(name){
 if(anyAttackBusy())return;SA.attackLocal=name;renderAttacks();
 try{
  const r=await api('attack',{name});
  if(r.error){toast(r.error,'bad');}
  else{SA.openD.add(name);toast(pretty(name)+': '+AST[r.status].label,r.status==='blocked'?'ok':r.status==='error'?'warn':'bad');}
 }catch(e){toast('Could not reach the dashboard: '+e,'bad');}
 finally{SA.attackLocal=null;await refresh();}
}
async function runAll(){
 if(anyAttackBusy())return;SA.attackLocal='*';renderAttacks();
 try{
  const r=await api('attacks',{});
  if(r.error)toast(r.error,'bad');else toast(r.summary||'Attack suite finished',r.ok?'ok':'bad');
 }catch(e){toast('Could not reach the dashboard: '+e,'bad');}
 finally{SA.attackLocal=null;await refresh();}
}
function render(){renderAttacks();}

const focus=new URLSearchParams(location.search).get('focus');
if(focus){$('att-q').value=focus;}
$('b-att').onclick=runAll;
$('b-attreset').onclick=async()=>{
 if(!await confirmDlg('Reset displayed attack results?','This only clears the results shown in this dashboard. The network, keys and security configuration are not changed, and attacks can be run again at any time.','Reset display'))return;
 const r=await api('attacks-reset',{});if(r.error)toast(r.error,'bad');else{SA.openD.clear();toast('Displayed attack results cleared','ok');}await refresh();
};
$('att-q').addEventListener('input',()=>S.st&&renderAttacks());$('att-f').addEventListener('change',()=>S.st&&renderAttacks());
refresh();setInterval(refresh,2000);
</script>"""
    return _head("SecurePay · Attack simulator", "attacks") + _chrome("/attacks", body)


def _page_audit() -> str:
    body = """<main>
 <section class="card" id="verify">
  <div class="sec-h"><h2><svg class="i"><use href="#i-link"/></svg>Audit log &amp; receipt verification</h2>
   <p>Both checks run offline against the switch's public Ed25519 key. Nothing is trusted from the switch's say-so. Top-ups made on the Accounts page appear here as <code>TOPUP</code> events in the signed chain.</p></div>
  <div class="grid2">
   <div class="vbox"><h3><svg class="i"><use href="#i-link"/></svg>Signed audit chain</h3>
    <p class="d">Recomputes every SHA-256 link and checks every switch signature in the audit log (settlements, student declines, rejections, top-ups and enrolments).</p>
    <div><button class="btn" id="b-aud"><svg class="i"><use href="#i-shield"/></svg>Verify audit log</button></div>
    <div class="vres" id="r-aud" role="status"></div></div>
   <div class="vbox"><h3><svg class="i"><use href="#i-receipt"/></svg>Signed receipt</h3>
    <p class="d">Pick a saved receipt and verify the switch signature (and ledger entry) offline.</p>
    <select id="rcpt" aria-label="Receipt"></select>
    <div><button class="btn" id="b-rcpt"><svg class="i"><use href="#i-cert"/></svg>Verify receipt</button></div>
    <div class="vres" id="r-rcpt" role="status"></div></div>
  </div>
 </section>
 <section class="card" id="outcomes">
  <div class="sec-h"><h2><svg class="i"><use href="#i-swap"/></svg>Payment outcomes log</h2>
   <p>Every settled payment, every payment the student declined (signed by the student's key, event <code>payment_declined</code>) and every switch-side rejection, newest first. The log is read from the same signed chain and the chain is re-verified on each load.</p></div>
  <div class="row"><button class="btn sec sm" id="b-log" type="button"><svg class="i"><use href="#i-link"/></svg>Refresh log</button></div>
  <div id="r-log" role="status" aria-live="polite" style="margin-top:12px"></div>
 </section>
</main>
<script>
"use strict";
const SV={vAud:null,vRcpt:null,log:null};
const money=m=>(m/100).toFixed(2);
function fill(sel,items,emptyText){const v=sel.value;sel.replaceChildren(...(items.length?items:[['',emptyText]]).map(([val,txt])=>new Option(txt,val)));if(v&&items.some(i=>i[0]===v))sel.value=v;}
function renderForms(){
 const s=S.st,info=s.receipt_info||[];
 if(!same('rc',info))fill($('rcpt'),info.map(r=>[r.txn,r.txn+(r.payer?' \\u00b7 '+r.payer+' \\u2192 '+r.merchant:'')+(r.amount_minor!=null?' \\u00b7 '+money(r.amount_minor)+' AED':'')]),'No receipts yet');
 $('b-rcpt').disabled=!info.length||S.busy.has('rcpt');
 $('b-aud').disabled=!s.provisioned||S.busy.has('aud');
}
function renderVres(id,v){
 const box=$(id);if(!v){box.className='vres';box.replaceChildren();return;}
 if(same(id,v))return;
 const kids=[h('div',{class:'t'},icon(v.ok?'check':'x'),v.title)];
 if(v.txn)kids.push(h('div',{class:'txn',style:'margin-top:8px'},h('code',{text:v.txn}),h('button',{class:'btn sec sm',type:'button','aria-label':'Copy transaction ID',onclick:()=>copy(v.txn,'Transaction ID')},icon('copy'),'Copy')));
 if(v.lines&&v.lines.length){const kv=h('dl',{class:'kv'});for(const[k,val]of v.lines)kv.append(h('dt',{text:k}),h('dd',{text:val}));kids.push(kv);}
 if(v.msg)kids.push(h('div',{style:'margin-top:8px;font-size:13.5px',text:v.msg}));
 if(v.raw)kids.push(h('details',{class:'d'},h('summary',{},icon('chev'),'Technical verification details'),h('pre',{text:v.raw})));
 box.className='vres show '+(v.ok?'ok':'bad');box.replaceChildren(...kids);
}
function parseAudit(r){
 const out=r.output||'',m=out.match(/audit log: (\\d+) entries/),ok=r.ok&&/chain integrity: OK/.test(out);
 return{ok,title:ok?'Audit chain verified':'Audit verification FAILED',lines:m?[['Entries checked',m[1]]]:[],msg:ok?'Hash chain and every switch signature check out.':out.split('\\n').filter(l=>l.startsWith('  -')).join('\\n')||'See technical details.',raw:out};
}
function parseReceipt(r,txn){
 const out=r.output||'',ok=r.ok&&/VERIFIED/.test(out.split('\\n')[0]||''),lines=[];
 for(const l of out.split('\\n').slice(2)){const m=l.match(/^\\s+([a-z_ ]+?)\\s*:\\s*(.*)$/);if(m)lines.push([m[1].trim(),m[2]]);}
 return{ok,title:ok?'Receipt VERIFIED':'Receipt INVALID',txn,lines,msg:(out.split('\\n')[1]||'').trim(),raw:out};
}
const OUT_NAMES={SETTLED:'Settled',DECLINED_BY_STUDENT:'Declined by student',REJECTED:'Rejected by switch',ENROLLED:'Enrolled'};
function renderLog(){
 const box=$('r-log'),r=SV.log;
 if(!r||same('log',r))return;
 if(r.error){box.replaceChildren(h('div',{class:'hint',text:r.error}));return;}
 const rows=r.entries||[];
 if(!rows.length){box.replaceChildren(h('div',{class:'hint',text:'No payment outcomes recorded yet.'}));return;}
 const pill=e=>h('span',{class:'pill '+((e.outcome==='SETTLED'||e.outcome==='ENROLLED')?'ok':e.outcome==='DECLINED_BY_STUDENT'?'warn':'bad'),text:OUT_NAMES[e.outcome]||e.outcome});
 const tr=e=>h('tr',{},h('td',{text:(e.time||'').replace('T',' ').replace('Z','')}),h('td',{},pill(e)),h('td',{text:e.payer}),h('td',{text:e.merchant}),h('td',{text:e.amount+' AED'}),h('td',{text:e.reason==='-'?'':e.reason}),h('td',{},h('code',{text:e.txn})));
 const head=['Time (UTC)','Outcome','Student','Merchant','Amount','Reason','Transaction'].map(t=>h('th',{text:t}));
 const kids=[h('div',{style:'overflow-x:auto'},h('table',{},h('thead',{},h('tr',{},head)),h('tbody',{},rows.map(tr))))];
 if(!r.ok)kids.unshift(h('div',{class:'note bad',text:'Audit chain verification FAILED: treat this listing as untrusted.'}));
 box.replaceChildren(...kids);
}
async function loadLog(){const r=await api('audit-log',{});SV.log=r;renderLog();}
function render(){renderForms();renderVres('r-aud',SV.vAud);renderVres('r-rcpt',SV.vRcpt);renderLog();}
$('b-aud').onclick=e=>guarded('aud',e.currentTarget,async()=>{const r=await api('audit',{});SV.vAud=r.error?{ok:false,title:'Audit verification could not run',msg:r.error}:parseAudit(r);renderVres('r-aud',null);renderVres('r-aud',SV.vAud);toast(SV.vAud.title,SV.vAud.ok?'ok':'bad');});
$('b-rcpt').onclick=e=>{const txn=$('rcpt').value;if(!txn)return;return guarded('rcpt',e.currentTarget,async()=>{const r=await api('verify-receipt',{txn});SV.vRcpt=r.error?{ok:false,title:'Receipt verification could not run',txn,msg:r.error}:parseReceipt(r,txn);renderVres('r-rcpt',null);renderVres('r-rcpt',SV.vRcpt);toast(SV.vRcpt.title,SV.vRcpt.ok?'ok':'bad');});};

$('b-log').onclick=e=>guarded('log',e.currentTarget,loadLog);
loadLog();
const want=new URLSearchParams(location.search).get('receipt');
if(want){const once=()=>{if([...$('rcpt').options].some(o=>o.value===want)){$('rcpt').value=want;$('b-rcpt').click();}else setTimeout(once,700);};setTimeout(once,300);}
refresh();setInterval(refresh,2000);
</script>"""
    return _head("SecurePay · Audit &amp; receipts", "audit") + _chrome("/audit", body)


def _page_security() -> str:
    body = """<main>
 <section class="card" id="security">
  <div class="sec-h"><h2><svg class="i"><use href="#i-lock"/></svg>Security architecture</h2>
   <p>The mechanisms below are implemented in this repository (module names shown) and exercised by the attack simulator. Click a test name to see that attack on the Attack simulator page.</p></div>
  <div class="warnbar"><svg class="i"><use href="#i-info"/></svg><div>This is a <b>custom protocol (SP1)</b> built on libsodium and X.509. It is <b>not TLS</b>: it borrows design ideas such as ephemeral key exchange, transcript signatures and a Finished MAC, but it is its own handshake and record layer.</div></div>
  <div class="grid3" id="feat"></div>
  <div class="libs">
   <div class="lib"><b>PyNaCl (libsodium)</b>ChaCha20-Poly1305 AEAD (record layer, vaults), X25519 key agreement, Argon2id, Ed25519 signatures for payments, receipts and audit entries.</div>
   <div class="lib"><b>cryptography</b>X.509 certificate parsing and issuing, certificate revocation list, and the HKDF-Expand step of the key schedule. SHA-256 comes from the Python standard library and <code>cryptography</code>.</div>
  </div>
 </section>
</main>
<script>
"use strict";
const FEATURES=[
 {id:'confidentiality',icon:'lock',title:'Confidentiality',prop:'Nobody on the wire can read payments',items:[
  [tip('Authenticated Encryption with Associated Data: encrypts and authenticates in one operation.','ChaCha20-Poly1305 AEAD'),' (IETF, 12-byte nonce, 16-byte tag) protects every application frame'],
  ['Implemented with PyNaCl / libsodium bindings; no hand-rolled primitives'],
  ['Payment requests, authorisations and receipts only ever travel inside encrypted frames'],
  ['The same AEAD also encrypts key vaults at rest']],src:'channel.py · keystore.py',test:['bit-flip','mitm-modify-amount']},
 {id:'integrity',icon:'shield',title:'Integrity',prop:'Tampering, replay and reordering are detected',items:[
  ['Poly1305 tag authenticates the ciphertext and the ',tip('Additional Authenticated Data: the frame header (direction, epoch, counter, session id, timestamp) is authenticated but not encrypted.','AAD header')],
  ['Strict ',tip('Each direction has a counter that must match exactly; the counter is part of the nonce, so a duplicate or out-of-order frame is rejected.','monotonic message counter'),': replays and reordering are rejected'],
  ['Timestamp freshness window of 30 s rejects stale frames'],
  ['Length-prefixed framing with a size cap; malformed frames close the connection']],src:'channel.py · framing.py',test:['aad-tamper','replay-same-session','reorder','stale-frame','malformed-frame','double-spend']},
 {id:'authentication',icon:'cert',title:'Authentication',prop:'Both ends prove who they are',items:[
  ['Mutual ',tip('Standard certificate format. Here every switch, merchant and student holds a certificate with an Ed25519 key.','X.509'),' certificates, issued by a private campus CA'],
  [tip('Edwards-curve signature scheme: small keys, deterministic signatures.','Ed25519'),' signs the handshake transcript (certificate_verify)'],
  ['Chain, validity window, CA constraint and key type are checked; the registry pins subject, role and public key'],
  [tip('Certificate Revocation List, signed by the CA. This system re-reads it from disk on every handshake, so revocation applies immediately.','CRL'),' is checked on every handshake, so revocation needs no restart']],src:'pki.py · handshake.py',test:['impersonate-switch','revoked-certificate','expired-certificate']},
 {id:'keyexchange',icon:'swap',title:'Key exchange & forward secrecy',prop:'Fresh keys for every session',items:[
  ['Ephemeral ',tip('Elliptic-curve Diffie-Hellman on Curve25519. Both sides generate a fresh key pair per session and discard it afterwards.','X25519'),' key agreement per handshake'],
  [tip('HMAC-based key derivation function with SHA-256. Turns the shared secret and transcript hash into separate directional keys.','HKDF-SHA256'),' derives directional keys, nonce prefixes and session id'],
  ['Version and cipher suite are inside the signed transcript (downgrade protection); a Finished MAC confirms both sides derived the same keys'],
  ['Automatic rekey inside the encrypted channel after 1000 messages or 300 s, using fresh X25519 keys']],src:'handshake.py · channel.py',test:['mitm-key-substitution','downgrade']},
 {id:'nonrepudiation',icon:'pen',title:'Non-repudiation',prop:'Every party signs what it did',items:[
  ['Merchant signs the payment request; student signs the authorisation; switch signs the receipt'],
  ['Signatures cover domain-tagged canonical JSON plus the session id (channel binding)'],
  ['Persistent txn_id and per-payer nonce stop captured artefacts being reused'],
  ['Audit log is SHA-256 hash-chained and every entry is signed by the switch']],src:'protocol.py · ledger.py · audit.py',test:['replay-new-session','double-spend']},
 {id:'keystorage',icon:'vault',title:'Secure key storage',prop:'Stolen files stay useless',items:[
  [tip('Memory-hard password hashing function (3 iterations, 64 MiB here). Makes every passphrase guess expensive.','Argon2id'),' derives the vault key from the passphrase'],
  ['Vaults are ChaCha20-Poly1305 encrypted; KDF parameters and owner id are authenticated'],
  ['Persistent lockout after repeated wrong passphrases, even for the correct one while locked']],src:'keystore.py · ratelimit.py',test:['vault-bruteforce']}
];
const AST={blocked:{label:'BLOCKED \\u2013 PASS',icon:'check'},not_blocked:{label:'NOT BLOCKED \\u2013 FAIL',icon:'x'},error:{label:'Execution Error',icon:'alert'},running:{label:'Running',icon:'alert'}};
function renderFeatures(){
 const A=S.st.attacks,res=A.results,names=new Set(A.catalogue.map(c=>c.name));
 const key=FEATURES.map(f=>f.test.map(t=>res[t]&&res[t].status));
 if(same('feat',key))return;
 $('feat').replaceChildren(...FEATURES.map(f=>{
  const tests=f.test.filter(t=>names.has(t));
  return h('div',{class:'sc',id:'feat-'+f.id},
   h('div',{class:'h'},h('div',{class:'ic'},icon(f.icon)),h('div',{},h('h3',{text:f.title}),h('div',{class:'p',text:f.prop}))),
   h('ul',{},f.items.map(it=>h('li',{},...it))),
   h('div',{class:'src'},'Source: ',h('code',{text:f.src})),
   h('div',{class:'tested'},h('small',{text:'Tested by attack simulator'}),h('div',{class:'tchips'},tests.map(t=>{const r=res[t],cls=r?(r.status==='blocked'?'ok':r.status==='not_blocked'?'bad':'warn'):'';
    return h('button',{class:'tchip '+cls,type:'button',title:r?AST[r.status].label:'Not run yet',onclick:()=>{location.href='/attacks?focus='+encodeURIComponent(t);}},r?icon(r.status==='blocked'?'check':r.status==='not_blocked'?'x':'alert'):null,t);}))));
 }));
}
function render(){renderFeatures();}
refresh();setInterval(refresh,2000);
</script>"""
    return _head("SecurePay · Security architecture", "security") + _chrome("/security", body)


def _page_log() -> str:
    body = """<main>
 <section class="card" id="log">
  <div class="sec-h"><h2><svg class="i"><use href="#i-term"/></svg>Live switch log</h2><p>Output of the switch and wallet processes started by this dashboard. The page fetches only new lines (via /api/log) every second; scrolling up pauses the follow.</p>
   <div class="grow"><div class="fchips" id="lf" role="group" aria-label="Log level filter"></div><button class="btn sec sm" id="b-logclear">Clear display</button></div></div>
  <div class="logbox" id="logbox" tabindex="0" aria-label="Switch log"></div>
 </section>
</main>
<script>
"use strict";
const SL={logLevel:'ALL',logClearedAt:0,logPin:true,logPos:0,logLines:[]};
const LV=['ALL','INFO','WARNING','ERROR'];
function parseLog(line){const m=line.match(/^(\\d\\d:\\d\\d:\\d\\d) (INFO|WARNING|ERROR|DEBUG)\\s+(.*)$/);return m?{t:m[1],lv:m[2],m:m[3]}:{t:'',lv:/error|traceback|failed/i.test(line)?'ERROR':'INFO',m:line};}
async function pollLog(){
 let j;try{j=await api('log?after='+SL.logPos);}catch(e){return;}
 if(j.error)return;
 const total=j.total;
 if(j.dropped){SL.logLines=j.lines;}
 else if(j.lines.length){SL.logLines=SL.logLines.concat(j.lines);}
 SL.logPos=total;
 renderLog();
}
function renderLog(){
 const lines=SL.logLines.map((l,i)=>({i:i,lv:parseLog(l).lv,p:parseLog(l)}))
  .filter(l=>l.i>=SL.logClearedAt&&(SL.logLevel==='ALL'||l.lv===SL.logLevel||(SL.logLevel==='INFO'&&l.lv==='DEBUG')));
 if(!same('lf',[SL.logLevel]))$('lf').replaceChildren(...LV.map(v=>h('button',{class:'fchip',type:'button','aria-pressed':String(SL.logLevel===v),onclick:()=>{SL.logLevel=v;renderLog();}},v==='ALL'?'All':v[0]+v.slice(1).toLowerCase())));
 if(same('log',[lines.map(l=>l.i),SL.logLevel]))return;
 const box=$('logbox');
 box.replaceChildren(...(lines.length?lines.map(l=>h('div',{class:'ll '+l.lv},h('span',{class:'t',text:l.p.t||'\\u2014'}),h('span',{class:'lv',text:l.lv}),h('span',{class:'m',text:l.p.m}))):[h('div',{class:'empty'},icon('term'),SL.logLines.length?'Nothing to show for this filter.':'No output yet. Start the switch (Overview page) to see its log.')]));
 if(SL.logPin)box.scrollTop=box.scrollHeight;
}
$('logbox').addEventListener('scroll',e=>{const b=e.target;SL.logPin=b.scrollHeight-b.scrollTop-b.clientHeight<24;});
$('b-logclear').onclick=()=>{SL.logClearedAt=SL.logLines.length;renderLog();};
pollLog();setInterval(pollLog,1000);
refresh();
</script>"""
    return _head("SecurePay · Live log", "log") + _chrome("/log", body)


_ASSETS: dict[str, _Asset] = {
    "/assets/app.css": _Asset(_CSS, "text/css; charset=utf-8"),
    "/assets/app.js": _Asset(_SHARED_JS, "text/javascript; charset=utf-8"),
}

_PAGES: dict[str, str] = {
    "/": _page_home(),
    "/payment": _page_payment(),
    "/accounts": _page_accounts(),
    "/attacks": _page_attacks(),
    "/audit": _page_audit(),
    "/security": _page_security(),
    "/log": _page_log(),
}
