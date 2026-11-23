from __future__ import annotations

import http.client
import json
import os
import re
import socket
import subprocess
import sys
import threading
from collections import deque
from collections.abc import Iterator
from pathlib import Path

import pytest

from securepay import gui
from securepay.attacks.simulator import CASES
from securepay.gui import (
    _ASSETS,
    _ATTACK_META,
    _PAGES,
    _UNSERIALISED,
    Controller,
    GuiError,
    _bind,
    _Proc,
    _Server,
    selftest,
)

_PAGE_PATHS = ["/", "/payment", "/accounts", "/attacks", "/audit", "/security", "/log"]


def _fake_registry(controller: Controller) -> None:
    controller.paths.registry.parent.mkdir(parents=True, exist_ok=True)
    controller.paths.registry.write_text(
        json.dumps(
            {
                "entities": [
                    {"id": "902101", "role": "student", "name": "Student"},
                    {"id": "coffee_shop", "role": "merchant", "name": "Coffee"},
                ]
            }
        ),
        encoding="utf-8",
    )


@pytest.fixture
def controller(tmp_path: Path) -> Iterator[Controller]:
    ctl = Controller(tmp_path / "network")
    yield ctl
    ctl.close()


def test_state_before_provisioning(controller: Controller) -> None:
    state = controller.state()
    assert state["provisioned"] is False
    assert state["switch_running"] is False
    assert state["entities"] == []


def test_start_switch_requires_provisioning(controller: Controller) -> None:
    with pytest.raises(GuiError, match="provision"):
        controller.start_switch()


def test_charge_rejects_unknown_and_malicious_identifiers(controller: Controller) -> None:
    _fake_registry(controller)
    with pytest.raises(GuiError, match="invalid identifier"):
        controller.charge("../etc/passwd", "coffee_shop", "1.00", True)
    with pytest.raises(GuiError, match="unknown student"):
        controller.charge("999999", "coffee_shop", "1.00", True)
    with pytest.raises(GuiError, match="unknown merchant"):
        controller.charge("902101", "no_such_shop", "1.00", True)


@pytest.mark.parametrize("amount", ["", "abc", "1;rm -rf /", "-5", "1.234", "12345678", "1e3"])
def test_charge_rejects_bad_amounts(controller: Controller, amount: str) -> None:
    _fake_registry(controller)
    with pytest.raises(GuiError, match="amount"):
        controller.charge("902101", "coffee_shop", amount, True)


def test_charge_requires_running_switch(controller: Controller) -> None:
    _fake_registry(controller)
    with pytest.raises(GuiError, match="start the switch"):
        controller.charge("902101", "coffee_shop", "1.00", True)


@pytest.mark.parametrize("txn", ["", "../../etc/passwd", "TXN-1/../x", "txn-1", "TXN-" + "a" * 70])
def test_verify_receipt_rejects_bad_ids(controller: Controller, txn: str) -> None:
    with pytest.raises(GuiError):
        controller.verify_receipt(txn)


def test_verify_receipt_unknown(controller: Controller) -> None:
    with pytest.raises(GuiError, match="no such receipt"):
        controller.verify_receipt("TXN-123-ABC")


def test_enrol_requires_a_provisioned_network(controller: Controller) -> None:
    with pytest.raises(GuiError, match="provision"):
        controller.enrol_student("902201", "New Student", "100.00")


@pytest.mark.parametrize("bad_id", ["", "../etc/passwd", "902 101", "x" * 33, "café"])
def test_enrol_rejects_bad_ids(controller: Controller, bad_id: str) -> None:
    _fake_registry(controller)
    with pytest.raises(GuiError, match=r"identifier|ID"):
        controller.enrol_student(bad_id, "New Student", "100.00")


def test_enrol_rejects_duplicate_ids(controller: Controller) -> None:
    _fake_registry(controller)
    for existing in ("902101", "coffee_shop"):
        with pytest.raises(GuiError, match="already in the registry"):
            controller.enrol_student(existing, "Copy Cat", "10.00")


@pytest.mark.parametrize(
    ("name", "which"),
    [
        ("", "name"),
        ("   ", "name"),
        ("x" * 65, "name"),
        ("line\nbreak", "name"),
        ("902101", "ok-name"),
    ],
)
def test_enrol_validates_names(controller: Controller, name: str, which: str) -> None:
    _fake_registry(controller)
    if which == "ok-name":
        with pytest.raises(GuiError, match=r"ca.pass"):
            controller.enrol_student("902201", name, "10.00")
    else:
        with pytest.raises(GuiError, match="name"):
            controller.enrol_student("902201", name, "10.00")


@pytest.mark.parametrize("amount", ["", "abc", "0.00", "-5", "1.234", "1e3", "0"])
def test_enrol_rejects_bad_balances(controller: Controller, amount: str) -> None:
    _fake_registry(controller)
    with pytest.raises(GuiError, match="balance"):
        controller.enrol_student("902201", "New Student", amount)


def test_enrol_requires_ca_passphrase_file(controller: Controller) -> None:
    _fake_registry(controller)
    with pytest.raises(GuiError, match=r"ca.pass"):
        controller.enrol_student("902201", "New Student", "100.00")


def test_topup_requires_a_provisioned_network(controller: Controller) -> None:
    with pytest.raises(GuiError, match="provision"):
        controller.topup("902101", "50.00")


def test_topup_rejects_unknown_and_revoked(controller: Controller) -> None:
    _fake_registry(controller)
    with pytest.raises(GuiError, match="unknown account"):
        controller.topup("nobody", "50.00")
    for entity in controller._registry():
        entity["revoked"] = True
    controller.paths.registry.write_text(
        json.dumps(
            {
                "entities": [
                    {"id": "902101", "role": "student", "name": "Student", "revoked": True},
                    {"id": "coffee_shop", "role": "merchant", "name": "Coffee"},
                    {"id": "switch", "role": "switch", "name": "Switch"},
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(GuiError, match="revoked"):
        controller.topup("902101", "50.00")
    with pytest.raises(GuiError, match="student and merchant"):
        controller.topup("switch", "50.00")


@pytest.mark.parametrize("amount", ["", "abc", "0.00", "-5", "1.234", "1e3"])
def test_topup_rejects_bad_amounts(controller: Controller, amount: str) -> None:
    _fake_registry(controller)
    with pytest.raises(GuiError, match="amount"):
        controller.topup("902101", amount)


def test_child_failure_reports_the_real_reason(tmp_path: Path) -> None:
    proc = _Proc(
        ["--network-dir", str(tmp_path / "nothing"), "run-switch", "--passphrase", "x"],
        "SWITCH_READY",
        deque(maxlen=50),
    )
    try:
        with pytest.raises(GuiError, match="No network found"):
            proc.wait_ready("switch", timeout=30)
    finally:
        proc.stop()


@pytest.fixture
def server(tmp_path: Path) -> Iterator[_Server]:
    srv = _Server(Controller(tmp_path / "network"), "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    srv.controller.close()
    thread.join(timeout=5)


def _request(
    srv: _Server,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    port = srv.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def _page_token(srv: _Server, path: str = "/") -> str:
    status, _, body = _request(srv, "GET", path)
    assert status == 200
    match = re.search(rb'name="tok" content="([^"]+)"', body)
    assert match
    return match.group(1).decode()


def test_server_binds_loopback_only(server: _Server) -> None:
    assert server.server_address[0] == "127.0.0.1"


def test_every_page_is_served_with_security_headers(server: _Server) -> None:
    for path in _PAGE_PATHS:
        status, headers, body = _request(server, "GET", path)
        assert status == 200, path
        assert b"SecurePay" in body, path
        lowered = {k.lower(): v for k, v in headers.items()}
        assert lowered["x-content-type-options"] == "nosniff", path
        assert "default-src 'self'" in lowered["content-security-policy"], path
        assert lowered["cache-control"] == "no-store", path


def test_every_page_has_its_own_token_and_highlights_itself(server: _Server) -> None:
    token = _page_token(server)
    for path in _PAGE_PATHS:
        status, _, body = _request(server, "GET", path)
        text = body.decode()
        page_token = re.search(r'name="tok" content="([^"]+)"', text)
        assert status == 200 and page_token, path
        assert page_token.group(1) == token, f"{path} carries the same per-run token"
        assert 'aria-current="page"' in text, f"{path} highlights itself in the nav"
        for href in _PAGE_PATHS:
            assert f'href="{href}"' in text, f"{path} nav missing {href}"
        assert 'src="/assets/app.js"' in text and 'href="/assets/app.css"' in text, path


def test_assets_are_served_from_the_fixed_set_only(server: _Server) -> None:
    for path in ("/assets/app.css", "/assets/app.js"):
        status, headers, body = _request(server, "GET", path)
        assert status == 200 and len(body) > 1000, path
        lowered = {k.lower(): v for k, v in headers.items()}
        assert "default-src 'self'" in lowered["content-security-policy"]
    for path in (
        "/assets/../gui.py",
        "/assets/../../etc/passwd",
        "/assets/nope.js",
        "/assets/app.css/../../../etc/passwd",
    ):
        status, _, _ = _request(server, "GET", path)
        assert status == 404, path


def test_unknown_paths_are_refused(server: _Server) -> None:
    status, _, _ = _request(server, "GET", "/no-such-page")
    assert status == 404
    status, _, _ = _request(server, "GET", "/api/unknown")
    assert status == 403


def test_api_requires_token(server: _Server) -> None:
    status, _, _ = _request(server, "GET", "/api/state")
    assert status == 403
    status, _, _ = _request(server, "GET", "/api/state", headers={"X-Token": "wrong"})
    assert status == 403
    status, _, _ = _request(server, "GET", "/api/log?after=0")
    assert status == 403
    status, _, _ = _request(server, "GET", "/api/log?after=0", headers={"X-Token": "wrong"})
    assert status == 403
    status, _, _ = _request(server, "POST", "/api/audit", headers={"X-Token": "wrong"}, body=b"{}")
    assert status == 403


def test_api_accepts_valid_token(server: _Server) -> None:
    token = _page_token(server)
    status, _, body = _request(server, "GET", "/api/state", headers={"X-Token": token})
    assert status == 200
    state = json.loads(body)
    assert state["provisioned"] is False
    assert "log" not in state and "log_total" not in state, "no log tail on every poll"


def test_api_log_serves_incremental_lines(server: _Server) -> None:
    token = _page_token(server)
    headers = {"X-Token": token}
    status, _, body = _request(server, "GET", "/api/log?after=0", headers=headers)
    assert status == 200
    assert json.loads(body) == {"lines": [], "total": 0, "dropped": False}

    server.controller.log.append("19:00:00 INFO securepay.test first")
    server.controller.log.append("19:00:01 INFO securepay.test second")
    _, _, body = _request(server, "GET", "/api/log?after=0", headers=headers)
    data = json.loads(body)
    assert data["lines"] == [
        "19:00:00 INFO securepay.test first",
        "19:00:01 INFO securepay.test second",
    ]
    assert data["total"] == 2 and data["dropped"] is False

    _, _, body = _request(server, "GET", "/api/log?after=1", headers=headers)
    data = json.loads(body)
    assert data["lines"] == ["19:00:01 INFO securepay.test second"]
    assert data["total"] == 2

    _, _, body = _request(server, "GET", "/api/log?after=-7", headers=headers)
    assert len(json.loads(body)["lines"]) == 2
    _, _, body = _request(server, "GET", "/api/log", headers=headers)
    assert len(json.loads(body)["lines"]) == 2


def test_api_log_validates_the_after_parameter(server: _Server) -> None:
    token = _page_token(server)
    headers = {"X-Token": token}
    status, _, body = _request(server, "GET", "/api/log?after=abc", headers=headers)
    assert status == 400
    assert "integer" in json.loads(body)["error"]
    status, _, body = _request(server, "GET", "/api/log?after=1.5", headers=headers)
    assert status == 400


def test_api_log_reports_dropped_positions(server: _Server) -> None:
    token = _page_token(server)
    headers = {"X-Token": token}
    for i in range(3050):
        server.controller.log.append(f"line {i}")
    _, _, body = _request(server, "GET", "/api/log?after=1", headers=headers)
    data = json.loads(body)
    assert data["dropped"] is True
    assert len(data["lines"]) == 3000
    assert data["total"] == 3050
    _, _, body = _request(server, "GET", "/api/log?after=" + str(data["total"]), headers=headers)
    data = json.loads(body)
    assert data["lines"] == [] and data["dropped"] is False


def test_foreign_host_header_is_rejected(server: _Server) -> None:
    token = _page_token(server)
    status, _, _ = _request(server, "GET", "/", headers={"Host": "evil.example"})
    assert status == 403
    status, _, _ = _request(
        server, "GET", "/api/state", headers={"Host": "evil.example", "X-Token": token}
    )
    assert status == 403
    status, _, _ = _request(server, "GET", "/assets/app.css", headers={"Host": "evil.example"})
    assert status == 403


def test_foreign_host_gets_a_helpful_message(server: _Server) -> None:
    status, _, body = _request(server, "GET", "/", headers={"Host": "10.0.0.5:8765"})
    assert status == 403
    assert b"http://127.0.0.1:" in body


def test_unknown_route_and_bad_bodies(server: _Server) -> None:
    token = _page_token(server)
    headers = {"X-Token": token, "Content-Type": "application/json"}
    status, _, _ = _request(server, "POST", "/api/not-a-route", headers=headers, body=b"{}")
    assert status == 404
    status, _, _ = _request(server, "POST", "/api/audit", headers=headers, body=b"{broken")
    assert status == 400
    status, _, _ = _request(server, "POST", "/api/audit", headers=headers, body=b"[1, 2]")
    assert status == 400
    status, _, body = _request(
        server, "POST", "/api/charge", headers=headers, body=b'{"payer": "../x"}'
    )
    assert status == 400
    assert "invalid identifier" in json.loads(body)["error"]


def test_new_routes_validate_their_bodies(server: _Server) -> None:
    token = _page_token(server)
    headers = {"X-Token": token, "Content-Type": "application/json"}
    status, _, body = _request(
        server, "POST", "/api/enrol-student", headers=headers, body=b'{"id": "902 101"}'
    )
    assert status == 400
    status, _, body = _request(
        server, "POST", "/api/topup", headers=headers, body=b'{"id": "902101", "amount": "1.234"}'
    )
    assert status == 400
    assert "amount" in json.loads(body)["error"]
    for route in ("enrol-student", "topup"):
        status, _, _ = _request(server, "POST", f"/api/{route}", headers=headers, body=b"{}")
        assert status == 400, route
        status, _, _ = _request(
            server, "POST", f"/api/{route}", headers={"X-Token": "nope"}, body=b"{}"
        )
        assert status == 403, route


def test_enrol_and_topup_are_serialised_with_other_actions(server: _Server) -> None:
    assert "enrol-student" not in _UNSERIALISED
    assert "topup" not in _UNSERIALISED
    token = _page_token(server)
    headers = {"X-Token": token, "Content-Type": "application/json"}
    assert server.action_lock.acquire(blocking=False)
    try:
        result: dict[str, object] = {}

        def call() -> None:
            status, _, _body = _request(
                server, "POST", "/api/topup", headers=headers, body=b'{"id": "x", "amount": "1"}'
            )
            result["status"] = status

        worker = threading.Thread(target=call, daemon=True)
        worker.start()
        worker.join(timeout=1.0)
        assert worker.is_alive(), "topup must wait for the action lock"
    finally:
        server.action_lock.release()
    worker.join(timeout=5)
    assert result.get("status") in (200, 400), result


def test_oversized_body_is_rejected(server: _Server) -> None:
    token = _page_token(server)
    status, _, body = _request(
        server,
        "POST",
        "/api/audit",
        headers={"X-Token": token, "Content-Type": "application/json"},
        body=b"{" + b" " * 10_000 + b"}",
    )
    assert status == 400
    assert "too large" in json.loads(body)["error"]


@pytest.mark.slow
def test_full_flow_through_dashboard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYTHONUNBUFFERED", raising=False)
    ctl = Controller(tmp_path / "network")
    try:
        assert ctl.provision()["ok"] is True
        with pytest.raises(GuiError, match="already provisioned"):
            ctl.provision()

        assert ctl.start_switch()["ok"] is True
        before = {e["id"]: e["balance"] for e in ctl.state()["entities"]}

        approved = ctl.charge("902101", "coffee_shop", "12.50", True)
        assert approved["ok"] is True
        assert approved["status"] == "SETTLED"
        assert approved["txn"]

        declined = ctl.charge("902101", "coffee_shop", "5.00", False)
        assert declined["ok"] is False
        assert declined["status"] == "REJECTED", "the merchant is told at once, no timeout"
        assert "declined_by_payer" in declined["output"]

        state = ctl.state()
        after = {e["id"]: e["balance"] for e in state["entities"]}
        assert after["902101"] != before["902101"], "the approved payment moved money"
        assert approved["txn"] in state["receipts"]
        assert len(state["receipts"]) == 1, "the declined payment left no receipt"

        assert ctl.audit()["ok"] is True
        assert ctl.verify_receipt(approved["txn"])["ok"] is True

        log = ctl.audit_log()
        assert log["ok"] is True, log["output"]
        outcomes = {row["txn"]: row["outcome"] for row in log["entries"]}
        assert outcomes[approved["txn"]] == "SETTLED"
        assert outcomes[declined["txn"]] == "DECLINED_BY_STUDENT"
    finally:
        ctl.close()


@pytest.mark.slow
def test_enrol_topup_and_charge_the_new_student(tmp_path: Path) -> None:
    ctl = Controller(tmp_path / "network")
    try:
        assert ctl.provision()["ok"] is True
        assert ctl.start_switch()["ok"] is True
        old_port = ctl.state()["switch_port"]
        assert old_port is not None

        result = ctl.enrol_student("902201", "Noor Al-Sayed", "120.00")
        assert result["ok"] is True, result["output"]
        assert result["passphrase"], "the VAULT_PASSPHRASE line must be parsed"
        pass_file = ctl.paths.wallets_dir / "902201.pass"
        assert pass_file.exists(), "wallet .pass file created like seed does"
        assert pass_file.read_text(encoding="utf-8").strip() == result["passphrase"]
        assert (pass_file.stat().st_mode & 0o777) == 0o600

        state = ctl.state()
        assert state["switch_running"] is True
        assert state["switch_port"] is not None
        assert state["switch_port"] != old_port, "switch was restarted to reload the registry"

        entities = {e["id"]: e for e in state["entities"]}
        assert "902201" in entities
        assert entities["902201"]["role"] == "student"
        assert entities["902201"]["name"] == "Noor Al-Sayed"
        assert entities["902201"]["balance"] == "120.00 AED"

        charge = ctl.charge("902201", "coffee_shop", "2.50", True)
        assert charge["ok"] is True, charge["output"]
        assert charge["status"] == "SETTLED"
        after = {e["id"]: e["balance"] for e in ctl.state()["entities"]}
        assert after["902201"] == "117.50 AED"

        top = ctl.topup("902201", "30.25")
        assert top["ok"] is True, top["output"]
        assert top["old_balance"] == "11750"
        assert top["new_balance"] == "14775"
        after = {e["id"]: e["balance"] for e in ctl.state()["entities"]}
        assert after["902201"] == "147.75 AED"

        audit = ctl.audit()
        assert audit["ok"] is True, audit["output"]
        assert "TOPUP" in audit["output"] or "chain integrity: OK" in audit["output"]
        import sqlite3

        conn = sqlite3.connect(ctl.paths.ledger)
        try:
            events = [row[0] for row in conn.execute("SELECT event FROM audit_log ORDER BY seq")]
        finally:
            conn.close()
        assert "TOPUP" in events
    finally:
        ctl.close()


@pytest.mark.slow
def test_topup_refusals_leave_the_chain_consistent(tmp_path: Path) -> None:
    ctl = Controller(tmp_path / "network")
    try:
        assert ctl.provision()["ok"] is True
        with pytest.raises(GuiError, match="unknown account"):
            ctl.topup("nobody", "5.00")
        with pytest.raises(GuiError, match="amount"):
            ctl.topup("902101", "0.00")
        with pytest.raises(GuiError, match="amount"):
            ctl.topup("902101", "1.234")
        code, out = ctl._cli(
            "revoke-cert",
            "--id",
            "902102",
            "--ca-passphrase-file",
            str(ctl.paths.root / "ca.pass"),
        )
        assert code == 0, out
        with pytest.raises(GuiError, match="revoked"):
            ctl.topup("902102", "5.00")
        assert ctl.audit()["ok"] is True
    finally:
        ctl.close()


@pytest.mark.slow
def test_ready_marker_reaches_a_buffered_pipe_reader(tmp_path: Path) -> None:
    ctl = Controller(tmp_path / "network")
    assert ctl.provision()["ok"] is True
    env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
    child = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "securepay",
            "--network-dir",
            str(ctl.paths.root),
            "run-switch",
            "--port",
            "0",
            "--passphrase-file",
            str(ctl.paths.switch_dir / "switch.pass"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    try:
        seen: list[str] = []

        def pump() -> None:
            assert child.stdout is not None
            for line in child.stdout:
                seen.append(line)
                if "SWITCH_READY" in line:
                    return

        thread = threading.Thread(target=pump, daemon=True)
        thread.start()
        thread.join(timeout=30)
        assert any("SWITCH_READY" in line for line in seen), "READY marker stuck in buffer"
    finally:
        child.terminate()
        child.wait(timeout=10)


def test_busy_port_falls_back_to_a_free_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    busy = holder.getsockname()[1]
    srv = None
    try:
        srv = _bind(Controller(tmp_path / "network"), busy)
        assert srv.server_address[1] != busy
        assert "still running" in capsys.readouterr().out
    finally:
        if srv is not None:
            srv.server_close()
        holder.close()


def test_browser_launch_never_blocks_the_server(monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()
    monkeypatch.setattr(gui.webbrowser, "open", lambda url: release.wait(timeout=30))
    try:
        started = threading.Event()
        worker = threading.Thread(
            target=lambda: (gui._open_browser("http://127.0.0.1:1/"), started.set())
        )
        worker.start()
        assert started.wait(timeout=5), "_open_browser blocked on a slow browser launcher"
    finally:
        release.set()


def test_selftest_passes_on_a_healthy_install(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert selftest(tmp_path / "network") in (0, 1)
    out = capsys.readouterr().out
    assert "[PASS] dashboard serves pages + API" in out
    assert "[PASS] securepay runs as a child process" in out


def _fake_cli(calls: list[tuple[str, ...]], rows: dict[str, tuple[bool, str]]):

    def fake(*args: str, timeout: float = 60.0, to_log: bool = False) -> tuple[int, str]:
        calls.append(args)
        names = [a for a in args[1:] if not a.startswith("--")] or list(rows)
        lines = [
            f"[{'PASS' if rows[n][0] else 'FAIL'}] {n}  {rows[n][1]}" for n in names if n in rows
        ]
        return 0, "\n".join(lines) + f"\n\n{len(lines)}/{len(lines)} attacks blocked"

    return fake


def test_attack_metadata_covers_exactly_the_simulator_cases() -> None:
    assert set(_ATTACK_META) == set(CASES)
    catalogue = Controller(Path("unused")).attack_catalogue()
    assert [c["name"] for c in catalogue] == list(CASES)
    assert all(c["description"] == CASES[c["name"]][0] for c in catalogue)
    assert len(catalogue) == 15


@pytest.mark.parametrize("name", ["", "nope", "../etc/passwd", "bit-flip; ls", "--all", "BIT-FLIP"])
def test_run_attack_rejects_unknown_names(controller: Controller, name: str) -> None:
    with pytest.raises(GuiError, match="unknown attack"):
        controller.run_attack(name)
    assert controller.attack_state()["results"] == {}


def test_run_attack_runs_only_the_selected_case(
    controller: Controller, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(controller, "_cli", _fake_cli(calls, {"reorder": (True, "blocked")}))
    result = controller.run_attack("reorder")
    assert calls == [("attack", "reorder")]
    assert result["status"] == "blocked"
    assert result["ok"] is True
    assert set(controller.attack_state()["results"]) == {"reorder"}
    assert controller.attack_state()["running"] is None


def test_run_attack_maps_fail_and_harness_error(
    controller: Controller, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = {
        "bit-flip": (False, "tampered frame accepted"),
        "downgrade": (False, "harness error: boom"),
    }
    monkeypatch.setattr(controller, "_cli", _fake_cli([], rows))
    assert controller.run_attack("bit-flip")["status"] == "not_blocked"
    assert controller.run_attack("downgrade")["status"] == "error"


def test_run_attack_without_result_line_is_an_execution_error(
    controller: Controller, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(controller, "_cli", lambda *a, **k: (1, "Traceback: kaboom"))
    result = controller.run_attack("stale-frame")
    assert result["status"] == "error"
    assert "kaboom" in result["detail"]


def test_attack_runs_cannot_overlap(controller: Controller) -> None:
    assert controller._attack_lock.acquire(blocking=False)
    controller._attack_running = "bit-flip"
    try:
        with pytest.raises(GuiError, match="already in progress"):
            controller.run_attack("bit-flip")
        with pytest.raises(GuiError, match="already in progress"):
            controller.attacks()
        with pytest.raises(GuiError, match="in progress"):
            controller.reset_attack_results()
    finally:
        controller._attack_running = None
        controller._attack_lock.release()


def test_run_all_records_every_case_and_reset_only_clears_display(
    controller: Controller, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(controller, "_cli", _fake_cli(calls, {n: (True, f"{n} ok") for n in CASES}))
    out = controller.attacks()
    assert calls == [("attack", "--all")]
    assert len(out["rows"]) == 15
    assert len(controller.attack_state()["results"]) == 15
    controller.paths.registry.parent.mkdir(parents=True, exist_ok=True)
    controller.paths.registry.write_text('{"entities": []}', encoding="utf-8")
    controller.reset_attack_results()
    assert controller.attack_state()["results"] == {}
    assert controller.paths.registry.exists(), "reset must not touch the network"


def test_attack_routes_need_token_and_validate_names(server: _Server) -> None:
    headers = {"Content-Type": "application/json"}
    for route in ("attack", "attacks", "attacks-reset"):
        status, _, _ = _request(server, "POST", f"/api/{route}", headers=headers, body=b"{}")
        assert status == 403
    token = _page_token(server)
    headers["X-Token"] = token
    status, _, body = _request(
        server, "POST", "/api/attack", headers=headers, body=b'{"name": "rm -rf /"}'
    )
    assert status == 400
    assert json.loads(body)["error"] == "unknown attack"
    status, _, _ = _request(server, "POST", "/api/attack", headers=headers, body=b"{}")
    assert status == 400


def test_state_exposes_attack_catalogue_and_no_log_tail(server: _Server) -> None:
    token = _page_token(server)
    _, _, body = _request(server, "GET", "/api/state", headers={"X-Token": token})
    state = json.loads(body)
    assert len(state["attacks"]["catalogue"]) == 15
    assert state["attacks"]["running"] is None
    assert "log" not in state, "the log moved to /api/log (incremental)"


def test_pages_are_offline_and_have_no_unsafe_html_insertion() -> None:
    corpus = "".join(_PAGES.values()) + "".join(a.body for a in _ASSETS.values())
    assert "innerHTML" not in corpus
    assert "outerHTML" not in corpus
    assert "document.write" not in corpus
    urls = re.findall(r"https?://[^\s\"'<>)]+", corpus)
    assert set(urls) <= {"http://www.w3.org/2000/svg"}, "no CDN scripts, fonts or services"
    assert "Run This Attack" in corpus and "BLOCKED &ndash; PASS" in corpus
    assert "Enrol student" in corpus and "Add funds" in corpus
    for path, html in _PAGES.items():
        assert html.count("<html") == 1 and html.count("</html>") == 1, path
        assert "__TOKEN__" in html, f"{path} has its own token injection point"
    assert set(_PAGES) == set(_PAGE_PATHS)


@pytest.mark.slow
def test_real_single_attack_leaves_the_other_fourteen_untouched(controller: Controller) -> None:
    result = controller.run_attack("bit-flip")
    assert result["status"] == "blocked"
    assert "AEAD" in result["detail"]
    assert set(controller.attack_state()["results"]) == {"bit-flip"}


def test_attack_logs_reach_live_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctl = Controller(tmp_path)
    name = "downgrade"
    fake_out = (
        f"12:00:00 INFO    securepay.attacks.simulator event=attack_start name={name}\n"
        "12:00:01 WARNING securepay.switch event=session_failed peer=? addr=127.0.0.1"
        " code=version_mismatch\n"
        f"12:00:02 ERROR   securepay.attacks.simulator event=attack_blocked name={name}"
        " property=Authentication impact=high detail=rejected\n"
        f"[PASS] {name}  rejected\n\n1/1 attacks blocked\n"
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=fake_out, stderr=""),
    )
    ctl.run_attack(name)
    lines = list(ctl.log)
    assert [ln.split()[1] for ln in lines] == ["INFO", "WARNING", "ERROR"]
    assert sum("event=attack_blocked" in ln for ln in lines) == 1


def test_attack_crash_output_is_logged_as_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctl = Controller(tmp_path)
    crash = "Traceback (most recent call last):\nValueError: boom\n"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 1, stdout=crash, stderr=""),
    )
    ctl.run_attack("downgrade")
    assert any("ERROR" in ln and "attack_process_crash" in ln for ln in ctl.log)
