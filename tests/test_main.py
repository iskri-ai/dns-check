import datetime
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from dnscheck import checks, main
from dnscheck.checks import Result, Status
from dnscheck.main import Deps, diff, run
from dnscheck.notify import TelegramError
from dnscheck.state import Entry, StateError

NOW = datetime.datetime(2026, 11, 12, 13, 19, tzinfo=datetime.UTC)
ENV = {
    "TELEGRAM_BOT_TOKEN": "123:secret-token",
    "TELEGRAM_CHAT_ID": "-100500",
    "TELEGRAM_THREAD_ID": "42",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "iskri-ai/dns-check",
    "GITHUB_RUN_ID": "7",
}
RUN = "https://github.com/iskri-ai/dns-check/actions/runs/7"
CONFIG = """\
domain: iskri.io
nameservers: [a.ns.selectel.ru]
expiry:
  rdap_base_url: https://rdap.example/rdap/
  min_days_left: 30
records:
  "@": {TXT: "v=spf1 -all"}
"""
KEYS = ["delegation", "soa", "expiry", "records @ TXT"]


class FakeStore:
    def __init__(self, state: dict[str, Entry] | None = None, fail_read: StateError | None = None, fail_write: bool = False) -> None:
        self.state = dict(state or {})
        self.fail_read = fail_read
        self.fail_write = fail_write
        self.writes: list[dict[str, Entry]] = []
        self.path: Path | None = None

    def read(self) -> dict[str, Entry]:
        if self.fail_read:
            raise self.fail_read
        return dict(self.state)

    def write(self, state: dict[str, Entry]) -> None:
        if self.fail_write:
            raise StateError("cannot write state.json (PermissionError)")
        self.writes.append(state)


class FakeMessenger:
    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.sent: list[str] = []
        self.attempts = 0

    def send(self, text: str) -> None:
        self.attempts += 1
        if self.attempts <= self.failures:
            raise TelegramError("Telegram send failed: HTTP 400")
        self.sent.append(text)


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, passes: list[dict[str, Status]]) -> None:
        self.config = tmp_path / "expected.yaml"
        self.config.write_text(CONFIG)
        self.output = tmp_path / "github_output"
        self.output.write_text("")
        self.state_path = tmp_path / "state.json"
        self.store = FakeStore()
        self.messenger = FakeMessenger()
        self.sleeps: list[float] = []
        self.passes = list(passes)
        self.asked: list[list[str]] = []
        self.commit_age = datetime.timedelta(days=3)
        self.commit_error: Exception | None = None
        current: dict[str, Status] = {}

        def scripted(key: str) -> Result:
            return Result(key, current[key], f"{key} detail")

        def querier() -> object:
            current.clear()
            current.update(self.passes.pop(0))
            self.asked.append([])
            return object()

        def record(key: str) -> Result:
            self.asked[-1].append(key)
            return scripted(key)

        monkeypatch.setattr(checks, "delegation", lambda q, c: record("delegation"))
        monkeypatch.setattr(checks, "soa", lambda q, c: record("soa"))
        monkeypatch.setattr(checks, "expiry", lambda c, now, fetch: record("expiry"))
        monkeypatch.setattr(checks, "records", lambda q, c, sets: [record(r.key) for r in sets])
        self.querier = querier

    def commit_time(self, repo: Path) -> datetime.datetime:
        if self.commit_error:
            raise self.commit_error
        return NOW - self.commit_age

    def open_store(self, path: Path) -> FakeStore:
        self.store.path = path
        return self.store

    def run(self, heartbeat: bool = False, env: dict[str, str] | None = None) -> int:
        deps = Deps(
            querier=self.querier,  # type: ignore[arg-type]
            fetch=lambda url: b"",
            store=self.open_store,
            messenger=lambda token, chat, thread: self.messenger,
            now=lambda: NOW,
            sleep=self.sleeps.append,
            commit_time=self.commit_time,
        )
        env = {**ENV, "GITHUB_OUTPUT": str(self.output), **(env or {})}
        code = run(
            config_path=self.config,
            state_path=self.state_path,
            repo=self.config.parent,
            heartbeat=heartbeat,
            env=env,
            deps=deps,
        )
        assert not self.passes, f"unused scripted passes: {self.passes}"
        return code


def all_(status: Status, **overrides: Status) -> dict[str, Status]:
    statuses = {key: status for key in KEYS}
    for name, value in overrides.items():
        assert name in statuses, f"unknown check {name!r}"
        statuses[name] = value
    return statuses


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    return lambda *passes: Harness(tmp_path, monkeypatch, list(passes))


def test_a_healthy_first_run_records_the_state_silently(harness: Any) -> None:
    h = harness(all_(Status.OK))
    assert h.run() == 0
    assert h.messenger.sent == []
    assert h.store.path == h.state_path
    assert h.store.writes == [{key: Entry(Status.OK, NOW) for key in KEYS}]
    assert h.sleeps == []
    assert h.output.read_text() == ""


def test_an_unchanged_run_sends_nothing_and_writes_nothing(harness: Any) -> None:
    h = harness(all_(Status.OK))
    h.store.state = {key: Entry(Status.OK, NOW - datetime.timedelta(days=1)) for key in KEYS}
    assert h.run() == 0
    assert h.messenger.sent == []
    assert h.store.writes == []


def test_the_recheck_repeats_only_unknown_checks_and_its_result_counts(harness: Any) -> None:
    h = harness(all_(Status.OK, soa=Status.UNKNOWN), {"soa": Status.OK})
    h.store.state = {key: Entry(Status.OK, NOW) for key in KEYS}
    assert h.run() == 0
    assert h.sleeps == [120.0]
    assert h.asked == [KEYS, ["soa"]]
    assert h.messenger.sent == []
    assert h.store.writes == []


def test_a_failure_is_reported_in_the_run_that_found_it(harness: Any) -> None:
    h = harness(all_(Status.OK, soa=Status.FAIL, expiry=Status.UNKNOWN), {"expiry": Status.OK})
    h.store.state = {key: Entry(Status.OK, NOW) for key in KEYS}
    assert h.run() == 0
    assert h.asked == [KEYS, ["expiry"]]
    assert h.messenger.sent == [f"iskri.io: 1 status change\nFAIL soa: soa detail\n{RUN}"]


def test_a_failure_alone_starts_no_recheck(harness: Any) -> None:
    h = harness(all_(Status.OK, soa=Status.FAIL))
    h.store.state = {key: Entry(Status.OK, NOW) for key in KEYS}
    assert h.run() == 0
    assert h.sleeps == []
    assert h.asked == [KEYS]


def test_a_confirmed_failure_sends_one_message_and_saves_the_state(harness: Any) -> None:
    h = harness(all_(Status.OK, soa=Status.FAIL))
    h.store.state = {key: Entry(Status.OK, NOW - datetime.timedelta(days=1)) for key in KEYS}
    assert h.run() == 0
    assert h.messenger.sent == [f"iskri.io: 1 status change\nFAIL soa: soa detail\n{RUN}"]
    assert h.store.writes[-1]["soa"] == Entry(Status.FAIL, NOW)
    assert h.store.writes[-1]["delegation"] == h.store.state["delegation"]
    assert h.output.read_text() == ""


def test_the_job_log_keeps_details_that_telegram_drops(
    harness: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    h = harness(all_(Status.OK, soa=Status.FAIL))
    detail = "x" * 5000 + " UNIQUE-DIAGNOSTIC"
    monkeypatch.setattr(checks, "soa", lambda q, c: Result("soa", Status.FAIL, detail))
    assert h.run() == 0
    assert "UNIQUE-DIAGNOSTIC" not in h.messenger.sent[0]
    assert len(h.messenger.sent[0]) <= 4000
    assert f"FAIL soa: {detail}" in capsys.readouterr().out


def test_a_fault_behind_an_unknown_status_still_sends_a_message(harness: Any) -> None:
    h = harness(all_(Status.OK, soa=Status.FAIL))
    h.store.state = {key: Entry(Status.OK, NOW) for key in KEYS}
    h.store.state["soa"] = Entry(Status.UNKNOWN, NOW - datetime.timedelta(hours=1))
    assert h.run() == 0
    assert h.messenger.sent == [f"iskri.io: 1 status change\nFAIL soa: soa detail\n{RUN}"]


def test_a_recovery_reports_the_duration(harness: Any) -> None:
    h = harness(all_(Status.OK))
    h.store.state = {key: Entry(Status.OK, NOW) for key in KEYS}
    h.store.state["soa"] = Entry(Status.FAIL, NOW - datetime.timedelta(hours=3, minutes=12))
    assert h.run() == 0
    assert h.messenger.sent == [f"iskri.io: 1 status change\nOK soa: recovered after 3h 12m\n{RUN}"]


@pytest.mark.parametrize("env", [{"SCHEDULE": "17 4 * * *"}, {"HEARTBEAT": "true"}])
def test_heartbeat_runs_send_the_summary(harness: Any, env: dict[str, str]) -> None:
    h = harness(all_(Status.OK))
    h.store.state = {key: Entry(Status.OK, NOW) for key in KEYS}
    h.commit_age = datetime.timedelta(days=52)
    assert h.run(env=env) == 0
    text = h.messenger.sent[0]
    assert text.startswith("iskri.io: daily summary\ndelegation ok: delegation detail\n")
    assert "records: 1/1 ok" in text
    assert "no commits on master for 52 days" in text


def test_a_regular_schedule_is_not_a_heartbeat(harness: Any) -> None:
    h = harness(all_(Status.OK))
    h.store.state = {key: Entry(Status.OK, NOW) for key in KEYS}
    assert h.run(env={"SCHEDULE": "7,37 * * * *", "HEARTBEAT": "false"}) == 0
    assert h.messenger.sent == []


def test_an_unreadable_commit_date_is_reported_in_the_heartbeat(harness: Any) -> None:
    h = harness(all_(Status.OK))
    h.commit_error = subprocess.CalledProcessError(128, ["git"])
    assert h.run(heartbeat=True) == 0
    assert "could not read the date of the latest commit on master" in h.messenger.sent[0]


def test_a_failed_send_aborts_without_saving_the_state(harness: Any) -> None:
    h = harness(all_(Status.OK, soa=Status.FAIL))
    h.messenger.failures = 1
    assert h.run() == 1
    assert h.store.writes == []
    assert h.messenger.sent == [f"iskri.io: run aborted: Telegram send failed: HTTP 400\n{RUN}"]
    assert h.output.read_text() == "reported=true\n"


def test_reported_stays_unset_when_the_abort_message_fails_too(harness: Any) -> None:
    h = harness(all_(Status.OK, soa=Status.FAIL))
    h.messenger.failures = 2
    assert h.run() == 1
    assert h.output.read_text() == ""


def test_an_unreadable_state_aborts(harness: Any) -> None:
    h = harness()
    h.store.fail_read = StateError("cannot read state.json (FileNotFoundError)")
    assert h.run() == 1
    assert h.messenger.sent == [f"iskri.io: run aborted: cannot read state.json (FileNotFoundError)\n{RUN}"]
    assert h.output.read_text() == "reported=true\n"


def test_a_failed_state_write_aborts_after_the_message(harness: Any) -> None:
    h = harness(all_(Status.OK, soa=Status.FAIL))
    h.store.fail_write = True
    assert h.run() == 1
    assert h.messenger.sent[0].startswith("iskri.io: 1 status change")
    assert h.messenger.sent[1] == f"iskri.io: run aborted: cannot write state.json (PermissionError)\n{RUN}"


def test_an_invalid_config_aborts(harness: Any) -> None:
    h = harness()
    h.config.write_text(CONFIG.replace("min_days_left: 30", "min_days_left: true"))
    assert h.run() == 1
    assert h.messenger.sent == [
        f"dns-check: run aborted: invalid expected.yaml: expiry.min_days_left: expected a positive integer\n{RUN}"]


def test_an_unexpected_error_aborts_with_our_wording_only(harness: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    h = harness(all_(Status.OK))

    def broken(querier: object, config: object) -> Result:
        raise RuntimeError("123:secret-token")

    monkeypatch.setattr(checks, "soa", broken)
    assert h.run() == 1
    assert h.messenger.sent == [f"iskri.io: run aborted: unexpected error (RuntimeError)\n{RUN}"]


def test_empty_telegram_values_abort_before_anything_else(harness: Any) -> None:
    h = harness()
    assert h.run(env={"TELEGRAM_THREAD_ID": ""}) == 1
    assert h.messenger.attempts == 0


def test_main_passes_the_options_to_run(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    def fake_run(**kwargs: Any) -> int:
        calls.append(kwargs)
        return 1

    monkeypatch.setattr(main, "run", fake_run)
    assert main.main(["--state", "some/state.json"]) == 1
    assert calls == [
        {
            "config_path": Path("expected.yaml"),
            "state_path": Path("some/state.json"),
            "repo": Path.cwd(),
            "heartbeat": False,
            "env": os.environ,
        }
    ]


def test_main_requires_the_state_option() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main.main([])
    assert excinfo.value.code == 2


def test_diff_treats_new_keys_as_previously_ok_and_drops_removed_ones() -> None:
    earlier = NOW - datetime.timedelta(hours=1)
    state = {"soa": Entry(Status.OK, earlier), "records old A": Entry(Status.FAIL, earlier)}
    new_state, changes = diff(state, [Result("soa", Status.OK, ""), Result("records @ A", Status.FAIL, "x")], NOW)
    assert new_state == {"soa": Entry(Status.OK, earlier), "records @ A": Entry(Status.FAIL, NOW)}
    assert [(c.previous, c.result.key) for c in changes] == [(Status.OK, "records @ A")]


def test_the_heartbeat_cron_matches_the_constant() -> None:
    assert main.HEARTBEAT_CRON == "17 4 * * *"
