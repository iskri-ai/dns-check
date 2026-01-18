import datetime
from pathlib import Path

import pytest

from dnscheck.checks import Status
from dnscheck.state import Entry, StateError, Store, parse

T0 = datetime.datetime(2026, 11, 11, 12, 7, tzinfo=datetime.UTC)


def test_read_write_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{}\n")
    store = Store(path)
    assert store.read() == {}

    state = {"soa": Entry(Status.FAIL, T0), "records @ TXT": Entry(Status.OK, T0)}
    store.write(state)

    assert path.read_text() == """\
{
  "records @ TXT": {
    "since": "2026-11-11T12:07:00+00:00",
    "status": "ok"
  },
  "soa": {
    "since": "2026-11-11T12:07:00+00:00",
    "status": "fail"
  }
}
"""
    assert Store(path).read() == state


def test_a_missing_file_aborts_with_our_wording(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    with pytest.raises(StateError) as excinfo:
        Store(path).read()
    assert str(excinfo.value) == f"cannot read {path} (FileNotFoundError)"


def test_a_failed_write_aborts_with_our_wording(tmp_path: Path) -> None:
    path = tmp_path / "gone" / "state.json"
    with pytest.raises(StateError) as excinfo:
        Store(path).write({})
    assert str(excinfo.value) == f"cannot write {path} (FileNotFoundError)"


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        "null",
        '{"soa": null}',
        '{"soa": "ok"}',
        '{"soa": {"status": "ok"}}',
        '{"soa": {"status": "great", "since": "2026-11-11T12:07:00+00:00"}}',
        '{"soa": {"status": "ok", "since": "yesterday"}}',
    ],
)
def test_invalid_state_aborts(text: str) -> None:
    with pytest.raises(StateError):
        parse(text)
