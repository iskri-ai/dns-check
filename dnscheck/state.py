"""Read and write state.json, the status of each check and since when.

The workflow checks the file out from the state branch before the run
and commits it back after, so this module only sees a local file.
"""

import dataclasses
import datetime
import json
from pathlib import Path

from dnscheck.checks import Status


class StateError(Exception):
    """The state could not be read or written. The message is our own wording only."""


@dataclasses.dataclass(frozen=True)
class Entry:
    status: Status
    since: datetime.datetime


type State = dict[str, Entry]


def parse(text: str) -> State:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise StateError("the state file is not valid JSON") from exc
    if not isinstance(data, dict):
        raise StateError("the state file is not a JSON object")
    state: State = {}
    for key, entry in data.items():
        try:
            state[key] = Entry(Status(entry["status"]), datetime.datetime.fromisoformat(entry["since"]))
        except (ValueError, TypeError, KeyError) as exc:
            raise StateError(f"the state file has an invalid entry {key!r}") from exc
    return state


def dump(state: State) -> str:
    data = {key: {"status": e.status.value, "since": e.since.isoformat()} for key, e in state.items()}
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


class Store:
    def __init__(self, path: Path) -> None:
        self._path = path

    def read(self) -> State:
        try:
            text = self._path.read_text(encoding="utf-8")
        except OSError as exc:
            raise StateError(f"cannot read {self._path} ({type(exc).__name__})") from exc
        return parse(text)

    def write(self, state: State) -> None:
        try:
            self._path.write_text(dump(state), encoding="utf-8")
        except OSError as exc:
            raise StateError(f"cannot write {self._path} ({type(exc).__name__})") from exc
