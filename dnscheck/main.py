"""One run of the monitor.

The run loads expected.yaml, reads the state, checks, re-checks what
failed after 2 minutes, sends one message and saves the state. It exits
0 whatever the domain's status, and 1 only when it could not finish its
work (aborted). An aborted run tries to send its reason to Telegram.
"""

import argparse
import dataclasses
import datetime
import os
import subprocess
import sys
import time
import traceback
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Protocol

from dnscheck import checks
from dnscheck.checks import Result, Status
from dnscheck.config import Config, ConfigError, load_file
from dnscheck.notify import (
    Change,
    Telegram,
    TelegramError,
    abort_text,
    cap,
    change_lines,
    compose,
    heartbeat_lines,
)
from dnscheck.query import Querier
from dnscheck.state import SETUP_HINT, Entry, State, StateError, Store

RECHECK_DELAY = 120.0
HEARTBEAT_CRON = "17 4 * * *"
"""Must match the heartbeat cron line in .github/workflows/dns-check.yml."""


class Aborted(Exception):
    """The run could not finish its work. The message is our own wording only."""


class StateStore(Protocol):
    def read(self) -> State: ...
    def write(self, state: State) -> None: ...


class Messenger(Protocol):
    def send(self, text: str) -> None: ...


def _commit_time(repo: Path) -> datetime.datetime:
    output = subprocess.run(
        ["git", "log", "-1", "--format=%ct", "HEAD"], cwd=repo, capture_output=True, check=True
    ).stdout
    return datetime.datetime.fromtimestamp(int(output), datetime.UTC)


@dataclasses.dataclass
class Deps:
    querier: Callable[[], Querier] = Querier
    fetch: checks.Fetch = checks.fetch_rdap
    store: Callable[[Path], StateStore] = Store
    messenger: Callable[[str, str, str], Messenger] = Telegram
    now: Callable[[], datetime.datetime] = lambda: datetime.datetime.now(datetime.UTC)
    sleep: Callable[[float], None] = time.sleep
    commit_time: Callable[[Path], datetime.datetime] = _commit_time


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dnscheck")
    parser.add_argument("--heartbeat", action="store_true", help="also send the daily summary")
    parser.add_argument("--config", type=Path, default=Path("expected.yaml"))
    args = parser.parse_args(argv)
    return run(args.config, Path.cwd(), args.heartbeat, os.environ)


def run(
    config_path: Path, repo: Path, heartbeat: bool, env: Mapping[str, str], deps: Deps | None = None
) -> int:
    deps = deps or Deps()
    run_url = _run_url(env)
    heartbeat = heartbeat or env.get("SCHEDULE") == HEARTBEAT_CRON or env.get("HEARTBEAT") == "true"
    names = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "TELEGRAM_THREAD_ID")
    missing = [name for name in names if not env.get(name)]
    if missing:
        print(f"run aborted: empty {', '.join(missing)}, cannot reach Telegram", file=sys.stderr)
        return 1
    messenger = deps.messenger(*(env[name] for name in names))
    domain = "dns-check"
    try:
        config = _load(config_path)
        domain = config.domain
        _check(config, repo, heartbeat, run_url, messenger, deps)
        return 0
    except Aborted as exc:
        reason = str(exc)
    except Exception as exc:
        traceback.print_exc()
        reason = f"unexpected error ({type(exc).__name__})"
    print(f"run aborted: {reason}", file=sys.stderr)
    try:
        messenger.send(abort_text(domain, reason, run_url))
    except TelegramError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _set_output(env, "reported", "true")
    return 1


def _load(path: Path) -> Config:
    try:
        return load_file(path)
    except ConfigError as exc:
        raise Aborted(f"invalid {path.name}: {exc}") from exc
    except Exception as exc:
        raise Aborted(f"invalid {path.name}: {type(exc).__name__}") from exc


def _check(
    config: Config, repo: Path, heartbeat: bool, run_url: str, messenger: Messenger, deps: Deps
) -> None:
    store = deps.store(repo)
    try:
        state = store.read()
    except StateError as exc:
        raise Aborted(f"{exc}. To {SETUP_HINT}") from exc

    results = _run_checks(config, deps)
    now = deps.now()
    new_state, changes = diff(state, results, now)

    summary = None
    if heartbeat:
        try:
            days: int | None = (now - deps.commit_time(repo)).days
        except (subprocess.CalledProcessError, ValueError, OSError):
            days = None
        since = {key: entry.since for key, entry in new_state.items()}
        summary = heartbeat_lines(results, since, days)

    lines = compose(config.domain, change_lines(changes, now), summary)
    if lines is not None:
        # The job log keeps the full text. Telegram gets a capped copy.
        print("\n".join([*lines, run_url]))
        try:
            messenger.send(cap(lines, run_url))
        except TelegramError as exc:
            raise Aborted(str(exc)) from exc

    if new_state != state:
        try:
            store.write(new_state)
        except StateError as exc:
            raise Aborted(str(exc)) from exc


def _run_checks(config: Config, deps: Deps) -> list[Result]:
    first = _one_pass(config, deps, None)
    failing = {r.key for r in first if r.status is not Status.OK}
    if not failing:
        return first
    deps.sleep(RECHECK_DELAY)
    second = {r.key: r for r in _one_pass(config, deps, failing)}
    return [second.get(r.key, r) for r in first]


def _one_pass(config: Config, deps: Deps, keys: set[str] | None) -> list[Result]:
    """Run the checks with a fresh Querier, so dead addresses reset per pass."""
    querier = deps.querier()

    def wanted(key: str) -> bool:
        return keys is None or key in keys

    results = []
    if wanted("delegation"):
        results.append(checks.delegation(querier, config))
    if wanted("soa"):
        results.append(checks.soa(querier, config))
    if wanted("expiry"):
        results.append(checks.expiry(config, deps.now(), deps.fetch))
    results += checks.records(querier, config, [r for r in config.records if wanted(r.key)])
    return results


def diff(
    state: State, results: Iterable[Result], now: datetime.datetime
) -> tuple[State, list[Change]]:
    """Return the new state and the status changes.

    A key new to the state counts as previously ok. Keys no longer
    checked drop out of the state silently.
    """
    new_state: State = {}
    changes = []
    for result in results:
        old = state.get(result.key)
        previous = old.status if old else Status.OK
        if old and result.status is previous:
            new_state[result.key] = old
            continue
        new_state[result.key] = Entry(result.status, now)
        if result.status is not previous:
            changes.append(Change(previous, old.since if old else now, result))
    return new_state, changes


def _run_url(env: Mapping[str, str]) -> str:
    parts = [env.get(name) for name in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID")]
    if all(parts):
        return f"{parts[0]}/{parts[1]}/actions/runs/{parts[2]}"
    return "(no run link, local run)"


def _set_output(env: Mapping[str, str], name: str, value: str) -> None:
    path = env.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as output:
            output.write(f"{name}={value}\n")
