"""Read and write state.json on the state branch with git.

Reading needs no token, because the repository is public. Writing
builds the commit with plumbing commands, so the checkout of master is
never touched, and pushes through a credential helper that reads the
token from $GITHUB_TOKEN. The token never appears in a command line, a
remote URL or http.extraheader.
"""

import dataclasses
import datetime
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from dnscheck.checks import Status

BRANCH = "state"
FILE = "state.json"
COMMIT_MESSAGE = "chore(state): record status changes"
SETUP_HINT = (
    "create the state branch once: git switch --orphan state && echo '{}' > state.json"
    " && git add state.json && git commit -m 'chore(state): add empty state'"
    " && git push origin state"
)
# Answers only "get" requests, with the token from the environment.
CREDENTIAL_HELPER = (
    '!f() { test "$1" = get || exit 0; echo username=x-access-token;'
    ' echo "password=$GITHUB_TOKEN"; }; f'
)
BOT = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"

type Run = Callable[..., subprocess.CompletedProcess[bytes]]


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
        raise StateError(f"{FILE} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise StateError(f"{FILE} is not a JSON object")
    state: State = {}
    for key, entry in data.items():
        if not isinstance(entry, dict) or set(entry) != {"status", "since"}:
            raise StateError(f"{FILE}: invalid entry {key!r}")
        try:
            status = Status(entry["status"])
            since = datetime.datetime.fromisoformat(entry["since"])
        except (ValueError, TypeError) as exc:
            raise StateError(f"{FILE}: invalid entry {key!r}") from exc
        if since.tzinfo is None:
            raise StateError(f"{FILE}: invalid entry {key!r}")
        state[key] = Entry(status, since)
    return state


def dump(state: State) -> str:
    data = {key: {"status": e.status.value, "since": e.since.isoformat()} for key, e in state.items()}
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


class Store:
    def __init__(self, repo: Path, remote: str = "origin", run: Run = subprocess.run) -> None:
        self._repo = repo
        self._remote = remote
        self._run = run
        self._parent: str | None = None

    def read(self) -> State:
        self._git("fetch", ["fetch", "--no-tags", "--depth=1", self._remote, f"refs/heads/{BRANCH}"])
        self._parent = self._git("rev-parse", ["rev-parse", "FETCH_HEAD"])
        return parse(self._git("show", ["show", f"{self._parent}:{FILE}"]))

    def write(self, state: State) -> None:
        if self._parent is None:
            raise StateError("the state must be read before it is written")
        blob = self._git("hash-object", ["hash-object", "-w", "--stdin"], dump(state).encode())
        tree = self._git("mktree", ["mktree"], f"100644 blob {blob}\t{FILE}\n".encode())
        commit = self._git(
            "commit-tree",
            ["commit-tree", "--no-gpg-sign", tree, "-p", self._parent, "-m", COMMIT_MESSAGE],
        )
        self._git(
            "push",
            [
                "-c", "credential.helper=",
                "-c", f"credential.helper={CREDENTIAL_HELPER}",
                "push", self._remote, f"{commit}:refs/heads/{BRANCH}",
            ],
        )
        self._parent = commit

    def _git(self, what: str, args: list[str], stdin: bytes | None = None) -> str:
        env: dict[str, Any] = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": BOT,
            "GIT_AUTHOR_EMAIL": BOT_EMAIL,
            "GIT_COMMITTER_NAME": BOT,
            "GIT_COMMITTER_EMAIL": BOT_EMAIL,
        }
        result = self._run(
            ["git", *args], cwd=self._repo, input=stdin, capture_output=True, env=env, check=False
        )
        if result.returncode != 0:
            # The job log gets git's own output, for diagnosis. GitHub masks
            # the token there. Telegram only ever sees our wording.
            sys.stderr.write(result.stderr.decode(errors="replace"))
            raise StateError(f"git {what} on the {BRANCH} branch failed (exit {result.returncode})")
        return result.stdout.decode().strip()
