import datetime
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from dnscheck.checks import Status
from dnscheck.state import BOT, COMMIT_MESSAGE, Entry, StateError, StateMissing, Store, credential_args, dump, parse

T0 = datetime.datetime(2026, 11, 11, 12, 7, tzinfo=datetime.UTC)


@pytest.fixture(autouse=True)
def isolated_git(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the developer's git config out of the tests."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"):
        monkeypatch.setenv(name, "Test")
    for name in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"):
        monkeypatch.setenv(name, "test@example.invalid")


def git(cwd: Path, *args: str, stdin: bytes | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, input=stdin, check=True, capture_output=True).stdout.decode().strip()


@pytest.fixture
def repos(tmp_path: Path) -> tuple[Path, Path]:
    """A bare origin with master and a state branch holding '{}', and a clone of master."""
    origin = tmp_path / "origin.git"
    seed = tmp_path / "seed"
    work = tmp_path / "work"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "master", str(origin)], check=True)
    subprocess.run(["git", "init", "-q", "-b", "master", str(seed)], check=True)
    (seed / "README.md").write_text("# dns-check\n")
    git(seed, "add", "README.md")
    git(seed, "commit", "-q", "-m", "first commit")
    git(seed, "switch", "-q", "--orphan", "state")
    (seed / "state.json").write_text("{}\n")
    git(seed, "add", "state.json")
    git(seed, "commit", "-q", "-m", "chore(state): add empty state")
    git(seed, "push", "-q", str(origin), "master", "state")
    subprocess.run(["git", "clone", "-q", "--branch", "master", str(origin), str(work)], check=True)
    return origin, work


def test_read_write_round_trip(repos: tuple[Path, Path]) -> None:
    origin, work = repos
    store = Store(work)
    assert store.read() == {}

    state = {"soa": Entry(Status.FAIL, T0), "records @ TXT": Entry(Status.OK, T0)}
    store.write(state)

    assert Store(work).read() == state
    assert git(origin, "log", "-1", "--format=%s|%an", "state") == f"{COMMIT_MESSAGE}|{BOT}"
    assert git(origin, "show", "state:state.json") == dump(state).strip()
    assert git(origin, "rev-list", "--count", "state") == "2"
    assert git(work, "status", "--porcelain") == ""
    assert git(work, "branch", "--show-current") == "master"


def test_a_missing_branch_is_reported_as_missing(repos: tuple[Path, Path]) -> None:
    origin, work = repos
    git(origin, "branch", "-D", "state")
    with pytest.raises(StateMissing, match="the state branch does not exist on the remote"):
        Store(work).read()


def replace_state(origin: Path, tmp_path: Path, files: dict[str, str]) -> None:
    clone = tmp_path / "replace"
    subprocess.run(["git", "clone", "-q", "--branch", "state", str(origin), str(clone)], check=True)
    git(clone, "rm", "-q", "-r", ".")
    for name, text in files.items():
        (clone / name).write_text(text)
        git(clone, "add", name)
    git(clone, "commit", "-q", "-m", "replace state")
    git(clone, "push", "-q", "origin", "state")


@pytest.mark.parametrize(
    "case",
    ["unreachable remote", "no state.json", "invalid JSON"],
)
def test_other_read_failures_are_not_reported_as_missing(case: str, tmp_path: Path, repos: tuple[Path, Path]) -> None:
    origin, work = repos
    store = Store(work)
    if case == "unreachable remote":
        store = Store(work, remote=str(tmp_path / "gone.git"))
    elif case == "no state.json":
        replace_state(origin, tmp_path, {"other.txt": "x\n"})
    else:
        replace_state(origin, tmp_path, {"state.json": "not json\n"})
    with pytest.raises(StateError) as excinfo:
        store.read()
    assert not isinstance(excinfo.value, StateMissing)


def test_push_uses_the_credential_helper_and_never_the_token(
    repos: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, work = repos
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_secret_token_value")
    commands: list[list[str]] = []

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        commands.append(args)
        return subprocess.run(args, **kwargs)

    store = Store(work, run=run)
    store.read()
    store.write({"soa": Entry(Status.OK, T0)})

    push = next(c for c in commands if "push" in c)
    assert push[1:5] == credential_args()
    assert all("ghs_secret_token_value" not in part for command in commands for part in command)


def credential(action: str, protocol: str, host: str, token: str = "fake-token") -> subprocess.CompletedProcess[bytes]:
    env = {**os.environ, "GITHUB_TOKEN": token, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": ""}
    return subprocess.run(
        ["git", *credential_args(), "credential", action],
        input=f"protocol={protocol}\nhost={host}\n\n".encode(),
        capture_output=True, env=env, check=False,
    )


def test_the_helper_offers_the_token_to_github_over_https_only() -> None:
    granted = credential("fill", "https", "github.com")
    assert granted.returncode == 0
    assert b"username=x-access-token\n" in granted.stdout
    assert b"password=fake-token\n" in granted.stdout
    for protocol, host in [("https", "unrelated.example"), ("http", "github.com"), ("https", "github.com.evil.example")]:
        denied = credential("fill", protocol, host)
        assert b"fake-token" not in denied.stdout + denied.stderr, (protocol, host)
        assert denied.returncode != 0, (protocol, host)


def test_the_helper_ignores_store_and_erase() -> None:
    for action in ("approve", "reject"):
        result = credential(action, "https", "github.com")
        assert result.returncode == 0
        assert result.stdout == b""


def test_git_errors_carry_only_our_wording(repos: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    _, work = repos

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args, 128, b"", b"fatal: https://x-access-token:secret@example/ denied")

    with pytest.raises(StateError) as excinfo:
        Store(work, run=run).read()
    assert str(excinfo.value) == "git fetch on the state branch failed (exit 128)"
    assert "secret" in capsys.readouterr().err


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        '{"soa": "ok"}',
        '{"soa": {"status": "ok"}}',
        '{"soa": {"status": "great", "since": "2026-11-11T12:07:00+00:00"}}',
        '{"soa": {"status": "ok", "since": "yesterday"}}',
        '{"soa": {"status": "ok", "since": "2026-11-11T12:07:00"}}',
        '{"soa": {"status": "ok", "since": "2026-11-11T12:07:00+00:00", "detail": "x"}}',
    ],
)
def test_invalid_state_aborts(text: str) -> None:
    with pytest.raises(StateError):
        parse(text)


def test_writing_before_reading_is_refused(tmp_path: Path) -> None:
    with pytest.raises(StateError):
        Store(tmp_path).write({})
