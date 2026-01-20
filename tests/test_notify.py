import datetime
import email.message
import io
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import pytest

from dnscheck.checks import Result, Status
from dnscheck.notify import (
    LIMIT,
    Change,
    Telegram,
    TelegramError,
    abort_text,
    cap,
    change_lines,
    compose,
    duration,
    heartbeat_lines,
)

NOW = datetime.datetime(2026, 11, 12, 13, 19, tzinfo=datetime.UTC)
RUN = "https://github.com/iskri-ai/dns-check/actions/runs/1"


def test_change_lines_are_worded_by_the_new_status() -> None:
    lines = change_lines(
        [
            Change(
                Status.OK,
                NOW,
                Result(
                    "soa",
                    Status.FAIL,
                    "serials differ: 188.68.203.1 [5-ans-prod-spb] 1, all others 2",
                ),
            ),
            Change(
                Status.FAIL,
                NOW - datetime.timedelta(hours=3, minutes=12),
                Result("records @ TXT", Status.OK, ""),
            ),
            Change(Status.OK, NOW, Result("expiry", Status.UNKNOWN, "RDAP: HTTP 503")),
        ],
        NOW,
    )
    assert lines == [
        "FAIL soa: serials differ: 188.68.203.1 [5-ans-prod-spb] 1, all others 2",
        "OK records @ TXT: recovered after 3h 12m",
        "UNKNOWN expiry: could not check: RDAP: HTTP 503",
    ]


@pytest.mark.parametrize(
    ("delta", "text"),
    [
        (datetime.timedelta(minutes=14, seconds=59), "14m"),
        (datetime.timedelta(hours=3, minutes=12), "3h 12m"),
        (datetime.timedelta(days=2, hours=4, minutes=30), "2d 4h"),
    ],
)
def test_duration(delta: datetime.timedelta, text: str) -> None:
    assert duration(delta) == text


def results(*records: Result) -> list[Result]:
    return [
        Result(
            "delegation", Status.OK, "a.ns.selectel.ru, b.ns.selectel.ru (3/4 .io servers answered)"
        ),
        Result("soa", Status.OK, "serial 2026111001 on 4 addresses"),
        Result("expiry", Status.OK, "expires 2027-11-10, 363 days left"),
        *records,
    ]


def test_heartbeat_expands_the_checks_and_collapses_ok_record_sets() -> None:
    failing = Result("records @ TXT", Status.FAIL, 'all addresses: missing "v=spf1 -all"')
    since = {"records @ TXT": datetime.datetime(2026, 11, 12, 10, 7, tzinfo=datetime.UTC)}
    lines = heartbeat_lines(results(Result("records @ A", Status.OK, ""), failing), since)
    assert lines == [
        "delegation ok: a.ns.selectel.ru, b.ns.selectel.ru (3/4 .io servers answered)",
        "soa ok: serial 2026111001 on 4 addresses",
        "expiry ok: expires 2027-11-10, 363 days left",
        "records: 1/2 ok",
        'FAIL records @ TXT since 2026-11-12 10:07 UTC: all addresses: missing "v=spf1 -all"',
    ]


def test_heartbeat_expands_a_failing_check_and_handles_no_records() -> None:
    checks = results()
    checks[2] = Result("expiry", Status.UNKNOWN, "RDAP: HTTP 503")
    lines = heartbeat_lines(checks, {"expiry": NOW})
    assert lines[2] == "UNKNOWN expiry since 2026-11-12 13:19 UTC: RDAP: HTTP 503"
    assert lines[3] == "records: none listed"


def test_compose_sends_nothing_without_changes_or_heartbeat() -> None:
    assert compose("iskri.io", [], None) is None


def test_compose_puts_changes_and_heartbeat_in_one_message() -> None:
    lines = compose("iskri.io", ["FAIL soa: x"], ["soa fail: x"])
    assert lines == [
        "iskri.io: 1 status change",
        "FAIL soa: x",
        "",
        "iskri.io: daily summary",
        "soa fail: x",
    ]


def test_abort_text() -> None:
    assert (
        abort_text("iskri.io", "invalid expected.yaml: x", RUN)
        == "iskri.io: run aborted: invalid expected.yaml: x\n" + RUN
    )


def test_cap_drops_lines_past_the_limit_and_keeps_the_link_last() -> None:
    lines = ["iskri.io: 300 status changes"] + [
        f"FAIL records r{i} A: " + "x" * 40 for i in range(300)
    ]
    text = cap(lines, RUN)
    assert len(text) <= LIMIT
    assert text.endswith("more lines in the run log\n" + RUN)
    kept = text.splitlines()
    dropped = int(kept[-2].split()[1])
    assert len(kept) - 2 + dropped == len(lines)


def test_cap_cuts_a_single_huge_line() -> None:
    text = cap(["x" * 10_000], RUN)
    assert len(text) <= LIMIT
    assert text.endswith("…\n" + RUN)


class FakeResponse(io.BytesIO):
    def __init__(self, body: dict[str, Any], status: int = 200) -> None:
        super().__init__(json.dumps(body).encode())
        self.status = status


def test_telegram_sends_plain_text_to_the_thread() -> None:
    requests: list[urllib.request.Request] = []

    def urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        requests.append(request)
        return FakeResponse({"ok": True})

    Telegram("123:token", "-100500", "42", urlopen=urlopen).send("hello <b>&")
    request = requests[0]
    assert request.full_url == "https://api.telegram.org/bot123:token/sendMessage"
    assert request.get_method() == "POST"
    assert isinstance(request.data, bytes)
    assert urllib.parse.parse_qs(request.data.decode()) == {
        "chat_id": ["-100500"],
        "message_thread_id": ["42"],
        "text": ["hello <b>&"],
        "link_preview_options": ['{"is_disabled":true}'],
    }


def test_telegram_errors_never_carry_exception_text() -> None:
    errors: list[Exception] = [
        urllib.error.URLError("https://api.telegram.org/bot123:token/sendMessage"),
        TimeoutError("123:token"),
        urllib.error.HTTPError(
            "https://api.telegram.org/bot123:token/sendMessage",
            400,
            "123:token",
            email.message.Message(),
            None,
        ),
    ]
    sleeps: list[float] = []

    def urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        raise errors.pop(0)

    with pytest.raises(TelegramError) as excinfo:
        Telegram("123:token", "-100500", "42", urlopen=urlopen, sleep=sleeps.append).send("x")
    assert str(excinfo.value) == "Telegram send failed: HTTP 400"
    assert sleeps == [2.0, 2.0]


def test_telegram_requires_a_confirmation() -> None:
    def urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        return FakeResponse({"ok": False})

    with pytest.raises(TelegramError, match="did not confirm"):
        Telegram("t", "c", "1", urlopen=urlopen, sleep=lambda s: None).send("x")
