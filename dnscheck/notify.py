"""Message text and the Telegram send.

Messages are plain text, with no parse mode, because record values can
hold characters that Markdown or HTML modes would reject.
"""

import dataclasses
import datetime
import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from dnscheck.checks import Result, Status

LIMIT = 4000
"""Telegram rejects messages over 4,096 characters."""
TELEGRAM_TRIES = 3
TELEGRAM_TIMEOUT = 10.0


class TelegramError(Exception):
    """The message was not delivered. The message is our own wording only."""


@dataclasses.dataclass(frozen=True)
class Change:
    previous: Status
    previous_since: datetime.datetime
    result: Result


def change_lines(changes: Sequence[Change], now: datetime.datetime) -> list[str]:
    lines = []
    for change in changes:
        result = change.result
        if result.status is Status.OK:
            lines.append(
                f"OK {result.key}: recovered after {duration(now - change.previous_since)}"
            )
        elif result.status is Status.UNKNOWN:
            lines.append(f"UNKNOWN {result.key}: could not check: {result.detail}")
        else:
            lines.append(f"FAIL {result.key}: {result.detail}")
    return lines


def heartbeat_lines(results: Sequence[Result], since: Mapping[str, datetime.datetime]) -> list[str]:
    lines = []
    records = [r for r in results if r.key.startswith("records ")]
    for result in results:
        if result in records:
            continue
        if result.status is Status.OK:
            lines.append(f"{result.key} ok: {result.detail}")
        else:
            lines.append(_problem(result, since))
    if not records:
        lines.append("records: none listed")
    else:
        ok = sum(r.status is Status.OK for r in records)
        lines.append(f"records: {ok}/{len(records)} ok")
        lines.extend(_problem(r, since) for r in records if r.status is not Status.OK)
    return lines


def compose(domain: str, changes: list[str], heartbeat: list[str] | None) -> list[str] | None:
    """Return the lines of the run's single message, or None when there is nothing to send.

    The caller logs the full lines and caps only what goes to Telegram.
    """
    lines: list[str] = []
    if changes:
        noun = "change" if len(changes) == 1 else "changes"
        lines += [f"{domain}: {len(changes)} status {noun}", *changes]
    if heartbeat is not None:
        if lines:
            lines.append("")
        lines += [f"{domain}: daily summary", *heartbeat]
    return lines or None


def abort_text(domain: str, reason: str, run_url: str) -> str:
    return cap([f"{domain}: run aborted: {reason}"], run_url)


def cap(lines: list[str], run_url: str, limit: int = LIMIT) -> str:
    """Join the lines with the run link last, cutting the text to fit the limit."""
    text = "\n".join([*lines, run_url])
    if len(text) <= limit:
        return text
    tail = "…\nthe full message is in the run log\n" + run_url
    return "\n".join(lines)[: limit - len(tail)] + tail


def duration(delta: datetime.timedelta) -> str:
    minutes = max(int(delta.total_seconds() // 60), 0)
    days, minutes = divmod(minutes, 24 * 60)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _problem(result: Result, since: Mapping[str, datetime.datetime]) -> str:
    start = since.get(result.key)
    when = f" since {start.astimezone(datetime.UTC):%Y-%m-%d %H:%M} UTC" if start else ""
    return f"{result.status.value.upper()} {result.key}{when}: {result.detail}"


type Urlopen = Callable[..., Any]


class Telegram:
    def __init__(
        self,
        token: str,
        chat_id: str,
        thread_id: str,
        urlopen: Urlopen = urllib.request.urlopen,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._token = token
        self._chat_id = chat_id
        self._thread_id = thread_id
        self._urlopen = urlopen
        self._sleep = sleep

    def send(self, text: str) -> None:
        """Send a plain-text message without a link preview. Errors never
        include exception text, because the request URL contains the token."""
        data = urllib.parse.urlencode(
            {
                "chat_id": self._chat_id,
                "message_thread_id": self._thread_id,
                "text": text,
                "link_preview_options": '{"is_disabled":true}',
            }
        ).encode()
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{self._token}/sendMessage", data=data, method="POST"
        )
        reason = ""
        for attempt in range(TELEGRAM_TRIES):
            if attempt:
                self._sleep(2.0)
            try:
                with self._urlopen(request, timeout=TELEGRAM_TIMEOUT) as response:
                    body = json.load(response)
                    status = response.status
                if status == 200 and isinstance(body, dict) and body.get("ok") is True:
                    return
                reason = "Telegram did not confirm the message"
            except urllib.error.HTTPError as exc:
                reason = f"HTTP {exc.code}"
            except (OSError, http.client.HTTPException, ValueError) as exc:
                reason = f"request failed ({type(exc).__name__})"
        raise TelegramError(f"Telegram send failed: {reason}")
