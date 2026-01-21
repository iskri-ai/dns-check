"""The four checks: delegation, soa, expiry and records.

Each check returns a Result. For ok, the detail holds the key facts
the heartbeat shows. For fail and unknown, it says what is wrong.
"""

import collections
import dataclasses
import datetime
import enum
import http.client
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from typing import Any

import dns.name
from dns.rdtypes.ANY.SOA import SOA

from dnscheck.config import Config, RecordSet, RecordValue
from dnscheck.query import NotDelegated, Querier, Referral, Unusable, printable

SOA_SAMPLES = 8
"""SOA queries per address and pass, so one lagging backend instance is unlikely to hide."""
RDAP_TRIES = 3
RDAP_TIMEOUT = 10.0
RDAP_USER_AGENT = "rdap-client/1.0"
"""The RDAP server answers 403 to the default Python-urllib User-Agent."""
AUTO_RENEWED = "auto-renewed by the registry, confirm the renewal is paid at the registrar"

type Fetch = Callable[[str], bytes]
"""Fetch a URL and return the body of a 200 response. Raises RdapError."""


class Status(enum.StrEnum):
    OK = "ok"
    FAIL = "fail"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True)
class Result:
    key: str
    status: Status
    detail: str


class RdapError(Exception):
    """RDAP gave no usable response. The message is our own wording only."""


def delegation(querier: Querier, config: Config) -> Result:
    key = "delegation"
    qname = dns.name.from_text(config.domain)
    parent = qname.parent().to_text()
    expected = frozenset(config.nameservers)

    tld_servers = querier.lookup(parent, "NS")
    if tld_servers is None:
        return Result(key, Status.UNKNOWN, f"could not look up the {parent} servers")

    wrong: list[str] = []
    silent: list[str] = []
    answered = 0
    total = 0
    for server in tld_servers:
        addresses = querier.lookup(server, "A")
        if addresses is None:
            total += 1
            silent.append(f"{server}: address lookup failed")
            continue
        for address in addresses:
            total += 1
            where = f"{server} ({address})"
            result = querier.referral(address, qname)
            if isinstance(result, Referral):
                if result.nameservers == expected:
                    answered += 1
                else:
                    wrong.append(
                        f"{where} [{result.nsid}]: delegates to {_names(result.nameservers)}"
                    )
            elif isinstance(result, NotDelegated):
                wrong.append(f"{where} [{result.nsid}]: {result.reason}")
            else:
                silent.append(f"{where}: {result.reason}")

    if wrong:
        return Result(key, Status.FAIL, "; ".join(wrong))
    if answered:
        return Result(
            key,
            Status.OK,
            f"{_names(expected)} ({answered}/{total} .{parent.rstrip('.')} servers answered)",
        )
    return Result(key, Status.UNKNOWN, "no server answered: " + "; ".join(silent))


def soa(querier: Querier, config: Config) -> Result:
    key = "soa"
    qname = dns.name.from_text(config.domain)
    targets, silent = _targets(querier, config.nameservers)
    wrong: list[str] = []
    serials: list[tuple[str, str, int]] = []
    for name, address in targets:
        for _ in range(SOA_SAMPLES):
            result = querier.authoritative(address, qname, "SOA")
            if isinstance(result, Unusable):
                (silent if result.no_response else wrong).append(
                    f"{name} ({address}): {result.reason}"
                )
                continue
            records = [value for value in result.values if isinstance(value, SOA)]
            if len(records) != 1 or len(result.values) != 1:
                wrong.append(
                    f"{name} ({address}) [{result.nsid}]: {len(result.values)} SOA records"
                )
                continue
            serials.append((address, result.nsid, records[0].serial))

    distinct = collections.Counter(serial for _, _, serial in serials)
    if len(distinct) > 1:
        majority = distinct.most_common(1)[0][0]
        others = _unique(
            f"{address} [{nsid}] {serial}"
            for address, nsid, serial in serials
            if serial != majority
        )
        wrong.append("serials differ: " + ", ".join(others) + f", all others {majority}")
    if wrong:
        return Result(key, Status.FAIL, "; ".join(_unique(wrong + silent)))
    if silent:
        return Result(key, Status.UNKNOWN, "; ".join(_unique(silent)))
    return Result(key, Status.OK, f"serial {next(iter(distinct))} on {len(targets)} addresses")


def expiry(config: Config, now: datetime.datetime, fetch: Fetch | None = None) -> Result:
    key = "expiry"
    url = config.rdap_base_url.rstrip("/") + "/domain/" + config.domain
    try:
        body = (fetch or fetch_rdap)(url)
    except RdapError as exc:
        return Result(key, Status.UNKNOWN, f"RDAP: {exc}")
    try:
        data = json.loads(body)
    except ValueError:
        return Result(key, Status.UNKNOWN, "RDAP: the response is not valid JSON")
    if not isinstance(data, dict):
        return Result(key, Status.UNKNOWN, "RDAP: the response is not a JSON object")

    ldh_name = data.get("ldhName")
    if not isinstance(ldh_name, str) or ldh_name.lower() != config.domain:
        return Result(
            key, Status.UNKNOWN, f"RDAP: the response is for {ldh_name!r}, not {config.domain}"
        )
    expires, problem = _expiration(data)
    facts = ""
    if expires is not None:
        left = expires - now
        date = expires.astimezone(datetime.UTC).date().isoformat()
        if left < datetime.timedelta(0):
            return Result(key, Status.FAIL, f"expired on {date}")
        facts = f"expires {date}, {left.days} days left"
        if left < datetime.timedelta(days=config.min_days_left):
            return Result(key, Status.FAIL, f"{facts}, minimum {config.min_days_left}")

    status = data.get("status")
    entries = status if isinstance(status, list) else []
    if any(isinstance(value, str) and _squash(value) == "autorenewperiod" for value in entries):
        return Result(key, Status.FAIL, f"{AUTO_RENEWED} ({facts})" if facts else AUTO_RENEWED)
    if expires is None:
        return Result(key, Status.UNKNOWN, problem)
    # a domain must have at least one EPP status
    if not entries or not all(isinstance(value, str) for value in entries):
        return Result(key, Status.UNKNOWN, "RDAP: missing, empty or malformed status array")
    return Result(key, Status.OK, facts)


def _expiration(data: dict[str, Any]) -> tuple[datetime.datetime | None, str]:
    """Return the single expiration date, or None and why it can't be read."""
    events = data.get("events")
    dates = [
        event.get("eventDate")
        for event in (events if isinstance(events, list) else [])
        if isinstance(event, dict) and event.get("eventAction") == "expiration"
    ]
    if len(dates) != 1:
        return None, f"RDAP: expected one expiration event, found {len(dates)}"
    try:
        expires = datetime.datetime.fromisoformat(str(dates[0]))
    except ValueError:
        return None, f"RDAP: cannot parse the expiration date {dates[0]!r}"
    if expires.tzinfo is None:
        return None, f"RDAP: the expiration date {dates[0]!r} has no time zone"
    return expires, ""


def _squash(text: str) -> str:
    """Lowercase and drop everything but letters and digits, so "auto renew period"
    and "autoRenewPeriod" compare equal."""
    return "".join(char for char in text.lower() if char.isalnum())


def records(querier: Querier, config: Config, sets: Iterable[RecordSet]) -> list[Result]:
    targets, lookup_silent = _targets(querier, config.nameservers)
    results: list[Result] = []
    for record_set in sets:
        wrong: list[str] = []
        diffs: list[tuple[str, str]] = []
        silent = list(lookup_silent)
        for _name, address in targets:
            result = querier.authoritative(address, record_set.qname, record_set.rtype)
            if isinstance(result, Unusable):
                (silent if result.no_response else wrong).append(f"{address}: {result.reason}")
            elif result.values != record_set.expected:
                diffs.append(
                    (f"{address} [{result.nsid}]", _diff(record_set.expected, result.values))
                )
        if wrong or diffs:
            if (
                not wrong
                and not silent
                and len(diffs) == len(targets)
                and len({d for _, d in diffs}) == 1
            ):
                lines = [f"all addresses: {diffs[0][1]}"]
            else:
                lines = wrong + [f"{where}: {diff}" for where, diff in diffs] + silent
            results.append(Result(record_set.key, Status.FAIL, "; ".join(lines)))
        elif silent:
            results.append(Result(record_set.key, Status.UNKNOWN, "; ".join(silent)))
        else:
            results.append(Result(record_set.key, Status.OK, ""))
    return results


def fetch_rdap(url: str, sleep: Callable[[float], None] = time.sleep) -> bytes:
    """Fetch an RDAP URL. Error messages never include exception text."""
    request = urllib.request.Request(
        url, headers={"Accept": "application/rdap+json", "User-Agent": RDAP_USER_AGENT}
    )
    reason = ""
    for attempt in range(RDAP_TRIES):
        if attempt:
            sleep(1.0)
        try:
            with urllib.request.urlopen(request, timeout=RDAP_TIMEOUT) as response:
                if response.status == 200:
                    body: bytes = response.read()
                    return body
                reason = f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            reason = f"HTTP {exc.code}"
        except (OSError, http.client.HTTPException) as exc:
            reason = f"request failed ({type(exc).__name__})"
    raise RdapError(reason)


def format_value(value: RecordValue) -> str:
    if isinstance(value, bytes):
        return '"' + printable(value.decode("utf-8", errors="replace")) + '"'
    # dnspython text output already escapes control bytes
    return value.to_text()


def _diff(expected: frozenset[RecordValue], actual: frozenset[RecordValue]) -> str:
    parts = []
    missing = sorted(format_value(v) for v in expected - actual)
    unexpected = sorted(format_value(v) for v in actual - expected)
    if missing:
        parts.append("missing " + ", ".join(missing))
    if unexpected:
        parts.append("unexpected " + ", ".join(unexpected))
    return ", ".join(parts)


def _targets(querier: Querier, names: Iterable[str]) -> tuple[list[tuple[str, str]], list[str]]:
    """Return (name, address) pairs, and a line for each name whose lookup failed.

    A failed lookup counts like an address with no response.
    """
    targets: list[tuple[str, str]] = []
    problems: list[str] = []
    for name in names:
        addresses = querier.lookup(name, "A")
        if addresses is None:
            problems.append(f"{name}: address lookup failed")
        else:
            targets.extend((name, address) for address in addresses)
    return targets, problems


def _names(names: Iterable[str]) -> str:
    return ", ".join(sorted(names))


def _unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))
