import datetime
import email.message
import io
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from dnscheck import checks
from dnscheck.checks import RdapError, Result, Status
from dnscheck.config import Config, load
from dnscheck.notify import Change, change_lines
from dnscheck.query import NotDelegated, Querier, Records, Referral, Unusable

CONFIG = load("""\
domain: iskri.io
nameservers: [a.ns.selectel.ru, b.ns.selectel.ru, c.ns.selectel.ru, d.ns.selectel.ru]
expiry:
  rdap_base_url: https://rdap.example/rdap/
  min_days_left: 30
records:
  "@":
    A: 203.0.113.10
    AAAA: []
    TXT: "v=spf1 -all"
""")
EXPECTED_NS = frozenset(CONFIG.nameservers)
SELECTEL = {"a.ns.selectel.ru": "188.68.203.1", "b.ns.selectel.ru": "77.223.114.2",
            "c.ns.selectel.ru": "188.68.203.3", "d.ns.selectel.ru": "77.223.114.4"}
IO = {"a0.nic.io": "65.22.160.17", "a2.nic.io": "65.22.163.17",
      "b0.nic.io": "65.22.161.17", "c0.nic.io": "65.22.162.17"}


def lookups() -> dict[tuple[str, str], list[str] | None]:
    table: dict[tuple[str, str], list[str] | None] = {("io.", "NS"): sorted(IO)}
    table.update({(name, "A"): [address] for name, address in {**SELECTEL, **IO}.items()})
    return table


def rdata(rtype: str, text: str) -> dns.rdata.Rdata:
    return dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.from_text(rtype), text, origin=dns.name.root, relativize=False
    )


def soa_record(serial: int) -> Records:
    return Records(frozenset({rdata("SOA", f"a.ns.selectel.ru. support.selectel.ru. {serial} 10800 3600 604800 60")}), "5-ans-prod-spb")


type Answer = Callable[[str, dns.name.Name, str], Any]


class FakeQuerier:
    def __init__(self, answers: Answer | None = None, referrals: dict[str, Any] | None = None) -> None:
        self.lookups = lookups()
        self.answers = answers or (lambda address, qname, rdtype: Unusable("not scripted"))
        self.referrals = referrals or {}
        self.calls: list[tuple[str, str]] = []

    def lookup(self, name: str, rdtype: str) -> list[str] | None:
        return self.lookups.get((name, rdtype))

    def referral(self, address: str, qname: dns.name.Name) -> Any:
        return self.referrals[address]

    def authoritative(self, address: str, qname: dns.name.Name, rdtype: str) -> Any:
        self.calls.append((address, rdtype))
        return self.answers(address, qname, rdtype)


def good_referrals() -> dict[str, Any]:
    return {address: Referral(EXPECTED_NS, "LHR7") for address in IO.values()}


# delegation


def test_delegation_ok_when_every_answer_is_correct() -> None:
    result = checks.delegation(FakeQuerier(referrals=good_referrals()), CONFIG)  # type: ignore[arg-type]
    assert result == Result("delegation", Status.OK, "a.ns.selectel.ru, b.ns.selectel.ru, c.ns.selectel.ru, d.ns.selectel.ru (4/4 .io servers answered)")


def test_delegation_fails_on_a_wrong_set_nxdomain_or_nodata() -> None:
    referrals = good_referrals()
    referrals[IO["b0.nic.io"]] = Referral(frozenset({"ns1.evil.example"}), "SCL1")
    referrals[IO["c0.nic.io"]] = NotDelegated("the domain does not exist (NXDOMAIN)", "DXB1")
    referrals[IO["a2.nic.io"]] = NotDelegated("the registry has no NS records for the domain", "ASH3")
    result = checks.delegation(FakeQuerier(referrals=referrals), CONFIG)  # type: ignore[arg-type]
    assert result.status is Status.FAIL
    assert "b0.nic.io (65.22.161.17) [SCL1]: delegates to ns1.evil.example" in result.detail
    assert "c0.nic.io (65.22.162.17) [DXB1]: the domain does not exist (NXDOMAIN)" in result.detail
    assert "a2.nic.io (65.22.163.17) [ASH3]: the registry has no NS records for the domain" in result.detail


def test_delegation_ok_with_unreachable_servers_and_shows_the_count() -> None:
    querier = FakeQuerier(referrals=good_referrals())
    querier.referrals[IO["a0.nic.io"]] = Unusable("unreachable")
    querier.lookups[("a2.nic.io", "A")] = None
    result = checks.delegation(querier, CONFIG)  # type: ignore[arg-type]
    assert result.status is Status.OK
    assert result.detail.endswith("(2/4 .io servers answered)")


def test_delegation_unknown_when_no_server_answers_or_the_lookup_fails() -> None:
    silent = {address: Unusable("REFUSED") for address in IO.values()}
    result = checks.delegation(FakeQuerier(referrals=silent), CONFIG)  # type: ignore[arg-type]
    assert result.status is Status.UNKNOWN
    assert result.detail.startswith("no server answered: a0.nic.io (65.22.160.17): REFUSED")

    querier = FakeQuerier()
    querier.lookups[("io.", "NS")] = None
    assert checks.delegation(querier, CONFIG) == Result("delegation", Status.UNKNOWN, "could not look up the io. servers")  # type: ignore[arg-type]


# soa


def test_soa_ok_with_equal_serials_and_32_samples() -> None:
    querier = FakeQuerier(lambda address, qname, rdtype: soa_record(2026111002))
    assert checks.soa(querier, CONFIG) == Result("soa", Status.OK, "serial 2026111002 on 4 addresses")  # type: ignore[arg-type]
    assert len(querier.calls) == 32


def test_soa_fails_when_one_sample_lags_and_names_the_instance() -> None:
    samples = iter([Records(soa_record(2026111001).values, "2-ans-prod-spb")] + [soa_record(2026111002)] * 31)
    result = checks.soa(FakeQuerier(lambda *args: next(samples)), CONFIG)  # type: ignore[arg-type]
    assert result == Result("soa", Status.FAIL, "serials differ: 188.68.203.1 [2-ans-prod-spb] 2026111001, all others 2026111002")


def test_soa_unknown_when_an_address_gives_no_response_and_the_rest_agree() -> None:
    def answers(address: str, qname: dns.name.Name, rdtype: str) -> Any:
        if address == SELECTEL["b.ns.selectel.ru"]:
            return Unusable("unreachable", no_response=True)
        return soa_record(2026111002)

    result = checks.soa(FakeQuerier(answers), CONFIG)  # type: ignore[arg-type]
    assert result == Result("soa", Status.UNKNOWN, "b.ns.selectel.ru (77.223.114.2): unreachable")


def test_soa_unknown_on_a_failed_address_lookup() -> None:
    querier = FakeQuerier(lambda *args: soa_record(2026111002))
    querier.lookups[("d.ns.selectel.ru", "A")] = None
    assert checks.soa(querier, CONFIG) == Result("soa", Status.UNKNOWN, "d.ns.selectel.ru: address lookup failed")  # type: ignore[arg-type]


def test_soa_fails_on_a_received_unusable_answer() -> None:
    def answers(address: str, qname: dns.name.Name, rdtype: str) -> Any:
        if address == SELECTEL["c.ns.selectel.ru"]:
            return Unusable("REFUSED", "7-ans-prod-spb")
        return soa_record(2026111002)

    result = checks.soa(FakeQuerier(answers), CONFIG)  # type: ignore[arg-type]
    assert result == Result("soa", Status.FAIL, "c.ns.selectel.ru (188.68.203.3): REFUSED")


def test_soa_failure_outranks_silence_and_lists_wrong_answers_first() -> None:
    lagging = iter([Records(soa_record(2026111001).values, "2-ans-prod-spb")])

    def answers(address: str, qname: dns.name.Name, rdtype: str) -> Any:
        if address == SELECTEL["b.ns.selectel.ru"]:
            return Unusable("unreachable", no_response=True)
        if address == SELECTEL["c.ns.selectel.ru"]:
            return Records(frozenset(), "7-ans-prod-spb")
        return next(lagging, soa_record(2026111002))

    querier = FakeQuerier(answers)
    querier.lookups[("d.ns.selectel.ru", "A")] = None
    result = checks.soa(querier, CONFIG)  # type: ignore[arg-type]
    assert result == Result("soa", Status.FAIL, "; ".join([
        "c.ns.selectel.ru (188.68.203.3) [7-ans-prod-spb]: 0 SOA records",
        "serials differ: 188.68.203.1 [2-ans-prod-spb] 2026111001, all others 2026111002",
        "d.ns.selectel.ru: address lookup failed",
        "b.ns.selectel.ru (77.223.114.2): unreachable",
    ]))


ANSWERS = {
    "SOA": "a.ns.selectel.ru. support.selectel.ru. 2026111002 10800 3600 604800 60",
    "A": "203.0.113.10",
}


def transport(silent: str) -> Callable[[dns.message.Message, str, float], dns.message.Message]:
    """A transport that times out for one address and answers SOA and A for the rest."""

    def send(query: dns.message.Message, address: str, timeout: float) -> dns.message.Message:
        if address == silent:
            raise dns.exception.Timeout
        question = query.question[0]
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        response.answer.append(dns.rrset.from_text(
            question.name, 300, "IN", dns.rdatatype.to_text(question.rdtype), ANSWERS[dns.rdatatype.to_text(question.rdtype)]))
        return dns.message.from_wire(response.to_wire())

    return send


def real_querier(silent: str) -> Querier:
    addresses = {name: [address] for name, address in SELECTEL.items()}
    return Querier(transport=transport(silent), resolve=lambda name, rdtype: addresses[name], sleep=lambda s: None)


def test_a_timed_out_address_reaches_soa_as_unknown_through_the_real_querier() -> None:
    result = checks.soa(real_querier(SELECTEL["b.ns.selectel.ru"]), CONFIG)
    assert result == Result("soa", Status.UNKNOWN, "b.ns.selectel.ru (77.223.114.2): unreachable")


def test_a_timed_out_address_reaches_records_as_unknown_through_the_real_querier() -> None:
    sets = [r for r in CONFIG.records if r.rtype == "A"]
    assert checks.records(real_querier(SELECTEL["b.ns.selectel.ru"]), CONFIG, sets) == [
        Result("records @ A", Status.UNKNOWN, "77.223.114.2: unreachable")]


def hostile_transport(query: dns.message.Message, address: str, timeout: float) -> dns.message.Message:
    """Answers with a TXT value and an NSID that try to start new message lines."""
    question = query.question[0]
    rtype = dns.rdatatype.to_text(question.rdtype)
    if rtype == "TXT":
        data = r'"v=spf1 -all\010::warning::pwned\013\226\128\168"'
    else:
        serial = 2026111001 if address == SELECTEL["a.ns.selectel.ru"] else 2026111002
        data = f"a.ns.selectel.ru. support.selectel.ru. {serial} 10800 3600 604800 60"
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA
    response.answer.append(dns.rrset.from_text(question.name, 300, "IN", rtype, data))
    response.use_edns(0, options=[dns.edns.NSIDOption(b"evil\n::error::x\r")])
    return dns.message.from_wire(response.to_wire())


def test_hostile_dns_text_never_starts_a_new_message_line() -> None:
    addresses = {name: [address] for name, address in SELECTEL.items()}
    querier = Querier(transport=hostile_transport, resolve=lambda name, rdtype: addresses[name], sleep=lambda s: None)
    txt = [r for r in CONFIG.records if r.rtype == "TXT"]
    results = [checks.soa(querier, CONFIG), *checks.records(querier, CONFIG, txt)]
    assert [r.status for r in results] == [Status.FAIL, Status.FAIL]

    lines = change_lines([Change(Status.OK, NOW, r) for r in results], NOW)
    text = "\n".join(lines)
    assert len(text.splitlines()) == len(lines) == 2
    assert not any(line.lstrip().startswith("::") for line in text.splitlines())
    assert "[evil\\n::error::x\\r]" in text
    assert '"v=spf1 -all\\n::warning::pwned\\r\\u2028"' in text


# expiry

NOW = datetime.datetime(2026, 11, 11, 12, 0, tzinfo=datetime.UTC)


LIVE_STATUS = ["client delete prohibited", "client transfer prohibited"]
MISSING = object()


def rdap(events: list[dict[str, str]], ldh_name: str = "iskri.io", status: object = LIVE_STATUS) -> Callable[[str], bytes]:
    def fetch(url: str) -> bytes:
        assert url == "https://rdap.example/rdap/domain/iskri.io"
        data: dict[str, object] = {"ldhName": ldh_name, "events": events}
        if status is not MISSING:
            data["status"] = status
        return json.dumps(data).encode()
    return fetch


def expiration(date: str) -> list[dict[str, str]]:
    return [{"eventAction": "registration", "eventDate": "2026-11-10T09:43:44.556Z"},
            {"eventAction": "expiration", "eventDate": date}]


def test_expiry_ok_shows_date_and_days_left() -> None:
    result = checks.expiry(CONFIG, NOW, rdap(expiration("2027-11-10T09:43:44.556Z")))
    assert result == Result("expiry", Status.OK, "expires 2027-11-10, 363 days left")


def test_expiry_boundary_is_exact() -> None:
    exactly = (NOW + datetime.timedelta(days=30)).isoformat()
    just_under = (NOW + datetime.timedelta(days=30) - datetime.timedelta(seconds=1)).isoformat()
    assert checks.expiry(CONFIG, NOW, rdap(expiration(exactly))).status is Status.OK
    assert checks.expiry(CONFIG, NOW, rdap(expiration(just_under))) == Result(
        "expiry", Status.FAIL, "expires 2026-12-11, 29 days left, minimum 30")


def test_expiry_fails_after_expiration() -> None:
    result = checks.expiry(CONFIG, NOW, rdap(expiration("2026-11-01T00:00:00Z")))
    assert result == Result("expiry", Status.FAIL, "expired on 2026-11-01")


def test_expiry_accepts_an_uppercase_ldh_name_and_a_trailing_slashless_base() -> None:
    config = Config(CONFIG.domain, CONFIG.nameservers, "https://rdap.example/rdap", 30, ())
    assert checks.expiry(config, NOW, rdap(expiration("2027-11-10T09:43:44Z"), "ISKRI.IO")).status is Status.OK


@pytest.mark.parametrize(
    ("fetch", "detail"),
    [
        (lambda url: (_ for _ in ()).throw(RdapError("HTTP 503")), "RDAP: HTTP 503"),
        (lambda url: b"<html>", "RDAP: the response is not valid JSON"),
        (lambda url: b"[]", "RDAP: the response is not a JSON object"),
        (rdap(expiration("2027-11-10T09:43:44Z"), "other.io"), "RDAP: the response is for 'other.io', not iskri.io"),
        (rdap(expiration("2027-11-10T09:43:44Z"), "iskri.io."), "RDAP: the response is for 'iskri.io.', not iskri.io"),
        (rdap(expiration("2027-11-10T09:43:44Z"), "iskri.io..."), "RDAP: the response is for 'iskri.io...'"),
        (rdap([]), "RDAP: expected one expiration event, found 0"),
        (rdap(expiration("2027-11-10T00:00:00Z") + expiration("2028-11-10T00:00:00Z")[1:]), "found 2"),
        (rdap(expiration("next year")), "RDAP: cannot parse the expiration date 'next year'"),
        (rdap(expiration("2027-11-10T09:43:44")), "has no time zone"),
    ],
)
def test_expiry_unknown_cases(fetch: Callable[[str], bytes], detail: str) -> None:
    result = checks.expiry(CONFIG, NOW, fetch)
    assert result.status is Status.UNKNOWN
    assert detail in result.detail


AUTO_RENEWED = "auto-renewed by the registry, confirm the renewal is paid at the registrar"


@pytest.mark.parametrize("status", [["auto renew period"], ["client transfer prohibited", "autoRenewPeriod"]])
def test_expiry_fails_on_an_auto_renewal_even_a_year_ahead(status: list[str]) -> None:
    result = checks.expiry(CONFIG, NOW, rdap(expiration("2027-11-10T09:43:44Z"), status=status))
    assert result == Result("expiry", Status.FAIL, f"{AUTO_RENEWED} (expires 2027-11-10, 363 days left)")


@pytest.mark.parametrize("status", [MISSING, "ok", [], ["active", 1], None])
def test_expiry_unknown_on_a_missing_empty_or_malformed_status_array(status: object) -> None:
    result = checks.expiry(CONFIG, NOW, rdap(expiration("2027-11-10T09:43:44Z"), status=status))
    assert result == Result("expiry", Status.UNKNOWN, "RDAP: missing, empty or malformed status array")


@pytest.mark.parametrize("status", [["auto renew period", 1], ["autoRenewPeriod", None]])
def test_a_malformed_neighbor_does_not_hide_an_auto_renewal(status: list[object]) -> None:
    result = checks.expiry(CONFIG, NOW, rdap(expiration("2027-11-10T09:43:44Z"), status=status))
    assert result == Result("expiry", Status.FAIL, "; ".join([
        f"{AUTO_RENEWED} (expires 2027-11-10, 363 days left)", "RDAP: missing, empty or malformed status array"]))


def test_a_confirmed_expiry_problem_outranks_an_unreadable_part() -> None:
    expired = checks.expiry(CONFIG, NOW, rdap(expiration("2026-11-01T00:00:00Z"), status=MISSING))
    assert expired == Result("expiry", Status.FAIL, "expired on 2026-11-01; RDAP: missing, empty or malformed status array")
    renewed = checks.expiry(CONFIG, NOW, rdap(expiration("next year"), status=["auto renew period"]))
    assert renewed == Result("expiry", Status.FAIL, f"{AUTO_RENEWED}; RDAP: cannot parse the expiration date 'next year'")


def test_a_response_for_another_domain_stays_unknown_before_anything_else() -> None:
    result = checks.expiry(CONFIG, NOW, rdap(expiration("2026-11-01T00:00:00Z"), "other.io", ["auto renew period"]))
    assert result.status is Status.UNKNOWN


class FakeResponse(io.BytesIO):
    status = 200


def test_fetch_rdap_sends_its_own_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[urllib.request.Request] = []

    def urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        seen.append(request)
        return FakeResponse(b"{}")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    assert checks.fetch_rdap("https://rdap.example/rdap/domain/iskri.io") == b"{}"
    assert seen[0].get_header("User-agent") == "rdap-client/1.0"
    assert seen[0].get_header("Accept") == "application/rdap+json"


def test_fetch_rdap_errors_never_carry_exception_text(monkeypatch: pytest.MonkeyPatch) -> None:
    errors: list[Exception] = [
        urllib.error.URLError("secret-token-in-reason"),
        TimeoutError("secret-token"),
        urllib.error.HTTPError("https://x/secret-token", 503, "secret-token", email.message.Message(), None),
    ]

    def urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        raise errors.pop(0)

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    sleeps: list[float] = []
    with pytest.raises(RdapError) as excinfo:
        checks.fetch_rdap("https://rdap.example/rdap/domain/iskri.io", sleep=sleeps.append)
    assert str(excinfo.value) == "HTTP 503"
    assert sleeps == [1.0, 1.0]


# records


def by_type(table: dict[str, Any]) -> Answer:
    return lambda address, qname, rdtype: table[rdtype](address) if callable(table[rdtype]) else table[rdtype]


def test_records_ok_when_every_address_matches() -> None:
    answers = by_type({
        "A": Records(frozenset({rdata("A", "203.0.113.10")}), "6-ans-prod-spb"),
        "AAAA": Records(frozenset(), "6-ans-prod-spb"),
        "TXT": Records(frozenset({b"v=spf1 -all"}), "6-ans-prod-spb"),
    })
    results = checks.records(FakeQuerier(answers), CONFIG, CONFIG.records)  # type: ignore[arg-type]
    assert [(r.key, r.status) for r in results] == [
        ("records @ A", Status.OK), ("records @ AAAA", Status.OK), ("records @ TXT", Status.OK)]


def test_records_merge_identical_differences_into_one_line() -> None:
    answers = by_type({"TXT": Records(frozenset({b"v=spf1 +all"}), "6-ans-prod-spb")})
    sets = [r for r in CONFIG.records if r.rtype == "TXT"]
    assert checks.records(FakeQuerier(answers), CONFIG, sets) == [  # type: ignore[arg-type]
        Result("records @ TXT", Status.FAIL, 'all addresses: missing "v=spf1 -all", unexpected "v=spf1 +all"')]


def test_records_report_each_address_when_they_differ() -> None:
    def aaaa(address: str) -> Any:
        if address == SELECTEL["a.ns.selectel.ru"]:
            return Records(frozenset({rdata("AAAA", "2001:db8::1")}), "8-ans-prod-spb")
        if address == SELECTEL["b.ns.selectel.ru"]:
            return Unusable("REFUSED", "5-ans-prod-spb")
        return Records(frozenset(), "6-ans-prod-spb")

    sets = [r for r in CONFIG.records if r.rtype == "AAAA"]
    assert checks.records(FakeQuerier(by_type({"AAAA": aaaa})), CONFIG, sets) == [  # type: ignore[arg-type]
        Result("records @ AAAA", Status.FAIL, "77.223.114.2: REFUSED; 188.68.203.1 [8-ans-prod-spb]: unexpected 2001:db8::1")]


def test_records_unknown_on_a_failed_address_lookup() -> None:
    querier = FakeQuerier(by_type({"A": Records(frozenset({rdata("A", "203.0.113.10")}), "6-ans-prod-spb")}))
    querier.lookups[("c.ns.selectel.ru", "A")] = None
    sets = [r for r in CONFIG.records if r.rtype == "A"]
    assert checks.records(querier, CONFIG, sets) == [  # type: ignore[arg-type]
        Result("records @ A", Status.UNKNOWN, "c.ns.selectel.ru: address lookup failed")]


def test_records_unknown_when_an_address_gives_no_response_and_the_rest_match() -> None:
    def a_answer(address: str) -> Any:
        if address == SELECTEL["d.ns.selectel.ru"]:
            return Unusable("transport error: ConnectionResetError", no_response=True)
        return Records(frozenset({rdata("A", "203.0.113.10")}), "6-ans-prod-spb")

    sets = [r for r in CONFIG.records if r.rtype == "A"]
    assert checks.records(FakeQuerier(by_type({"A": a_answer})), CONFIG, sets) == [  # type: ignore[arg-type]
        Result("records @ A", Status.UNKNOWN, "77.223.114.4: transport error: ConnectionResetError")]


def test_records_mismatch_outranks_silence() -> None:
    def a_answer(address: str) -> Any:
        if address == SELECTEL["d.ns.selectel.ru"]:
            return Unusable("unreachable", no_response=True)
        if address == SELECTEL["a.ns.selectel.ru"]:
            return Records(frozenset({rdata("A", "198.51.100.7")}), "8-ans-prod-spb")
        return Records(frozenset({rdata("A", "203.0.113.10")}), "6-ans-prod-spb")

    sets = [r for r in CONFIG.records if r.rtype == "A"]
    assert checks.records(FakeQuerier(by_type({"A": a_answer})), CONFIG, sets) == [  # type: ignore[arg-type]
        Result("records @ A", Status.FAIL,
               "188.68.203.1 [8-ans-prod-spb]: missing 203.0.113.10, unexpected 198.51.100.7; 77.223.114.4: unreachable")]
