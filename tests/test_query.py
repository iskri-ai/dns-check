from collections.abc import Callable

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.resolver
import dns.rrset

from dnscheck.config import RecordValue, record_value
from dnscheck.query import (
    QUERY_PAUSE,
    TIMEOUT,
    UNREACHABLE,
    NotDelegated,
    Querier,
    Records,
    Referral,
    Unusable,
    printable,
)

QNAME = dns.name.from_text("iskri.io.")
WWW = dns.name.from_text("www.iskri.io.")

type Outcome = (
    type[BaseException] | BaseException | Callable[[dns.message.Message], dns.message.Message]
)


def respond(
    *,
    rcode: dns.rcode.Rcode = dns.rcode.NOERROR,
    aa: bool = True,
    tc: bool = False,
    answer: tuple[tuple[str, str, str], ...] = (),
    authority: tuple[tuple[str, str, str], ...] = (),
    nsid: bytes = b"5-ans-prod-spb",
) -> Callable[[dns.message.Message], dns.message.Message]:
    """Build a response the way a server sends it: encoded and decoded."""

    def build(query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.set_rcode(rcode)
        if aa:
            response.flags |= dns.flags.AA
        if tc:
            response.flags |= dns.flags.TC
        for owner, rtype, data in answer:
            response.answer.append(dns.rrset.from_text(owner, 300, "IN", rtype, *data.split("|")))
        for owner, rtype, data in authority:
            response.authority.append(
                dns.rrset.from_text(owner, 300, "IN", rtype, *data.split("|"))
            )
        response.use_edns(0, options=[dns.edns.NSIDOption(nsid)] if nsid else [])
        return dns.message.from_wire(response.to_wire())

    return build


class FakeTransport:
    def __init__(self, *outcomes: Outcome) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[dns.message.Message, str, float]] = []

    def __call__(
        self, query: dns.message.Message, address: str, timeout: float
    ) -> dns.message.Message:
        self.calls.append((query, address, timeout))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, (type, BaseException)):
            raise outcome
        return outcome(query)


def querier(*outcomes: Outcome) -> tuple[Querier, FakeTransport, list[float]]:
    transport = FakeTransport(*outcomes)
    sleeps: list[float] = []
    return (
        Querier(transport=transport, resolve=lambda n, t: [], sleep=sleeps.append),
        transport,
        sleeps,
    )


def a_record(text: str) -> RecordValue:
    return record_value(
        respond(answer=(("iskri.io.", "A", text),))(dns.message.make_query(QNAME, "A")).answer[0][0]
    )


def test_query_has_rd_cleared_edns_with_nsid_and_no_do() -> None:
    q, transport, _ = querier(respond(answer=(("iskri.io.", "A", "203.0.113.10"),)))
    q.authoritative("192.0.2.1", QNAME, "A")
    query, address, timeout = transport.calls[0]
    assert address == "192.0.2.1"
    assert timeout == TIMEOUT
    assert not query.flags & dns.flags.RD
    assert query.edns == 0
    assert not query.ednsflags & dns.flags.DO
    assert [o.otype for o in query.options] == [dns.edns.OptionType.NSID]


def test_matching_answer_gives_the_record_set_and_nsid() -> None:
    q, _, _ = querier(respond(answer=(("iskri.io.", "A", "203.0.113.10|198.51.100.7"),)))
    result = q.authoritative("192.0.2.1", QNAME, "A")
    assert result == Records(
        frozenset({a_record("203.0.113.10"), a_record("198.51.100.7")}), "5-ans-prod-spb"
    )


def test_txt_strings_are_joined() -> None:
    q, _, _ = querier(respond(answer=(("iskri.io.", "TXT", '"v=DKIM1; p=MIGf" "MA0GCSq"'),)))
    assert q.authoritative("192.0.2.1", QNAME, "TXT") == Records(
        frozenset({b"v=DKIM1; p=MIGfMA0GCSq"}), "5-ans-prod-spb"
    )


def test_nodata_and_nxdomain_with_aa_mean_no_records() -> None:
    q, _, _ = querier(respond(), respond(rcode=dns.rcode.NXDOMAIN))
    assert q.authoritative("192.0.2.1", QNAME, "AAAA") == Records(frozenset(), "5-ans-prod-spb")
    assert q.authoritative("192.0.2.1", WWW, "A") == Records(frozenset(), "5-ans-prod-spb")


def test_missing_nsid_shows_a_dash() -> None:
    q, _, _ = querier(respond(nsid=b""))
    assert q.authoritative("192.0.2.1", QNAME, "AAAA") == Records(frozenset(), "-")


def test_unusable_responses() -> None:
    cname = (("www.iskri.io.", "CNAME", "target.example.net."),)
    cases: list[tuple[Outcome, dns.name.Name, str, str]] = [
        (respond(rcode=dns.rcode.REFUSED, aa=False), QNAME, "A", "REFUSED"),
        (respond(rcode=dns.rcode.SERVFAIL), QNAME, "A", "SERVFAIL"),
        (respond(aa=False), QNAME, "A", "no AA flag"),
        (respond(rcode=dns.rcode.NXDOMAIN, aa=False), WWW, "A", "no AA flag"),
        (
            respond(answer=cname),
            WWW,
            "A",
            "unexpected answer: www.iskri.io. 300 IN CNAME target.example.net.",
        ),
        (respond(rcode=dns.rcode.NXDOMAIN, answer=cname), WWW, "A", "unexpected answer"),
        (
            respond(answer=(("other.iskri.io.", "A", "203.0.113.10"),)),
            WWW,
            "A",
            "unexpected answer",
        ),
    ]
    for outcome, qname, rtype, reason in cases:
        q, _, _ = querier(outcome)
        result = q.authoritative("192.0.2.1", qname, rtype)
        assert isinstance(result, Unusable), (reason, result)
        assert result.reason.startswith(reason), (reason, result)


def test_a_final_response_that_is_still_truncated_is_unusable() -> None:
    q, _, _ = querier(respond(tc=True), respond(aa=False, tc=True))
    assert q.authoritative("192.0.2.1", QNAME, "AAAA") == Unusable(
        "truncated response", "5-ans-prod-spb"
    )
    assert q.referral("192.0.2.1", QNAME) == Unusable("truncated response", "5-ans-prod-spb")


def test_timeouts_are_retried_and_every_try_is_paced() -> None:
    q, transport, sleeps = querier(
        dns.exception.Timeout,
        dns.exception.Timeout,
        respond(answer=(("iskri.io.", "A", "203.0.113.10"),)),
    )
    assert isinstance(q.authoritative("192.0.2.1", QNAME, "A"), Records)
    assert len(transport.calls) == 3
    assert sleeps == [QUERY_PAUSE] * 3


def test_a_successful_query_is_paced_too() -> None:
    q, _, sleeps = querier(respond())
    assert isinstance(q.authoritative("192.0.2.1", QNAME, "A"), Records)
    assert sleeps == [QUERY_PAUSE]


def test_an_address_that_times_out_on_every_try_is_dead_for_the_pass() -> None:
    q, transport, sleeps = querier(
        dns.exception.Timeout,
        dns.exception.Timeout,
        dns.exception.Timeout,
        respond(answer=(("iskri.io.", "A", "203.0.113.10"),)),
    )
    assert q.authoritative("192.0.2.1", QNAME, "A") == Unusable(UNREACHABLE, no_response=True)
    assert q.authoritative("192.0.2.1", QNAME, "SOA") == Unusable(UNREACHABLE, no_response=True)
    assert len(transport.calls) == 3
    assert sleeps == [QUERY_PAUSE] * 3
    assert isinstance(q.authoritative("192.0.2.2", QNAME, "A"), Records)


def test_refused_and_transport_errors_do_not_mark_the_address_dead() -> None:
    q, transport, _ = querier(
        respond(rcode=dns.rcode.REFUSED, aa=False),
        ConnectionRefusedError(),
        ConnectionRefusedError(),
        ConnectionRefusedError(),
        respond(),
    )
    assert q.authoritative("192.0.2.1", QNAME, "A") == Unusable("REFUSED", "5-ans-prod-spb")
    assert q.authoritative("192.0.2.1", QNAME, "A") == Unusable(
        "transport error: ConnectionRefusedError", no_response=True
    )
    assert q.authoritative("192.0.2.1", QNAME, "AAAA") == Records(frozenset(), "5-ans-prod-spb")
    assert len(transport.calls) == 5


def test_no_response_flag_is_set_only_when_nothing_arrived() -> None:
    timeouts: list[Outcome] = [dns.exception.Timeout] * 3
    no_response: list[list[Outcome]] = [
        timeouts,
        [OSError] * 3,
        [EOFError] * 3,
        [dns.exception.Timeout, OSError, dns.exception.Timeout],
    ]
    for outcomes in no_response:
        result = querier(*outcomes)[0].authoritative("192.0.2.1", QNAME, "A")
        assert isinstance(result, Unusable) and result.no_response, outcomes

    dead, _, _ = querier(*timeouts)
    dead.authoritative("192.0.2.1", QNAME, "A")
    assert dead.authoritative("192.0.2.1", QNAME, "SOA") == Unusable(UNREACHABLE, no_response=True)

    answered: list[Outcome] = [
        respond(rcode=dns.rcode.REFUSED, aa=False),
        respond(rcode=dns.rcode.SERVFAIL),
        respond(aa=False),
        respond(tc=True),
        respond(answer=(("www.iskri.io.", "CNAME", "target.example.net."),)),
    ]
    for outcome in answered:
        result = querier(outcome)[0].authoritative("192.0.2.1", WWW, "A")
        assert isinstance(result, Unusable) and not result.no_response, result


def test_a_tcp_answer_cut_off_mid_read_counts_as_no_response() -> None:
    q, transport, _ = querier(EOFError, EOFError, EOFError, respond())
    assert q.authoritative("192.0.2.1", QNAME, "A") == Unusable(
        "transport error: EOFError", no_response=True
    )
    assert q.authoritative("192.0.2.1", QNAME, "AAAA") == Records(frozenset(), "5-ans-prod-spb")
    assert len(transport.calls) == 4


def test_printable_escapes_backslashes_and_everything_non_printable() -> None:
    assert printable("a b é") == "a b é"
    assert printable("x\ny\r\x1b[31m") == "x\\ny\\r\\x1b[31m"
    assert printable("\x85\u2028\u2029\u202e\t") == "\\x85\\u2028\\u2029\\u202e\\t"
    assert printable("a\\nb") == "a\\\\nb"


def test_a_hostile_nsid_is_escaped() -> None:
    q, _, _ = querier(respond(nsid=b"5-ans\n::warning::x\x1b"))
    assert q.authoritative("192.0.2.1", QNAME, "AAAA") == Records(
        frozenset(), "5-ans\\n::warning::x\\x1b"
    )


def test_an_unexpected_answer_keeps_dnspython_escaping() -> None:
    uri = (("www.iskri.io.", "URI", '10 1 "ftp://x/\\010::warning::uri"'),)
    result = querier(respond(answer=uri))[0].authoritative("192.0.2.1", WWW, "A")
    assert isinstance(result, Unusable)
    assert result.reason.startswith("unexpected answer: ")
    assert len(result.reason.splitlines()) == 1


def test_a_referral_gives_the_delegated_names() -> None:
    q, _, _ = querier(
        respond(aa=False, authority=(("iskri.io.", "NS", "A.ns.selectel.ru.|b.ns.selectel.ru."),))
    )
    assert q.referral("192.0.2.1", QNAME) == Referral(
        frozenset({"a.ns.selectel.ru", "b.ns.selectel.ru"}), "5-ans-prod-spb"
    )


IO_SOA = (("io.", "SOA", "a0.nic.io. hostmaster.example. 1 2 3 4 5"),)


def test_referral_classification() -> None:
    nxdomain = querier(respond(rcode=dns.rcode.NXDOMAIN, authority=IO_SOA))[0].referral(
        "192.0.2.1", QNAME
    )
    assert nxdomain == NotDelegated("the domain does not exist (NXDOMAIN)", "5-ans-prod-spb")
    nodata = querier(respond(authority=IO_SOA))[0].referral("192.0.2.1", QNAME)
    assert nodata == NotDelegated("the registry has no NS records for the domain", "5-ans-prod-spb")
    cases: list[tuple[Outcome, str]] = [
        (respond(rcode=dns.rcode.NXDOMAIN, aa=False), "NXDOMAIN"),
        (respond(rcode=dns.rcode.REFUSED, aa=False), "REFUSED"),
        (respond(answer=(("iskri.io.", "NS", "a.ns.selectel.ru."),)), "unexpected answer"),
        (respond(aa=False, authority=IO_SOA), "no NS records"),
    ]
    for outcome, reason in cases:
        result = querier(outcome)[0].referral("192.0.2.1", QNAME)
        assert isinstance(result, Unusable) and result.reason.startswith(reason), (reason, result)


def test_lookups_are_cached_per_pass_and_failures_give_none() -> None:
    calls: list[tuple[str, str]] = []

    def resolve(name: str, rdtype: str) -> list[str]:
        calls.append((name, rdtype))
        if name == "missing.example":
            raise dns.resolver.NXDOMAIN
        return [] if name == "empty.example" else ["188.68.203.1"]

    q = Querier(transport=FakeTransport(), resolve=resolve, sleep=lambda s: None)
    assert q.lookup("a.ns.selectel.ru", "A") == ["188.68.203.1"]
    assert q.lookup("a.ns.selectel.ru", "A") == ["188.68.203.1"]
    assert q.lookup("missing.example", "A") is None
    assert q.lookup("empty.example", "A") is None
    assert calls == [("a.ns.selectel.ru", "A"), ("missing.example", "A"), ("empty.example", "A")]
