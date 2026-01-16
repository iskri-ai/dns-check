"""Send DNS queries and classify the responses.

A Querier serves one pass. Within a pass, an address that times out on
every try is dead: its later queries are skipped and reported as
unreachable, so a dead address costs one query's retries per pass.
"""

import dataclasses
import time
from collections.abc import Callable

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
from dns.rdtypes.ANY.NS import NS

from dnscheck.config import RecordValue, record_value

TRIES = 3
TIMEOUT = 5.0
PAUSE = 0.25
LOOKUP_LIFETIME = TRIES * TIMEOUT
UNREACHABLE = "unreachable"

type Transport = Callable[[dns.message.Message, str, float], dns.message.Message]
"""Send a query to an address and return the response. Raises on timeout."""
type Resolve = Callable[[str, str], list[str]]
"""Look up a name and type with the runner's resolver."""


@dataclasses.dataclass(frozen=True)
class Records:
    """A usable authoritative answer. Empty values mean "no records"."""

    values: frozenset[RecordValue]
    nsid: str


@dataclasses.dataclass(frozen=True)
class Referral:
    """A TLD referral with the delegated nameserver names."""

    nameservers: frozenset[str]
    nsid: str


@dataclasses.dataclass(frozen=True)
class NotDelegated:
    """The TLD says authoritatively that the domain doesn't exist."""

    nsid: str


@dataclasses.dataclass(frozen=True)
class Unusable:
    """No usable answer from this address."""

    reason: str
    nsid: str = "-"
    no_response: bool = False
    """No response arrived at all, so the address says nothing about the zone."""


def udp_with_tcp_fallback(
    query: dns.message.Message, address: str, timeout: float
) -> dns.message.Message:
    response, _ = dns.query.udp_with_fallback(query, address, timeout=timeout)
    return response


def system_resolve(name: str, rdtype: str) -> list[str]:
    answer = dns.resolver.resolve(name, rdtype, lifetime=LOOKUP_LIFETIME, search=False)
    return sorted(rdata.to_text().lower().rstrip(".") for rdata in answer)


class Querier:
    def __init__(
        self,
        transport: Transport = udp_with_tcp_fallback,
        resolve: Resolve = system_resolve,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._transport = transport
        self._resolve = resolve
        self._sleep = sleep
        self._dead: set[str] = set()
        self._lookups: dict[tuple[str, str], list[str] | None] = {}

    def lookup(self, name: str, rdtype: str) -> list[str] | None:
        """Return names or addresses for name, or None if the lookup failed.

        Results are cached for the pass, so the re-check pass looks up again.
        """
        key = (name, rdtype)
        if key not in self._lookups:
            try:
                self._lookups[key] = self._resolve(name, rdtype) or None
            except dns.exception.DNSException:
                self._lookups[key] = None
        return self._lookups[key]

    def authoritative(
        self, address: str, qname: dns.name.Name, rdtype: str
    ) -> Records | Unusable:
        """Query an authoritative server and classify the response."""
        response = self._send(address, qname, rdtype)
        if isinstance(response, Unusable):
            return response
        nsid = _nsid(response)
        rcode = response.rcode()
        if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            return Unusable(dns.rcode.to_text(rcode), nsid)
        if not response.flags & dns.flags.AA:
            return Unusable("no AA flag", nsid)
        wanted = dns.rdatatype.from_text(rdtype)
        for rrset in response.answer:
            if (
                rcode == dns.rcode.NXDOMAIN
                or rrset.name != qname
                or rrset.rdtype != wanted
                or rrset.rdclass != dns.rdataclass.IN
            ):
                return Unusable(f"unexpected answer: {_text(response.answer)}", nsid)
        return Records(
            frozenset(record_value(rdata) for rrset in response.answer for rdata in rrset), nsid
        )

    def referral(
        self, address: str, qname: dns.name.Name
    ) -> Referral | NotDelegated | Unusable:
        """Ask a TLD server for the delegation of qname."""
        response = self._send(address, qname, "NS")
        if isinstance(response, Unusable):
            return response
        nsid = _nsid(response)
        rcode = response.rcode()
        if rcode == dns.rcode.NXDOMAIN and response.flags & dns.flags.AA:
            return NotDelegated(nsid)
        if rcode != dns.rcode.NOERROR:
            return Unusable(dns.rcode.to_text(rcode), nsid)
        if response.answer:
            return Unusable(f"unexpected answer: {_text(response.answer)}", nsid)
        ns_sets = [
            rrset
            for rrset in response.authority
            if rrset.name == qname
            and rrset.rdtype == dns.rdatatype.NS
            and rrset.rdclass == dns.rdataclass.IN
        ]
        if len(ns_sets) != 1:
            return Unusable("no NS records for the domain in the referral", nsid)
        names = frozenset(
            str(rdata.target).lower().rstrip(".") for rdata in ns_sets[0] if isinstance(rdata, NS)
        )
        return Referral(names, nsid)

    def _send(
        self, address: str, qname: dns.name.Name, rdtype: str
    ) -> dns.message.Message | Unusable:
        if address in self._dead:
            return Unusable(UNREACHABLE, no_response=True)
        query = dns.message.make_query(
            qname,
            rdtype,
            use_edns=0,
            options=[dns.edns.GenericOption(dns.edns.OptionType.NSID, b"")],
        )
        query.flags &= ~dns.flags.RD
        timeouts = 0
        reason = UNREACHABLE
        for _ in range(TRIES):
            try:
                response = self._transport(query, address, TIMEOUT)
                # reject incomplete answers after the TCP retry
                if response.flags & dns.flags.TC:
                    return Unusable("truncated response", _nsid(response))
                return response
            except dns.exception.Timeout:
                timeouts += 1
            except (dns.exception.DNSException, OSError) as exc:
                reason = f"transport error: {type(exc).__name__}"
            finally:
                self._sleep(PAUSE)
        if timeouts == TRIES:
            self._dead.add(address)
        return Unusable(reason, no_response=True)


def _nsid(response: dns.message.Message) -> str:
    for option in response.options:
        if isinstance(option, dns.edns.NSIDOption):
            return option.nsid.decode("ascii", errors="replace") or "-"
    return "-"


def _text(rrsets: list[dns.rrset.RRset]) -> str:
    return "; ".join(line for rrset in rrsets for line in rrset.to_text().splitlines())
