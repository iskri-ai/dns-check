"""Load and validate expected.yaml.

Any problem raises ConfigError, and the run aborts before the first
query. Messages quote only config content.
"""

import dataclasses
from pathlib import Path
from typing import Any

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import yaml
from dns.rdtypes.txtbase import TXTBase

SUPPORTED_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "CAA")

type RecordValue = dns.rdata.Rdata | bytes
"""A comparable record value: rdata for most types, joined bytes for TXT."""


class ConfigError(Exception):
    """expected.yaml is invalid."""


@dataclasses.dataclass(frozen=True)
class RecordSet:
    """The expected records for one name and type."""

    name: str
    """Lowercased relative name, "@" for the apex."""
    rtype: str
    qname: dns.name.Name
    expected: frozenset[RecordValue]

    @property
    def key(self) -> str:
        return f"records {self.name} {self.rtype}"


@dataclasses.dataclass(frozen=True)
class Config:
    domain: str
    nameservers: tuple[str, ...]
    rdap_base_url: str
    min_days_left: int
    records: tuple[RecordSet, ...]


def record_value(rdata: dns.rdata.Rdata) -> RecordValue:
    """Return the comparable value of a record from an answer.

    TXT compares as the joined bytes of its strings, because how a
    server splits a long value into strings does not matter.
    """
    if isinstance(rdata, TXTBase):
        return b"".join(rdata.strings)
    return rdata


def load_file(path: Path) -> Config:
    return load(path.read_text(encoding="utf-8"))


def load(text: str) -> Config:
    try:
        raw = yaml.load(text, Loader=_Loader)
    except yaml.YAMLError as exc:
        raise ConfigError(f"not valid YAML: {exc}") from exc

    _keys(raw, "root", ("domain", "nameservers", "expiry", "records"))
    _keys(raw["expiry"], "expiry", ("rdap_base_url", "min_days_left"))

    domain = _string(raw["domain"], "domain").lower().rstrip(".")
    origin = _name(domain, "domain")

    nameservers = raw["nameservers"]
    _need(isinstance(nameservers, list) and nameservers, "nameservers: expected a non-empty list")
    ns_names = tuple(_string(ns, "nameservers").lower().rstrip(".") for ns in nameservers)
    for ns in ns_names:
        _name(ns, "nameservers")

    days = raw["expiry"]["min_days_left"]
    _need(type(days) is int and days > 0, "expiry.min_days_left: expected a positive integer")

    return Config(
        domain=domain,
        nameservers=ns_names,
        rdap_base_url=_string(raw["expiry"]["rdap_base_url"], "expiry.rdap_base_url"),
        min_days_left=days,
        records=_records(raw["records"], domain, origin),
    )


def _records(raw: Any, domain: str, origin: dns.name.Name) -> tuple[RecordSet, ...]:
    _need(isinstance(raw, dict), "records: expected a mapping")
    result: list[RecordSet] = []
    seen: dict[str, str] = {}
    for name, types in raw.items():
        _need(isinstance(name, str) and name, f"records: name {name!r} must be a non-empty string")
        lowered = name.lower()
        _need(
            not (lowered.endswith(".") or lowered == domain or lowered.endswith("." + domain)),
            f'records: "{name}" must be relative to {domain}, such as "old", or "@" for the apex',
        )
        _need(lowered not in seen, f'records: "{seen.get(lowered)}" and "{name}" are the same name')
        seen[lowered] = name
        qname = _name(lowered, f'records: "{name}"', origin)

        where = f'records."{name}"'
        _need(isinstance(types, dict) and types, f"{where}: expected a mapping of types")
        for rtype, value in types.items():
            _need(
                rtype in SUPPORTED_TYPES,
                f"{where}: unsupported type {rtype!r}, use one of {', '.join(SUPPORTED_TYPES)}",
            )
            values = [value] if isinstance(value, str) else value
            _need(
                isinstance(values, list) and all(isinstance(v, str) for v in values),
                f"{where}.{rtype}: expected a string or a list of strings",
            )
            expected = frozenset(_value(rtype, v, f"{where}.{rtype}") for v in values)
            if rtype == "CNAME" and expected:
                _need(len(types) == 1, f"{where}: a CNAME must be the only type at its name")
                _need(len(expected) == 1, f"{where}: a name can hold only one CNAME")
            result.append(RecordSet(lowered, rtype, qname, expected))
    return tuple(sorted(result, key=lambda r: (r.name, r.rtype)))


def _value(rtype: str, text: str, where: str) -> RecordValue:
    if rtype == "TXT":
        return text.encode("utf-8")
    try:
        # Origin root: names inside values are always absolute.
        return dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.from_text(rtype), text, origin=dns.name.root
        )
    except (dns.exception.DNSException, ValueError) as exc:
        raise ConfigError(f"{where}: cannot parse {text!r} as {rtype}") from exc


def _name(text: str, where: str, origin: dns.name.Name | None = None) -> dns.name.Name:
    try:
        return dns.name.from_text(text, origin=origin or dns.name.root)
    except (dns.exception.DNSException, ValueError) as exc:
        raise ConfigError(f"{where}: {text!r} is not a valid DNS name") from exc


def _need(ok: object, message: str) -> None:
    if not ok:
        raise ConfigError(message)


def _keys(obj: Any, where: str, required: tuple[str, ...]) -> None:
    _need(isinstance(obj, dict), f"{where}: expected a mapping")
    missing = set(required) - set(obj)
    _need(not missing, f"{where}: missing {', '.join(sorted(missing))}")
    unknown = set(obj) - set(required)
    _need(not unknown, f"{where}: unknown keys {', '.join(sorted(map(str, unknown)))}")


def _string(value: Any, where: str) -> str:
    _need(isinstance(value, str) and value, f"{where}: expected a non-empty string")
    return str(value)


class _Loader(yaml.SafeLoader):
    """A SafeLoader that rejects duplicate keys instead of keeping the last one."""


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in result:
            raise ConfigError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
