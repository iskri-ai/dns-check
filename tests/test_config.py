from pathlib import Path

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest

from dnscheck.config import ConfigError, load, load_file, record_value

HEAD = """\
domain: iskri.io
nameservers: [a.ns.selectel.ru, B.NS.Selectel.ru.]
expiry:
  rdap_base_url: https://rdap.example/rdap/
  min_days_left: 30
"""

GOOD = HEAD + """\
records:
  "@":
    A: 203.0.113.10
    AAAA: []
    MX: ["10 MX.Example.com", "20 backup.example.com."]
    TXT: ["v=spf1 -all", "google-site-verification=AbC"]
    CAA: '0 issue "letsencrypt.org"'
  WWW:
    CNAME: target.example.net
  _dmarc:
    TXT: "v=DMARC1; p=quarantine"
  old:
    CNAME: []
    A: []
"""


def rdata(rtype: str, text: str) -> dns.rdata.Rdata:
    return dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.from_text(rtype), text, origin=dns.name.root
    )


def test_loads_a_valid_config() -> None:
    config = load(GOOD)

    assert config.domain == "iskri.io"
    assert config.nameservers == ("a.ns.selectel.ru", "b.ns.selectel.ru")
    assert config.rdap_base_url == "https://rdap.example/rdap/"
    assert config.min_days_left == 30
    by_key = {r.key: r for r in config.records}
    assert sorted(by_key) == [
        "records @ A", "records @ AAAA", "records @ CAA", "records @ MX", "records @ TXT",
        "records _dmarc TXT", "records old A", "records old CNAME", "records www CNAME",
    ]
    assert by_key["records @ A"].qname == dns.name.from_text("iskri.io.")
    assert by_key["records www CNAME"].qname == dns.name.from_text("www.iskri.io.")
    assert by_key["records @ AAAA"].expected == frozenset()
    assert by_key["records @ TXT"].expected == {b"v=spf1 -all", b"google-site-verification=AbC"}
    assert by_key["records @ MX"].expected == {
        rdata("MX", "10 mx.example.com."), rdata("MX", "20 backup.example.com."),
    }


def test_the_real_expected_yaml_loads() -> None:
    config = load_file(Path(__file__).parent.parent / "expected.yaml")
    assert config.domain == "iskri.io"


def test_txt_compares_as_joined_bytes_and_is_case_sensitive() -> None:
    split = rdata("TXT", '"v=DKIM1; p=MIGf" "MA0GCSq"')
    assert record_value(split) == b"v=DKIM1; p=MIGfMA0GCSq"
    assert record_value(rdata("TXT", '"v=DMARC1"')) != record_value(rdata("TXT", '"v=dmarc1"'))


def test_other_types_compare_as_parsed_records() -> None:
    assert record_value(rdata("AAAA", "2001:DB8:0::1")) == record_value(rdata("AAAA", "2001:db8::1"))
    assert record_value(rdata("CNAME", "Foo.Example.com")) == record_value(rdata("CNAME", "foo.example.com."))


def records(body: str) -> str:
    return HEAD + "records:\n" + body


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "root: expected a mapping"),
        ("- a\n- b\n", "root: expected a mapping"),
        ("domain: [unclosed\n", "not valid YAML"),
        (HEAD, "root: missing records"),
        (HEAD + "record: {}\n", "root: missing records"),
        (HEAD + "records: {}\nextra: 1\n", "root: unknown keys extra"),
        (GOOD.replace("min_days_left: 30", "min_days_left: 30\n  min_days: 1"), "expiry: unknown keys"),
        (GOOD.replace("[a.ns.selectel.ru, B.NS.Selectel.ru.]", "a.ns.selectel.ru"), "nameservers: expected a non-empty list"),
        (GOOD.replace("[a.ns.selectel.ru, B.NS.Selectel.ru.]", "[]"), "nameservers: expected a non-empty list"),
        (GOOD.replace("min_days_left: 30", "min_days_left: true"), "min_days_left: expected a positive integer"),
        (GOOD.replace("min_days_left: 30", "min_days_left: 0"), "min_days_left: expected a positive integer"),
        (GOOD.replace("min_days_left: 30", 'min_days_left: "30"'), "min_days_left: expected a positive integer"),
        (HEAD + "records: [a, b]\n", "records: expected a mapping"),
        (records('  "@": 1.1.1.1\n'), 'records."@": expected a mapping of types'),
        (records('  "@": {}\n'), 'records."@": expected a mapping of types'),
        (records("  www:\n"), 'records."www": expected a mapping of types'),
        (records("  no: {A: 1.1.1.1}\n"), "records: name False must be a non-empty string"),
        (records("  123: {A: 1.1.1.1}\n"), "records: name 123 must be a non-empty string"),
        (records('  "@": {TXT: 12345}\n'), 'records."@".TXT: expected a string or a list of strings'),
        (records('  "@":\n    TXT:\n'), 'records."@".TXT: expected a string or a list of strings'),
        (records('  "@": {TXT: ["a", 1]}\n'), 'records."@".TXT: expected a string or a list of strings'),
        (records('  "@": {A: 1.1.1.1}\n  "@": {TXT: "x"}\n'), "duplicate key '@' at line"),
        (records('  "@":\n    A: 1.1.1.1\n    A: 2.2.2.2\n'), "duplicate key 'A' at line"),
        (records('  "@": {A: 1.1.1.1, A: 2.2.2.2}\n'), "duplicate key 'A' at line"),
        (records('  "@": {NS: a.example.}\n'), "unsupported type 'NS'"),
        (records('  "@": {a: 1.1.1.1}\n'), "unsupported type 'a'"),
        (records('  "@": {A: 203.0.113.010}\n'), "cannot parse '203.0.113.010' as A"),
        (records('  "@": {MX: "mail.example.com"}\n'), "cannot parse 'mail.example.com' as MX"),
        (records("  www: {CNAME: a.example., A: []}\n"), "a CNAME must be the only type at its name"),
        (records("  www: {CNAME: [a.example., b.example.]}\n"), "a name can hold only one CNAME"),
        (records("  old.iskri.io: {A: []}\n"), 'records: "old.iskri.io" must be relative to iskri.io'),
        (records("  Old.ISKRI.io: {A: []}\n"), "must be relative to iskri.io"),
        (records("  iskri.io: {A: []}\n"), "must be relative to iskri.io"),
        (records("  old.: {A: []}\n"), "must be relative to iskri.io"),
        (records("  example.com.: {A: []}\n"), "must be relative to iskri.io"),
        (records("  www: {A: []}\n  WWW: {AAAA: []}\n"), 'records: "www" and "WWW" are the same name'),
        (records("  a..b: {A: []}\n"), "is not a valid DNS name"),
    ],
)
def test_rejects_invalid_configs(text: str, message: str) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load(text)
    assert message in str(excinfo.value)


def test_an_empty_cname_combines_with_other_types() -> None:
    config = load(records("  www: {CNAME: [], A: 203.0.113.10}\n"))
    assert [r.key for r in config.records] == ["records www A", "records www CNAME"]


def test_duplicate_values_in_a_list_collapse() -> None:
    config = load(records('  "@": {A: [203.0.113.10, 203.0.113.10]}\n'))
    assert len(config.records[0].expected) == 1
