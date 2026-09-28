from pathlib import Path

from src.ipki.parser import parse_certificate
from src.ipki.chain import build_chain
from src.ipki.validator import validate_certificate
from src.ipki.policy import apply_policy


FIXTURES = Path("tests/fixtures")


def load_certificate(filename):
    return parse_certificate(
        (FIXTURES / filename).read_bytes()
    )


def build_chain_for(leaf_filename):
    root = load_certificate("root.pem")
    intermediate = load_certificate("intermediate.pem")
    leaf = load_certificate(leaf_filename)

    chain = build_chain(
        leaf=leaf,
        candidates=[intermediate],
        anchors=[root]
    )

    return leaf, chain


def test_policy_has_six_rules():
    leaf, chain = build_chain_for("healthy-leaf.pem")

    findings = validate_certificate(
        cert=leaf,
        chain=chain,
        hostname="example.com"
    )

    results = apply_policy(
        findings,
        chain.status,
        chain.certs,
        leaf
    )

    rules = {result.rule for result in results}

    assert rules == {
        "expiry",
        "chain_trust",
        "revocation",
        "name_match",
        "key_strength",
        "sig_algorithm"
    }


def test_healthy_policy():
    leaf, chain = build_chain_for("healthy-leaf.pem")

    findings = validate_certificate(
        cert=leaf,
        chain=chain,
        hostname="example.com"
    )

    results = apply_policy(
        findings,
        chain.status,
        chain.certs,
        leaf
    )

    statuses = {
        result.rule: result.status
        for result in results
    }

    assert statuses["expiry"] == "PASS"
    assert statuses["chain_trust"] == "PASS"
    assert statuses["name_match"] == "PASS"
    assert statuses["key_strength"] == "PASS"
    assert statuses["sig_algorithm"] == "PASS"


def test_expired_policy():
    leaf, chain = build_chain_for("expired-leaf.pem")

    findings = validate_certificate(
        cert=leaf,
        chain=chain,
        hostname="example.com"
    )

    results = apply_policy(
        findings,
        chain.status,
        chain.certs,
        leaf
    )

    expiry = next(
        result for result in results
        if result.rule == "expiry"
    )

    assert expiry.status == "FAIL"


def test_hostname_policy():
    leaf, chain = build_chain_for(
        "mismatched-hostname-leaf.pem"
    )

    findings = validate_certificate(
        cert=leaf,
        chain=chain,
        hostname="definitely-not-the-certificate-host.com"
    )

    results = apply_policy(
        findings,
        chain.status,
        chain.certs,
        leaf
    )

    name = next(
        result for result in results
        if result.rule == "name_match"
    )

    assert name.status == "FAIL"


def test_weak_key_policy():
    leaf, chain = build_chain_for("weakkey-leaf.pem")

    findings = validate_certificate(
        cert=leaf,
        chain=chain,
        hostname="example.com"
    )

    results = apply_policy(
        findings,
        chain.status,
        chain.certs,
        leaf
    )

    key = next(
        result for result in results
        if result.rule == "key_strength"
    )

    assert key.status == "FAIL"