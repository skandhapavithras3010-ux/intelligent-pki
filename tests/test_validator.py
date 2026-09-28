from pathlib import Path

from src.ipki.parser import parse_certificate
from src.ipki.chain import build_chain
from src.ipki.validator import validate_certificate


FIXTURES = Path("tests/fixtures")


def load_certificate(filename):
    path = FIXTURES / filename
    return parse_certificate(path.read_bytes())


def build_test_chain(leaf_filename):

    root = load_certificate("root.pem")

    intermediate = load_certificate("intermediate.pem")

    leaf = load_certificate(leaf_filename)

    chain = build_chain(
        leaf=leaf,
        candidates=[intermediate],
        anchors=[root]
    )

    return leaf, chain


def test_healthy_certificate():

    leaf, chain = build_test_chain(
        "healthy-leaf.pem"
    )

    findings = validate_certificate(
        cert=leaf,
        chain=chain,
        hostname="example.com"
    )

    statuses = [
        finding.status
        for finding in findings
    ]

    assert "FAIL" not in statuses


def test_expired_certificate():

    leaf, chain = build_test_chain(
        "expired-leaf.pem"
    )

    findings = validate_certificate(
        cert=leaf,
        chain=chain,
        hostname="example.com"
    )

    expiry_findings = [
        finding
        for finding in findings
        if finding.rule == "expiry"
    ]

    assert any(
        finding.status == "FAIL"
        for finding in expiry_findings
    )


def test_hostname_mismatch():

    leaf, chain = build_test_chain(
        "mismatched-hostname-leaf.pem"
    )

    findings = validate_certificate(
        cert=leaf,
        chain=chain,
        hostname="definitely-not-the-certificate-host.com"
    )

    hostname_findings = [
        finding
        for finding in findings
        if finding.rule == "name_match"
    ]

    assert any(
        finding.status == "FAIL"
        for finding in hostname_findings
    )


def test_broken_signature():

    leaf, chain = build_test_chain(
        "broken-signature-leaf.pem"
    )

    findings = validate_certificate(
        cert=leaf,
        chain=chain,
        hostname="example.com"
    )

    signature_findings = [
        finding
        for finding in findings
        if finding.rule == "signature"
    ]

    assert any(
        finding.status == "FAIL"
        for finding in signature_findings
    )


def test_leaf_as_ca():

    leaf, chain = build_test_chain(
        "leaf-as-ca.pem"
    )

    findings = validate_certificate(
        cert=leaf,
        chain=chain,
        hostname="example.com"
    )

    assert findings

