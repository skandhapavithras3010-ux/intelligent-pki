from pathlib import Path

from src.ipki.parser import parse_certificate
from src.ipki.chain import build_chain
from src.ipki.features import build_features


FIXTURES = Path("tests/fixtures")


def load_certificate(filename):
    return parse_certificate(
        (FIXTURES / filename).read_bytes()
    )


def test_feature_builder():
    root = load_certificate("root.pem")
    intermediate = load_certificate("intermediate.pem")
    leaf = load_certificate("healthy-leaf.pem")

    chain = build_chain(
        leaf=leaf,
        candidates=[intermediate],
        anchors=[root]
    )

    features = build_features(leaf, chain)

    assert len(features) == 13

    assert "chain_length" in features
    assert "key_bits" in features
    assert "is_ca" in features
    assert "is_self_signed" in features
    assert "extension_count" in features
    assert "san_count" in features
    assert "ocsp_count" in features
    assert "crl_count" in features
    assert "days_until_expiry" in features
    assert "days_since_validity_start" in features
    assert "subject_length" in features
    assert "issuer_length" in features
    assert "has_wildcard_san" in features


def test_feature_values():
    root = load_certificate("root.pem")
    intermediate = load_certificate("intermediate.pem")
    leaf = load_certificate("healthy-leaf.pem")

    chain = build_chain(
        leaf=leaf,
        candidates=[intermediate],
        anchors=[root]
    )

    features = build_features(leaf, chain)

    assert features["chain_length"] == 3
    assert features["key_bits"] > 0
    assert features["is_ca"] == 0
    assert features["san_count"] >= 1
    assert features["extension_count"] > 0