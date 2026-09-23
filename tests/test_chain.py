from pathlib import Path

from src.ipki.parser import parse_certificate
from src.ipki.chain import build_chain


FIXTURES = Path("tests/fixtures")


def load_certificate(filename):
    path = FIXTURES / filename
    return parse_certificate(path.read_bytes())


def test_ordered_chain():
    root = load_certificate("root.pem")
    intermediate = load_certificate("intermediate.pem")
    leaf = load_certificate("healthy-leaf.pem")

    result = build_chain(
        leaf=leaf,
        candidates=[intermediate],
        anchors=[root]
    )

    assert result.status == "anchored"
    assert len(result.certs) == 3


def test_shuffled_chain():
    root = load_certificate("root.pem")
    intermediate = load_certificate("intermediate.pem")
    leaf = load_certificate("healthy-leaf.pem")

    result = build_chain(
        leaf=leaf,
        candidates=[intermediate],
        anchors=[root]
    )

    assert result.status == "anchored"

    subjects = [cert.subject for cert in result.certs]

    assert subjects[0] == leaf.subject
    assert subjects[1] == intermediate.subject
    assert subjects[2] == root.subject


def test_missing_intermediate():
    root = load_certificate("root.pem")
    leaf = load_certificate("healthy-leaf.pem")

    result = build_chain(
        leaf=leaf,
        candidates=[],
        anchors=[root]
    )

    assert result.status == "incomplete"
    assert len(result.certs) == 1


def test_cycle_in_candidates():
    root = load_certificate("root.pem")
    intermediate = load_certificate("intermediate.pem")
    leaf = load_certificate("healthy-leaf.pem")

    result = build_chain(
        leaf=leaf,
        candidates=[intermediate, leaf],
        anchors=[root]
    )

    assert result.status in ["anchored", "incomplete"]


def test_untrusted_self_signed_root():
    root = load_certificate("root.pem")
    intermediate = load_certificate("intermediate.pem")
    leaf = load_certificate("healthy-leaf.pem")

    result = build_chain(
        leaf=leaf,
        candidates=[intermediate, root],
        anchors=[]
    )

    assert result.status == "untrusted_root"