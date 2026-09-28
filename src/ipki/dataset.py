from pathlib import Path

from .parser import parse_certificate
from .chain import build_chain
from .features import build_features


FIXTURES = Path("tests/fixtures")


# Ground truth for our generated lab certificates.
GROUND_TRUTH = {
    "healthy-leaf.pem": 1,
    "expired-leaf.pem": 0,
    "weakkey-leaf.pem": 0,
    "mismatched-hostname-leaf.pem": 0,
    "broken-signature-leaf.pem": 0,
    "leaf-as-ca.pem": 0,
}


def load_certificate(filename):
    return parse_certificate(
        (FIXTURES / filename).read_bytes()
    )


def build_training_dataset():
    X = []
    y = []

    root = load_certificate("root.pem")
    intermediate = load_certificate("intermediate.pem")

    for filename, label in GROUND_TRUTH.items():
        leaf = load_certificate(filename)

        chain = build_chain(
            leaf=leaf,
            candidates=[intermediate],
            anchors=[root]
        )

        features = build_features(leaf, chain)

        X.append(features)
        y.append(label)

    return X, y