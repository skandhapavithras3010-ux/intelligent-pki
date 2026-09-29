from pathlib import Path

from .parser import parse_certificate
from .chain import build_chain
from .validator import validate_certificate
from .policy import apply_policy
from .features import build_features
from .ml import train_model, predict_score
from .fusion import fuse_score
from .explain import explain_prediction


FIXTURES = Path("tests/fixtures")


def analyze(
    pem_bytes,
    intermediates=None,
    hostname=None,
    as_of=None
):
    if intermediates is None:
        intermediates = []

    # M1: Parse leaf certificate
    leaf = parse_certificate(pem_bytes)

    # Parse intermediates
    intermediate_certs = [
        parse_certificate(cert_bytes)
        for cert_bytes in intermediates
    ]

    # Load trusted lab root
    root = parse_certificate(
        (FIXTURES / "root.pem").read_bytes()
    )

    # M2: Build certificate chain
    chain = build_chain(
        leaf=leaf,
        candidates=intermediate_certs,
        anchors=[root]
    )

    # M3: Validate certificate and chain
    findings = validate_certificate(
        cert=leaf,
        chain=chain,
        hostname=hostname,
        as_of=as_of
    )

    # M4: Apply PKI policy
    policy_results = apply_policy(
        findings=findings,
        chain_status=chain.status,
        chain_certs=chain.certs,
        cert=leaf
    )

    # M5: Build ML features
    features = build_features(
        cert=leaf,
        chain=chain
    )

    # M6: Train Random Forest
    model = train_model()

    # ML trust score
    ml_score = predict_score(
        ml_model=model,
        features=features
    )

    # M7: Fuse PKI + ML
    fusion = fuse_score(
        ml_score=ml_score,
        policy_results=policy_results
    )

    # M8: Generate SHAP explanations
    explanations = explain_prediction(
        ml_model=model,
        features=features,
        policy_results=policy_results
    )

    return {
        "cert": leaf,
        "chain": chain,
        "findings": findings,
        "policy": policy_results,
        "features": features,
        "ml_score": ml_score,
        "fusion": fusion,
        "explanations": explanations,
    }