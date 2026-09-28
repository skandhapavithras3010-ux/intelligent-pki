from src.ipki.dataset import build_training_dataset
from src.ipki.ml import train_model
from src.ipki.explain import explain_prediction
from src.ipki.policy import PolicyResult


def test_explanation():
    model = train_model()

    X, y = build_training_dataset()
    features = X[0]

    policy_results = [
        PolicyResult("expiry", "PASS", ""),
        PolicyResult("chain_trust", "PASS", ""),
        PolicyResult("revocation", "WARN", ""),
        PolicyResult("name_match", "PASS", ""),
        PolicyResult("key_strength", "PASS", ""),
        PolicyResult("sig_algorithm", "PASS", ""),
    ]

    explanations = explain_prediction(
        model,
        features,
        policy_results
    )

    assert len(explanations) <= 5
    assert len(explanations) > 0

    for explanation in explanations:
        assert "feature" in explanation
        assert "impact" in explanation
        assert "rule" in explanation
        assert "status" in explanation