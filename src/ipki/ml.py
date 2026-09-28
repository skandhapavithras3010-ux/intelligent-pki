from dataclasses import dataclass

from sklearn.ensemble import RandomForestClassifier

from .dataset import build_training_dataset


@dataclass
class MLModel:
    model: RandomForestClassifier
    feature_names: list[str]


FEATURE_NAMES = [
    "chain_length",
    "key_bits",
    "is_ca",
    "is_self_signed",
    "extension_count",
    "san_count",
    "ocsp_count",
    "crl_count",
    "days_until_expiry",
    "days_since_validity_start",
    "subject_length",
    "issuer_length",
    "has_wildcard_san",
]


def train_model() -> MLModel:
    X_dict, y = build_training_dataset()

    X = [
        [row[name] for name in FEATURE_NAMES]
        for row in X_dict
    ]

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(X, y)

    return MLModel(
        model=model,
        feature_names=FEATURE_NAMES
    )


def predict_score(
    ml_model: MLModel,
    features: dict
) -> float:

    X = [[
        features[name]
        for name in ml_model.feature_names
    ]]

    probabilities = ml_model.model.predict_proba(X)

    trusted_probability = probabilities[0][1]

    return trusted_probability * 100