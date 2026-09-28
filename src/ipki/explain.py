import numpy as np
import shap

from .ml import MLModel


FEATURE_RULE_MAP = {
    "key_bits": "key_strength",
    "days_until_expiry": "expiry",
    "ocsp_count": "revocation",
    "crl_count": "revocation",
    "san_count": "name_match",
    "has_wildcard_san": "name_match",
    "chain_length": "chain_trust",
}


def explain_prediction(
    ml_model: MLModel,
    features: dict,
    policy_results,
    top_n: int = 5
) -> list[dict]:

    values = np.array([[
        features[name]
        for name in ml_model.feature_names
    ]])

    explainer = shap.TreeExplainer(ml_model.model)
    shap_values = explainer.shap_values(values)

    if isinstance(shap_values, list):
        values_for_class = shap_values[1][0]
    else:
        if shap_values.ndim == 3:
            values_for_class = shap_values[0, :, 1]
        else:
            values_for_class = shap_values[0]

    explanations = []

    for feature_name, shap_value in zip(
        ml_model.feature_names,
        values_for_class
    ):
        rule = FEATURE_RULE_MAP.get(feature_name)

        if rule is None:
            continue

        status = next(
            (
                result.status
                for result in policy_results
                if result.rule == rule
            ),
            "UNKNOWN"
        )

        explanations.append({
            "feature": feature_name,
            "impact": float(np.asarray(shap_value).squeeze()),
            "rule": rule,
            "status": status,
        })

    explanations.sort(
        key=lambda item: abs(item["impact"]),
        reverse=True
    )

    return explanations[:top_n]