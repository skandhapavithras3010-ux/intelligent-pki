from dataclasses import dataclass


@dataclass
class FusionResult:
    score: float
    verdict: str


HARD_RULES = {"expiry", "chain_trust", "revocation"}
SOFT_RULES = {"name_match", "key_strength", "sig_algorithm"}


def fuse_score(ml_score: float, policy_results) -> FusionResult:
    score = ml_score

    hard_failure = any(
        result.rule in HARD_RULES and result.status == "FAIL"
        for result in policy_results
    )

    if hard_failure:
        score = min(score, 20)

    else:
        for result in policy_results:
            if result.rule in SOFT_RULES and result.status == "FAIL":
                score -= 10

    score = max(0, min(100, score))

    if hard_failure:
        verdict = "UNTRUSTED"
    elif score >= 60:
        verdict = "TRUSTED"
    elif score >= 40:
        verdict = "CAUTION"
    else:
        verdict = "UNTRUSTED"

    return FusionResult(
        score=score,
        verdict=verdict
    )