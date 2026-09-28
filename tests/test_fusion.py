from src.ipki.fusion import fuse_score
from src.ipki.policy import PolicyResult


def test_healthy_fusion():
    results = [
        PolicyResult("expiry", "PASS", ""),
        PolicyResult("chain_trust", "PASS", ""),
        PolicyResult("revocation", "WARN", ""),
        PolicyResult("name_match", "PASS", ""),
        PolicyResult("key_strength", "PASS", ""),
        PolicyResult("sig_algorithm", "PASS", ""),
    ]

    result = fuse_score(80, results)

    assert result.score == 80
    assert result.verdict == "TRUSTED"


def test_soft_failure():
    results = [
        PolicyResult("expiry", "PASS", ""),
        PolicyResult("chain_trust", "PASS", ""),
        PolicyResult("revocation", "WARN", ""),
        PolicyResult("name_match", "FAIL", ""),
        PolicyResult("key_strength", "PASS", ""),
        PolicyResult("sig_algorithm", "PASS", ""),
    ]

    result = fuse_score(80, results)

    assert result.score == 70
    assert result.verdict == "TRUSTED"


def test_hard_failure_caps_score():
    results = [
        PolicyResult("expiry", "FAIL", ""),
        PolicyResult("chain_trust", "PASS", ""),
        PolicyResult("revocation", "WARN", ""),
        PolicyResult("name_match", "PASS", ""),
        PolicyResult("key_strength", "PASS", ""),
        PolicyResult("sig_algorithm", "PASS", ""),
    ]

    result = fuse_score(90, results)

    assert result.score == 20
    assert result.verdict == "UNTRUSTED"


def test_caution_threshold():
    results = [
        PolicyResult("expiry", "PASS", ""),
        PolicyResult("chain_trust", "PASS", ""),
        PolicyResult("revocation", "WARN", ""),
        PolicyResult("name_match", "PASS", ""),
        PolicyResult("key_strength", "PASS", ""),
        PolicyResult("sig_algorithm", "PASS", ""),
    ]

    result = fuse_score(50, results)

    assert result.score == 50
    assert result.verdict == "CAUTION"