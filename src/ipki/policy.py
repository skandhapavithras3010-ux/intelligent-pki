
from dataclasses import dataclass

from .validator import ValidationFinding


@dataclass
class PolicyResult:
    rule: str
    status: str
    message: str



# 1. EXPIRY

def evaluate_expiry(
    findings: list[ValidationFinding]
) -> PolicyResult:

    expiry_findings = [
        finding
        for finding in findings
        if finding.rule == "expiry"
    ]

    if any(
        finding.status == "FAIL"
        for finding in expiry_findings
    ):
        return PolicyResult(
            rule="expiry",
            status="FAIL",
            message="Certificate chain contains an expired or not-yet-valid certificate"
        )

    return PolicyResult(
        rule="expiry",
        status="PASS",
        message="All certificates in the chain are currently valid"
    )



# 2. CHAIN TRUST

def evaluate_chain_trust(
    chain_status: str,
    findings: list[ValidationFinding]
) -> PolicyResult:

    if chain_status != "anchored":
        return PolicyResult(
            rule="chain_trust",
            status="FAIL",
            message="Certificate chain is not anchored to a trusted root"
        )

    if any(
        finding.rule == "signature"
        and finding.status == "FAIL"
        for finding in findings
    ):
        return PolicyResult(
            rule="chain_trust",
            status="FAIL",
            message="Certificate chain contains an invalid signature"
        )

    if any(
        finding.rule == "ca_constraints"
        and finding.status == "FAIL"
        for finding in findings
    ):
        return PolicyResult(
            rule="chain_trust",
            status="FAIL",
            message="Certificate chain contains an invalid CA constraint"
        )

    return PolicyResult(
        rule="chain_trust",
        status="PASS",
        message="Certificate chain is anchored and cryptographically valid"
    )



# 3. REVOCATION
 

def evaluate_revocation(
    chain_certs
) -> PolicyResult:

    has_revocation_info = any(
        cert.ocsp_urls or cert.crl_urls
        for cert in chain_certs
    )

    if has_revocation_info:
        return PolicyResult(
            rule="revocation",
            status="PASS",
            message="Certificate chain contains revocation information"
        )

    return PolicyResult(
        rule="revocation",
        status="WARN",
        message="No OCSP or CRL information is available"
    )



# 4. NAME MATCH

def evaluate_name_match(
    findings: list[ValidationFinding]
) -> PolicyResult:

    name_findings = [
        finding
        for finding in findings
        if finding.rule == "name_match"
    ]

    if any(
        finding.status == "FAIL"
        for finding in name_findings
    ):
        return PolicyResult(
            rule="name_match",
            status="FAIL",
            message="Hostname does not match the certificate SAN"
        )

    if any(
        finding.status == "SKIPPED"
        for finding in name_findings
    ):
        return PolicyResult(
            rule="name_match",
            status="SKIPPED",
            message="Hostname matching was not performed"
        )

    return PolicyResult(
        rule="name_match",
        status="PASS",
        message="Hostname matches the certificate SAN"
    )



# 5. KEY STRENGTH


def evaluate_key_strength(
    cert
) -> PolicyResult:

    if cert.key_type == "RSA":

        if cert.key_bits is not None and cert.key_bits < 2048:
            return PolicyResult(
                rule="key_strength",
                status="FAIL",
                message="RSA key is weaker than the minimum allowed size"
            )

        return PolicyResult(
            rule="key_strength",
            status="PASS",
            message="RSA key meets the minimum strength requirement"
        )

    return PolicyResult(
        rule="key_strength",
        status="WARN",
        message="Key strength policy is not defined for this key type"
    )



# 6. SIGNATURE ALGORITHM


def evaluate_signature_algorithm(
    findings: list[ValidationFinding]
) -> PolicyResult:

    algorithm_findings = [
        finding
        for finding in findings
        if finding.rule == "sig_algorithm"
    ]

    if any(
        finding.status == "WARN"
        for finding in algorithm_findings
    ):
        return PolicyResult(
            rule="sig_algorithm",
            status="WARN",
            message="Certificate uses a signature hash algorithm outside the supported set"
        )

    return PolicyResult(
        rule="sig_algorithm",
        status="PASS",
        message="Certificate uses a supported signature hash algorithm"
    )



# APPLY ALL SIX POLICY RULES


def apply_policy(
    findings: list[ValidationFinding],
    chain_status: str,
    chain_certs,
    cert
) -> list[PolicyResult]:

    results = []

    results.append(
        evaluate_expiry(findings)
    )

    results.append(
        evaluate_chain_trust(
            chain_status,
            findings
        )
    )

    results.append(
        evaluate_revocation(
            chain_certs
        )
    )

    results.append(
        evaluate_name_match(findings)
    )

    results.append(
        evaluate_key_strength(cert)
    )

    results.append(
        evaluate_signature_algorithm(findings)
    )

    return results
