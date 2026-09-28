# IMPORTS 
from dataclasses import dataclass
from datetime import datetime, timezone 

from cryptography import x509 
from cryptography.exceptions import InvalidSignature 
from cryptography.hazmat.primitives.asymmetric import padding, rsa 

from .models import CertModel 
from .chain import Chain

# RESULT MODEL

@dataclass
class ValidationFinding:
    rule : str
    status : str
    message : str

# EXPIRY/VALIDITY CHECK
def validate_expiry(cert: CertModel, as_of = None) -> ValidationFinding:
    if as_of is None:
        from datetime import datetime , timezone
        as_of = datetime.now(timezone.utc)

    if cert.not_valid_before <= as_of <= cert.not_valid_after:
        return ValidationFinding(
            rule = "expiry",
            status = "PASS",
            message = "Certificate is currently valid"
        )

    return ValidationFinding(
        rule = "expiry",
        status = "FAIL",
        message = "Certificate is expired or not yet valid"
    )

# SIGNATURE CHECK
def verify_signature(
    child: CertModel,
    issuer: CertModel
) -> ValidationFinding:

    try:
        issuer_public_key = issuer.raw.public_key()

        if isinstance(issuer_public_key, rsa.RSAPublicKey):

            issuer_public_key.verify(
                child.raw.signature,
                child.raw.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.raw.signature_hash_algorithm
            )

        else:
            return ValidationFinding(
                rule="signature",
                status="WARN",
                message="Unsupported public key algorithm"
            )

        return ValidationFinding(
            rule="signature",
            status="PASS",
            message="Certificate signature is valid"
        )

    except InvalidSignature:
        return ValidationFinding(
            rule="signature",
            status="FAIL",
            message="Certificate signature verification failed"
        )

   # CA Constraints
def validate_ca_constraints(
    cert: CertModel
) -> ValidationFinding:

    if cert.is_ca:
        return ValidationFinding(
            rule="ca_constraints",
            status="PASS",
            message="Certificate is marked as a CA"
        )

    return ValidationFinding(
        rule="ca_constraints",
        status="PASS",
        message="Certificate is correctly marked as a non-CA"
    )


    # KEY USAGE
def validate_key_usage(
    cert: CertModel
) -> ValidationFinding:

    try:
        key_usage = cert.raw.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value

        if cert.is_ca:

            if key_usage.key_cert_sign:
                return ValidationFinding(
                    rule="key_usage",
                    status="PASS",
                    message="CA certificate has keyCertSign usage"
                )

            return ValidationFinding(
                rule="key_usage",
                status="FAIL",
                message="CA certificate does not have keyCertSign usage"
            )

        return ValidationFinding(
            rule="key_usage",
            status="PASS",
            message="Key usage is valid for this certificate"
        )

    except x509.ExtensionNotFound:

        return ValidationFinding(
            rule="key_usage",
            status="SKIPPED",
            message="Key Usage extension is not present"
        )

# HOSTNAME / SAN CHECK

def validate_hostname(
    cert: CertModel,
    hostname: str | None
) -> ValidationFinding:

    if hostname is None:
        return ValidationFinding(
            rule="name_match",
            status="SKIPPED",
            message="No hostname was provided"
        )

    if not cert.san_dns_names:
        return ValidationFinding(
            rule="name_match",
            status="FAIL",
            message="Certificate has no DNS SAN"
        )

    for san in cert.san_dns_names:

        if san == hostname:
            return ValidationFinding(
                rule="name_match",
                status="PASS",
                message="Hostname matches certificate SAN"
            )

        if san.startswith("*."):
            suffix = san[1:]

            if hostname.endswith(suffix):

                hostname_parts = hostname.split(".")
                suffix_parts = suffix.lstrip(".").split(".")

                if len(hostname_parts) == len(suffix_parts) + 1:
                    return ValidationFinding(
                        rule="name_match",
                        status="PASS",
                        message="Hostname matches certificate wildcard SAN"
                    )

    return ValidationFinding(
        rule="name_match",
        status="FAIL",
        message="Hostname does not match certificate SAN"
    )

# ALGORITHM HANDLING CHECK

def validate_algorithm(
    cert: CertModel
) -> ValidationFinding:

    supported_hashes = {
        "sha256",
        "sha384",
        "sha512"
    }

    if cert.sig_hash.lower() in supported_hashes:
        return ValidationFinding(
            rule="sig_algorithm",
            status="PASS",
            message=f"Signature hash algorithm {cert.sig_hash} is supported"
        )

    return ValidationFinding(
        rule="sig_algorithm",
        status="WARN",
        message=f"Signature hash algorithm {cert.sig_hash} is not supported"
    )

# VALIDATE THE COMPLETE CHAIN

def validate_chain(
    chain: Chain,
    as_of=None
) -> list[ValidationFinding]:

    findings = []

    for cert in chain.certs:

        findings.append(
            validate_expiry(cert, as_of)
        )

    for i in range(len(chain.certs) - 1):

        child = chain.certs[i]
        issuer = chain.certs[i + 1]

        findings.append(
            verify_signature(child, issuer)
        )

        if issuer.is_ca:
            findings.append(
                ValidationFinding(
                    rule="ca_constraints",
                    status="PASS",
                    message="Issuer certificate is marked as a CA"
                )
            )

        else:
            findings.append(
                ValidationFinding(
                    rule="ca_constraints",
                    status="FAIL",
                    message="Issuer certificate is not marked as a CA"
                )
            )

        findings.append(
            validate_key_usage(issuer)
        )

    return findings

# FUNCTION TO RUN ALL THE M3 CHECKS

def validate_certificate(
        cert: CertModel, 
        chain: Chain,
        hostname: str | None = None,
        as_of = None
) -> list[ValidationFinding]:

    findings = []

    findings.extend(
        validate_chain(chain, as_of)
    )

    findings.append(
        validate_hostname(cert, hostname)
    )

    findings.append(
        validate_algorithm(cert)
    )

    return findings