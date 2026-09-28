from datetime import datetime, timezone

from .models import CertModel
from .chain import Chain


def build_features(cert: CertModel, chain: Chain) -> dict:
    now = datetime.now(timezone.utc)

    features = {
        # 1. How many certificates are in the chain
        "chain_length": len(chain.certs),

        # 2. Public-key size
        "key_bits": cert.key_bits or 0,

        # 3. Whether this certificate is a CA
        "is_ca": int(cert.is_ca),

        # 4. Whether certificate is self-signed
        "is_self_signed": int(cert.is_self_signed),

        # 5. Number of extensions
        "extension_count": cert.extension_count,

        # 6. Number of DNS names in SAN
        "san_count": len(cert.san_dns_names),

        # 7. Number of OCSP URLs
        "ocsp_count": len(cert.ocsp_urls),

        # 8. Number of CRL URLs
        "crl_count": len(cert.crl_urls),

        # 9. Days until certificate expires
        "days_until_expiry": (
            cert.not_valid_after - now
        ).days,

        # 10. Days since certificate became valid
        "days_since_validity_start": (
            now - cert.not_valid_before
        ).days,

        # 11. Length of subject
        "subject_length": len(cert.subject),

        # 12. Length of issuer
        "issuer_length": len(cert.issuer),

        # 13. Whether SAN contains a wildcard
        "has_wildcard_san": int(
            any(
                san.startswith("*.")
                for san in cert.san_dns_names
            )
        ),
    }

    return features