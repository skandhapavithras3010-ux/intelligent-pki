from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from .models import CertModel


def parse_certificate(pem_bytes: bytes) -> CertModel:

    # Load the certificate
    cert = x509.load_pem_x509_certificate(pem_bytes)

    # Identity
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    # Validity
    not_valid_before = cert.not_valid_before_utc
    not_valid_after = cert.not_valid_after_utc

    # Hostname
    san_dns_names = []

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )

        san_dns_names = san.value.get_values_for_type(
            x509.DNSName
        )

    except x509.ExtensionNotFound:
        pass

    # Key
    public_key = cert.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_bits = public_key.key_size
    else:
        key_type = type(public_key).__name__
        key_bits = None

    # Security
    sig_hash = cert.signature_hash_algorithm.name

    try:
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        is_ca = basic_constraints.value.ca
    except x509.ExtensionNotFound:
        is_ca = False

    is_self_signed = (
        cert.subject == cert.issuer
        and cert.signature_hash_algorithm is not None
    )

    # Revocation
    ocsp_urls = []
    crl_urls = []

    try:
        aia = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        )

        for access in aia.value:
            if access.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                ocsp_urls.append(access.access_location.value)

    except x509.ExtensionNotFound:
        pass

    try:
        crl = cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        )

        for point in crl.value:
            if point.full_name:
                for name in point.full_name:
                    crl_urls.append(name.value)

    except x509.ExtensionNotFound:
        pass

    # Metadata
    extension_count = len(cert.extensions)

    sha256 = cert.fingerprint(
        hashes.SHA256()
    ).hex()

    return CertModel(
        subject=subject,
        issuer=issuer,
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        san_dns_names=san_dns_names,
        key_type=key_type,
        key_bits=key_bits,
        sig_hash=sig_hash,
        is_ca=is_ca,
        is_self_signed=is_self_signed,
        ocsp_urls=ocsp_urls,
        crl_urls=crl_urls,
        extension_count=extension_count,
        sha256=sha256,
    )