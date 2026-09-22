from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Project folders
BASE_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = BASE_DIR / "tests" / "fixtures"

FIXTURES_DIR.mkdir(parents=True, exist_ok=True)


# Generate RSA key
def generate_keys(bits=2048):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits
    )


# Save certificate
def save_cert(cert, filename):
    path = FIXTURES_DIR / filename
    path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )


# Create a CA certificate
def create_ca(subject_name, key, issuer_cert=None, issuer_key=None, path_length=None):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intelligent PKI Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    if issuer_cert is None:
        issuer = subject
        signer_key = key
    else:
        issuer = issuer_cert.subject
        signer_key = issuer_key

    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=path_length
            ),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        )
        .sign(
            private_key=signer_key,
            algorithm=hashes.SHA256()
        )
    )

    return cert


# Create a leaf certificate
def create_leaf(
    subject_name,
    key,
    issuer_cert,
    issuer_key,
    hostname="example.com",
    days_valid=365,
    ca=False,
    signature_key=None,
    bits_info=None
):
    now = datetime.now(timezone.utc)

    if days_valid < 0:
        not_before = now - timedelta(days=365)
        not_after = now - timedelta(days=30)
    else:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=days_valid)

    signer_key = signature_key if signature_key else issuer_key

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intelligent PKI Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(
                ca=ca,
                path_length=0 if ca else None
            ),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=not ca,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname)
            ]),
            critical=False
        )
        .sign(
            private_key=signer_key,
            algorithm=hashes.SHA256()
        )
    )

    return cert


def main():

    print("Generating Intelligent PKI lab certificates...")

    # --------------------------------------------------
    # 1. Root CA
    # --------------------------------------------------

    root_key = generate_keys(2048)

    root_cert = create_ca(
        "Intelligent PKI Root CA",
        root_key,
        path_length=2
    )

    save_cert(root_cert, "root.pem")


    # --------------------------------------------------
    # 2. Intermediate CA
    # --------------------------------------------------

    intermediate_key = generate_keys(2048)

    intermediate_cert = create_ca(
        "Intelligent PKI Intermediate CA",
        intermediate_key,
        issuer_cert=root_cert,
        issuer_key=root_key,
        path_length=1
    )

    save_cert(intermediate_cert, "intermediate.pem")


    # --------------------------------------------------
    # 3. Healthy leaf
    # --------------------------------------------------

    healthy_key = generate_keys(2048)

    healthy_cert = create_leaf(
        "healthy.example.com",
        healthy_key,
        intermediate_cert,
        intermediate_key,
        hostname="example.com"
    )

    save_cert(healthy_cert, "healthy-leaf.pem")


    # --------------------------------------------------
    # 4. Expired leaf
    # --------------------------------------------------

    expired_key = generate_keys(2048)

    expired_cert = create_leaf(
        "expired.example.com",
        expired_key,
        intermediate_cert,
        intermediate_key,
        hostname="example.com",
        days_valid=-1
    )

    save_cert(expired_cert, "expired-leaf.pem")


    # --------------------------------------------------
    # 5. Weak RSA-1024 leaf
    # --------------------------------------------------

    weak_key = generate_keys(1024)

    weak_cert = create_leaf(
        "weak.example.com",
        weak_key,
        intermediate_cert,
        intermediate_key,
        hostname="example.com"
    )

    save_cert(weak_cert, "weakkey-leaf.pem")


    # --------------------------------------------------
    # 6. Hostname mismatch
    # --------------------------------------------------

    mismatch_key = generate_keys(2048)

    mismatch_cert = create_leaf(
        "wrong.example.com",
        mismatch_key,
        intermediate_cert,
        intermediate_key,
        hostname="wrong.example.com"
    )

    save_cert(
        mismatch_cert,
        "mismatched-hostname-leaf.pem"
    )


    # --------------------------------------------------
    # 7. Broken signature
    # --------------------------------------------------

    broken_key = generate_keys(2048)
    rogue_key = generate_keys(2048)

    broken_cert = create_leaf(
        "broken.example.com",
        broken_key,
        intermediate_cert,
        intermediate_key,
        hostname="example.com",
        signature_key=rogue_key
    )

    save_cert(
        broken_cert,
        "broken-signature-leaf.pem"
    )


    # --------------------------------------------------
    # 8. Leaf pretending to be a CA
    # --------------------------------------------------

    ca_leaf_key = generate_keys(2048)

    ca_leaf_cert = create_leaf(
        "fake-ca.example.com",
        ca_leaf_key,
        intermediate_cert,
        intermediate_key,
        hostname="example.com",
        ca=True
    )

    save_cert(
        ca_leaf_cert,
        "leaf-as-ca.pem"
    )


    # --------------------------------------------------
    # 9. CA with no revocation information
    # --------------------------------------------------

    no_revocation_key = generate_keys(2048)

    no_revocation_cert = create_ca(
        "No Revocation Information CA",
        no_revocation_key,
        issuer_cert=root_cert,
        issuer_key=root_key,
        path_length=0
    )

    save_cert(
        no_revocation_cert,
        "no-revocation-ca.pem"
    )


    print("Done!")
    print(f"Certificates generated in: {FIXTURES_DIR}")


if __name__ == "__main__":
    main()