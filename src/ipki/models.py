from dataclasses import dataclass
from datetime import datetime

@dataclass
class CertModel:
    subject: str
    issuer: str
    not_valid_before: datetime
    not_valid_after: datetime
    san_dns_names: list[str]
    key_type: str
    key_bits: int | None
    sig_hash: str
    is_ca: bool
    is_self_signed: bool
    ocsp_urls: list[str]
    crl_urls: list[str]
    extension_count: int
    sha256: str
    raw: object    # Actual X.509 certificate


# CertModel is basically our Information box

