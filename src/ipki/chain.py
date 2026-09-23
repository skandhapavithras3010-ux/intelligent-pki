from dataclasses import dataclass
from .models import CertModel

@dataclass
class Chain:
    certs: list[CertModel]
    status : str

def build_chain(
        leaf : CertModel,
        candidates : list[CertModel],
        anchors: list[CertModel]
) -> Chain:

    # Create look up table for certificates
    cert_index = {
        cert.subject : cert
        for cert in candidates
    }

    # Add trusted root certificates to the lookup table
    for anchor in anchors:
        cert_index[anchor.subject] = anchor

    # Keep track of which certificates are trusted roots
    anchor_subjects = {
        cert.subject
        for cert in anchors
    }

    # Start thr chain with the leaf certificate
    chain = [leaf]

    # Keep track of certificates we have already visited
    visited = {leaf.subject}

    # Current certificate we are examining
    current = leaf

    # Walk upward through the certificate hierarchy
    for _ in range(6):
        # If the current certificate is already trusted anchor,
        # The chain is already complete and trusted.
        if current.subject in anchor_subjects:
            return Chain(
                certs = chain,
                status = "anchored"
            )

        # A self-signed certificate that is not trusted
        # means we reached an untrusted root
        if current.is_self_signed:
            return Chain(
                certs = chain,
                status = "untrusted_root"
            )

        # Find the ceertificate that issued the current certificate
        issuer = cert_index.get(current.issuer)

        # No issuer means the chain cannot be completed
        if issuer is None:
            return Chain(
                certs = chain,
                status = "incomplete"
            )

        # If we have already visited this certificate,
        # we have detected a cycle
        if issuer.subject in visited:
            return Chain(
                certs = chain,
                status = "incomplete"
            )

        # Add the issuer to the chain
        chain.append(issuer)

        # Mark the issuer as visited
        visited.add(issuer.subject)

        # Move upward to issuer
        current = issuer

    # We reached the maximum chain depth

    return Chain(
        certs = chain,
        status = "incomplete"
    )