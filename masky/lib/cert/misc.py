from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    NoEncryption,
    pkcs12,
)


def process_pfx(cert, private_key):
    rsa_pk = serialization.load_pem_private_key(private_key, None)
    x509_cert = x509.load_pem_x509_certificate(cert)
    pfx = pkcs12.serialize_key_and_certificates(
        name=b"",
        key=rsa_pk,
        cert=x509_cert,
        cas=None,
        encryption_algorithm=NoEncryption(),
    )
    return pfx, rsa_pk, x509_cert
