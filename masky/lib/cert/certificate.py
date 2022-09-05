import logging
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID
from pyasn1.codec.der import decoder
from pyasn1.type.char import UTF8String


logger = logging.getLogger("masky")

PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")

NTDS_CA_SECURITY_EXT = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2")


def cert_to_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(Encoding.DER)


def get_id_from_certificate(
    certificate: x509.Certificate,
) -> Tuple[str, str]:
    try:
        san = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )

        for name in san.value.get_values_for_type(x509.OtherName):
            if name.type_id == PRINCIPAL_NAME:
                return (
                    "UPN",
                    decoder.decode(name.value, asn1Spec=UTF8String)[0].decode(),
                )

        for name in san.value.get_values_for_type(x509.DNSName):
            return "DNS Host Name", name
    except:
        pass

    return None, None


def get_object_sid_from_certificate(
    certificate: x509.Certificate,
) -> Tuple[str, str]:
    try:
        object_sid = certificate.extensions.get_extension_for_oid(NTDS_CA_SECURITY_EXT)

        sid = object_sid.value.value
        return sid[sid.find(b"S-1-5") :].decode()
    except:
        pass

    return None


def rsa_pkcs1v15_sign(
    data: bytes,
    key: rsa.RSAPrivateKey,
    hash: hashes.HashAlgorithm = hashes.SHA256,
):
    return key.sign(data, padding.PKCS1v15(), hash())


def hash_digest(data: bytes, hash: hashes.Hash):
    digest = hashes.Hash(hash())
    digest.update(data)
    return digest.finalize()
