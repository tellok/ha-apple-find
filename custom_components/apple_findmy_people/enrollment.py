"""Build the legacy IDS CSR described by the research; no device is registered."""
import gzip
import hashlib
import plistlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID


def _der(tag, payload):
    length = len(payload)
    if length < 128:
        encoded_length = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded_length = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + encoded_length + payload


def ids_csr(private_key, profile_id):
    if private_key.key_size != 2048 or private_key.private_numbers().public_numbers.e != 65537:
        raise ValueError("IDS enrollment requires a 2048-bit RSA key with exponent 65537")
    name = hashlib.sha1(profile_id.encode()).hexdigest().upper()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]).public_bytes()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    request = _der(0x30, b"\x02\x01\x00" + subject + public_key + b"\xa0\x00")
    signature = private_key.sign(request, padding.PKCS1v15(), hashes.SHA1())
    algorithm = bytes.fromhex("300d06092a864886f70d0101050500")
    return _der(0x30, request + algorithm + _der(0x03, b"\x00" + signature))


def authenticate_body(private_key, profile_id, delegate_token):
    return gzip.compress(plistlib.dumps({
        "authentication-data": {"auth-token": delegate_token},
        "csr": ids_csr(private_key, profile_id), "realm-user-id": profile_id,
    }, fmt=plistlib.FMT_XML), mtime=0)
