import gzip
import hashlib
import plistlib

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from custom_components.apple_findmy_people.enrollment import authenticate_body


def test_ids_csr_has_legacy_signature_and_profile_cn():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    compressed = authenticate_body(key, "synthetic-profile", "synthetic-token")
    xml = gzip.decompress(compressed)
    assert xml.startswith(b"<?xml")
    payload = plistlib.loads(xml)
    csr = x509.load_der_x509_csr(payload["csr"])
    # Modern CSR convenience validation rejects SHA-1 by policy, although the
    # legacy protocol specifically requires it. Check the actual signature.
    key.public_key().verify(csr.signature, csr.tbs_certrequest_bytes, padding.PKCS1v15(), hashes.SHA1())
    assert csr.signature_hash_algorithm.name == "sha1"
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == hashlib.sha1(b"synthetic-profile").hexdigest().upper()
    assert payload["realm-user-id"] == "synthetic-profile"
