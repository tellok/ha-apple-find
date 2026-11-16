import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from scripts.ids_wire import compact_key, compact_public, expand_compact, kt_data, prekey_data, protobuf_fields


def test_compact_p256_identity_and_signed_prekey_match_wire_schema():
    device, prekey = compact_key(), compact_key()
    assert expand_compact(compact_public(device)).public_numbers() == device.public_key().public_numbers()
    fields = protobuf_fields(prekey_data(device, prekey))
    key, signature, timestamp = fields[1][0], fields[2][0], fields[3][0]
    signed = b"NGMPrekeySignature" + key + timestamp
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                    int.from_bytes(signature[32:], "big"))
    device.public_key().verify(der, signed, ec.ECDSA(hashes.SHA256()))
    assert len(key) == 32 and len(signature) == 64 and struct.unpack("<d", timestamp)[0] > 0
    kt = protobuf_fields(kt_data(device))
    assert kt[2] == [13] and kt[3] == [5]
    assert protobuf_fields(kt[1][0])[1] == [compact_public(device)]


@pytest.mark.parametrize("data", [b"\x0a\x05a", b"\x80", b"\x00", b"\x0b", b"\x09a", b"\x80" * 10])
def test_invalid_remote_protobuf_is_rejected(data):
    with pytest.raises(ValueError):
        protobuf_fields(data)
