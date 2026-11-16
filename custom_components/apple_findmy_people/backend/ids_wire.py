"""IDS signatures and bounded protobuf framing from the rustpush wire schema."""
import base64
import secrets
import struct
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

P256_PRIME = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF


def compact_key():
    while True:
        key = ec.generate_private_key(ec.SECP256R1())
        if key.public_key().public_numbers().y * 2 <= P256_PRIME:
            return key


def compact_public(key):
    if hasattr(key, "public_key"):
        key = key.public_key()
    return key.public_numbers().x.to_bytes(32, "big")


def expand_compact(value):
    if len(value) != 32:
        raise ValueError("Invalid compact P-256 key")
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x03" + value)
    numbers = key.public_numbers()
    return ec.EllipticCurvePublicNumbers(numbers.x,
        min(numbers.y, P256_PRIME - numbers.y), ec.SECP256R1()).public_key()


def raw_signature(key, value):
    r, s = utils.decode_dss_signature(key.sign(value, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def varint(value):
    if value < 0:
        raise ValueError("Negative protobuf integer")
    encoded = bytearray()
    while value > 127:
        encoded.append((value & 127) | 128)
        value >>= 7
    return bytes(encoded + bytes([value]))


def bytes_field(number, value):
    return varint(number << 3 | 2) + varint(len(value)) + value


def prekey_data(device, prekey):
    timestamp = struct.pack("<d", float(int(time.time())))
    key = compact_public(prekey)
    signature = raw_signature(device, b"NGMPrekeySignature" + key + timestamp)
    return bytes_field(1, key) + bytes_field(2, signature) + b"\x19" + timestamp


def kt_data(device):
    return bytes_field(1, bytes_field(1, compact_public(device))) + b"\x10\x0d\x18\x05"


def protobuf_fields(data):
    if len(data) > 1024 * 1024:
        raise ValueError("Oversized protobuf message")
    cursor, fields = 0, {}
    def integer():
        nonlocal cursor
        value = 0
        for shift in range(0, 70, 7):
            if cursor >= len(data):
                raise ValueError("Truncated protobuf integer")
            byte = data[cursor]
            cursor += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError("Oversized protobuf integer")
    while cursor < len(data):
        tag = integer()
        number, kind = tag >> 3, tag & 7
        if not number:
            raise ValueError("Invalid protobuf field number")
        if kind == 0:
            value = integer()
        elif kind in (1, 2, 5):
            length = integer() if kind == 2 else 8 if kind == 1 else 4
            if length > len(data) - cursor:
                raise ValueError("Truncated protobuf value")
            value = data[cursor:cursor + length]
            cursor += length
        else:
            raise ValueError("Unsupported protobuf wire type")
        fields.setdefault(number, []).append(value)
    return fields


def signing_headers(*, bag_key, query, body, token, auth, push, auth_number=None):
    result = {"x-push-token": token}
    decoded = base64.b64decode(token, validate=True)
    for prefix, identity in (("x-push", push), ("x-auth", auth)):
        postfix = f"-{auth_number}" if prefix == "x-auth" and auth_number is not None else ""
        nonce = b"\x01" + int(time.time() * 1000).to_bytes(8, "big") + secrets.token_bytes(8)
        fields = (bag_key.encode(), query.encode(), body or b"", decoded)
        payload = nonce + b"".join(len(x).to_bytes(4, "big") + x for x in fields)
        key = serialization.load_pem_private_key(identity["key"].encode(), password=None)
        signature = b"\x01\x01" + key.sign(payload, padding.PKCS1v15(), hashes.SHA1())
        cert = x509.load_pem_x509_certificate(identity["cert"].encode())
        for name, value in (("sig", signature), ("nonce", nonce),
                            ("cert", cert.public_bytes(serialization.Encoding.DER))):
            result[f"{prefix}-{name}{postfix}"] = base64.b64encode(value).decode()
    return result
