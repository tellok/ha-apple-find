"""Offline protocol primitives. No Apple account or network access here.

Based on https://zerotistic.blog/posts/find-my-people-linux/.
These functions do not implement IDS registration or authenticate a key's origin.
"""
from __future__ import annotations

import hmac
import json
import math
import plistlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF


def public_bytes(key):
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def decode_share_key(blob: bytes):
    if len(blob) != 85 or blob[0] != 4:
        raise ValueError("Expected a P-224 point plus private scalar (85 bytes)")
    key = ec.derive_private_key(int.from_bytes(blob[57:], "big"), ec.SECP224R1())
    if not hmac.compare_digest(public_bytes(key.public_key()), blob[:57]):
        raise ValueError("Private scalar does not match public point")
    return key


def open_pair_ec(*, receiver_prekey, receiver_device, sender_device,
                 ephemeral: bytes, validator: bytes, signature: bytes, ciphertext: bytes):
    """Caller must obtain sender_device from the token-matched IDS directory.

    Protobuf framing and directory authentication are deliberately outside this
    primitive. Successful verification alone does not identify a friend.
    """
    for key in (receiver_prekey, receiver_device, sender_device):
        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("NGM identities require P-256")
    prekey_x = public_bytes(receiver_prekey.public_key())[1:33]
    receiver_x = public_bytes(receiver_device)[1:33]
    sender_x = public_bytes(sender_device)[1:33]
    expected = sender_x[:2] + receiver_x[:2] + prekey_x[:2]
    if len(validator) != 7 or validator[6] not in (12, 13) or not hmac.compare_digest(expected, validator[:6]):
        raise ValueError("NGM validator mismatch")
    ephemeral_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral)
    secret = receiver_prekey.exchange(ec.ECDH(), ephemeral_key)
    signed = secret + prekey_x + ephemeral[1:33] + receiver_x + ciphertext
    sender_device.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    material = HKDF(algorithm=hashes.SHA256(), length=48,
                    salt=b"LastPawn-MessageKeys", info=b"").derive(secret)
    decryptor = Cipher(algorithms.AES(material[:32]), modes.CTR(material[32:])).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def decrypt_report(blob: bytes, private_key):
    if not isinstance(private_key.curve, ec.SECP224R1):
        raise ValueError("People location reports require P-224")
    if len(blob) < 73:
        raise ValueError("Truncated report")
    ephemeral = blob[:57]
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), ephemeral)
    secret = private_key.exchange(ec.ECDH(), key)
    material = X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=ephemeral).derive(secret)
    plaintext = AESGCM(material[:16]).decrypt(material[16:], blob[57:], None)
    # Actual People field names must be confirmed with the authenticated live report.
    if plaintext.startswith((b"bplist", b"<?xml", b"<plist")):
        return plistlib.loads(plaintext)
    return json.loads(plaintext)


def fetch_body(fm_id: str, courier_token: str, client_id: str, advertised_id: str | None = None):
    if not fm_id or not courier_token or not client_id:
        raise ValueError("A selected share and registered APNs identity are required")
    return {
        "fetch": [{"fmId": fm_id,
                   "intent": "startLocationUpdates" if advertised_id else "distributeKeys",
                   "mode": "shallow" if advertised_id else "proactive",
                   "ids": [advertised_id] if advertised_id else []}],
        "clientContext": {"apsToken": courier_token, "clientId": client_id,
                          "contextApp": "com.apple.findmy.findmylocateagent",
                          "shallowStats": {}, "autoMeConnectedDevice": []},
    }


@dataclass(frozen=True)
class Position:
    target_id: str
    latitude: float
    longitude: float
    accuracy: float
    timestamp: datetime
    floor: int | None = None

    @classmethod
    def from_snapshot(cls, value: dict, *, target_id: str, now: datetime, max_age: int):
        if value.get("target_id") != target_id:
            raise ValueError("Unselected target")
        # This is our normalized bridge schema, not an assumed Apple payload schema.
        numbers = [value[k] for k in ("latitude", "longitude", "accuracy")]
        if any(isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x)
               for x in numbers):
            raise ValueError("Invalid location number")
        lat, lon, accuracy = numbers
        if not -90 <= lat <= 90 or not -180 <= lon <= 180 or accuracy < 0:
            raise ValueError("Invalid location range")
        timestamp = datetime.fromisoformat(value["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("Timestamp requires timezone")
        timestamp = timestamp.astimezone(timezone.utc)
        age = (now - timestamp).total_seconds()
        if age < -60 or age > max_age:
            raise ValueError("Future or stale location")
        floor = value.get("floor")
        if floor is not None and type(floor) is not int:
            raise ValueError("Invalid location floor")
        return cls(target_id, lat, lon, accuracy, timestamp, floor)


def position_from_report(report: dict, *, target_id: str, now: datetime, max_age: int) -> Position:
    if not isinstance(report.get("plaintext"), dict):
        raise ValueError("Unsupported People report")
    plain = report["plaintext"]
    coordinate = plain.get("coordinate", plain)
    if not isinstance(coordinate, dict):
        raise ValueError("Invalid People coordinate")
    # The encrypted People report uses Apple's 2001 epoch. Current gateway
    # envelopes use Unix milliseconds and older envelopes use Apple seconds.
    apple_time = plain.get("timestamp")
    if apple_time is None:
        apple_time = report.get("locationTs")
    if type(apple_time) not in (int, float) or not math.isfinite(apple_time):
        raise ValueError("Invalid Apple report time")
    try:
        if plain.get("timestamp") is None and apple_time >= 100_000_000_000:
            timestamp = datetime.fromtimestamp(apple_time / 1000, timezone.utc)
        else:
            timestamp = datetime(2001, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=apple_time)
    except (OSError, OverflowError, ValueError) as error:
        raise ValueError("Invalid Apple report time") from error
    return Position.from_snapshot(
        {"target_id": target_id, "latitude": coordinate.get("latitude"),
         "longitude": coordinate.get("longitude"),
         "accuracy": plain.get("horizontalAccuracy", plain.get("accuracy")),
         "timestamp": timestamp.isoformat(), "floor": plain.get("floor")},
        target_id=target_id, now=now, max_age=max_age,
    )
