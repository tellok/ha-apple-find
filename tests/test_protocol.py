from datetime import datetime, timedelta, timezone

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

from custom_components.apple_find.protocol import (
    Position, decode_share_key, decrypt_report, fetch_body, open_pair_ec, position_from_report,
    public_bytes,
)


def test_p224_report_roundtrip_and_tamper_rejection():
    receiver = ec.generate_private_key(ec.SECP224R1())
    sender = ec.generate_private_key(ec.SECP224R1())
    point = public_bytes(sender.public_key())
    secret = sender.exchange(ec.ECDH(), receiver.public_key())
    material = X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=point).derive(secret)
    blob = point + AESGCM(material[:16]).encrypt(material[16:], b'{"test":true}', None)
    assert decrypt_report(blob, receiver) == {"test": True}
    with pytest.raises(InvalidTag):
        decrypt_report(blob[:-1] + bytes([blob[-1] ^ 1]), receiver)


def test_share_key_point_must_match_scalar():
    key = ec.generate_private_key(ec.SECP224R1())
    blob = public_bytes(key.public_key()) + key.private_numbers().private_value.to_bytes(28, "big")
    assert decode_share_key(blob).private_numbers() == key.private_numbers()
    with pytest.raises(ValueError):
        decode_share_key(blob[:57] + (1).to_bytes(28, "big"))


@pytest.mark.parametrize("version", [12, 13])
def test_pair_ec_authenticates_sender_before_decryption(version):
    prekey, receiver, sender, ephemeral = [ec.generate_private_key(ec.SECP256R1()) for _ in range(4)]
    point = public_bytes(ephemeral.public_key())
    rx, sx, px = [public_bytes(k.public_key())[1:33] for k in (receiver, sender, prekey)]
    secret = ephemeral.exchange(ec.ECDH(), prekey.public_key())
    material = HKDF(algorithm=hashes.SHA256(), length=48, salt=b"LastPawn-MessageKeys", info=b"").derive(secret)
    encryptor = Cipher(algorithms.AES(material[:32]), modes.CTR(material[32:])).encryptor()
    encrypted = encryptor.update(b"synthetic key envelope") + encryptor.finalize()
    signed = secret + px + point[1:33] + rx + encrypted
    signature = sender.sign(signed, ec.ECDSA(hashes.SHA256()))
    args = dict(receiver_prekey=prekey, receiver_device=receiver.public_key(),
                sender_device=sender.public_key(), ephemeral=point,
                validator=sx[:2] + rx[:2] + px[:2] + bytes([version]), signature=signature,
                ciphertext=encrypted)
    assert open_pair_ec(**args) == b"synthetic key envelope"
    with pytest.raises(InvalidSignature):
        open_pair_ec(**(args | {"signature": b"bad signature"}))
    with pytest.raises(ValueError):
        open_pair_ec(**(args | {"validator": b"wrong"}))


def test_request_is_scoped_to_one_share():
    body = fetch_body("selected-friend", "courier", "client")
    assert body["fetch"] == [{"fmId": "selected-friend", "intent": "distributeKeys", "mode": "proactive", "ids": []}]
    assert body["clientContext"] == {
        "apsToken": "courier", "clientId": "client",
        "contextApp": "com.apple.findmy.findmylocateagent",
        "shallowStats": {}, "autoMeConnectedDevice": [],
    }
    assert fetch_body("selected-friend", "courier", "client", "key-id")["fetch"][0]["ids"] == ["key-id"]


NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)
SNAPSHOT = dict(target_id="selected-friend", latitude=25.0, longitude=121.0, accuracy=20,
                timestamp=NOW.isoformat())


@pytest.mark.parametrize("change", [
    {"target_id": "other-friend"}, {"latitude": 91}, {"longitude": float("nan")},
    {"accuracy": -1}, {"latitude": True}, {"timestamp": (NOW-timedelta(hours=1)).isoformat()},
    {"timestamp": (NOW+timedelta(hours=1)).isoformat()}, {"timestamp": "2026-10-14T00:00:00"},
])
def test_invalid_snapshot_rejected(change):
    with pytest.raises(ValueError):
        Position.from_snapshot(SNAPSHOT | change, target_id="selected-friend", now=NOW, max_age=300)


def test_valid_snapshot():
    assert Position.from_snapshot(SNAPSHOT, target_id="selected-friend", now=NOW, max_age=300).accuracy == 20


def test_people_report_preserves_apple_epoch_and_rejects_stale_values():
    epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
    report = {"locationTs": (NOW - epoch).total_seconds(), "plaintext": {
        "coordinate": {"latitude": 25.0, "longitude": 121.0},
        "horizontalAccuracy": 20,
    }}
    position = position_from_report(report, target_id="selected-friend", now=NOW, max_age=300)
    assert (position.latitude, position.longitude, position.accuracy, position.timestamp) == (25.0, 121.0, 20.0, NOW)
    report["locationTs"] = int(NOW.timestamp() * 1000)
    assert position_from_report(report, target_id="selected-friend", now=NOW, max_age=300) == position
    report["plaintext"].update(timestamp=(NOW - epoch).total_seconds(), floor=8)
    report["locationTs"] += 1000
    actual = position_from_report(report, target_id="selected-friend", now=NOW, max_age=300)
    assert actual.timestamp == NOW and actual.floor == 8
    with pytest.raises(ValueError, match="stale"):
        position_from_report(report, target_id="selected-friend", now=NOW + timedelta(minutes=6), max_age=300)
