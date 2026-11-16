import plistlib
import struct
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def test_verified_ngm_wire_envelope_selects_only_requested_share(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    from ids_wire import bytes_field, compact_key, compact_public, kt_data, prekey_data, raw_signature
    from location_pipeline import decrypt_selected_message, selected_key
    from custom_components.apple_findmy_people.protocol import public_bytes

    sender, receiver, receiver_prekey, ephemeral = [compact_key() for _ in range(4)]
    sender_prekey = compact_key()
    sharing = ec.generate_private_key(ec.SECP224R1())
    blob = public_bytes(sharing.public_key()) + sharing.private_numbers().private_value.to_bytes(28, "big")
    envelope = {"entityIdentifier": "selected-share", "index": 1,
                "hashedAdvertisement": {"key": {"data": b"a" * 32}},
                "privateKey": {"key": {"data": blob}}}
    application = plistlib.dumps({"T": 10, "V": 1,
        "P": plistlib.dumps([envelope], fmt=plistlib.FMT_BINARY)}, fmt=plistlib.FMT_BINARY)
    inner = bytes_field(1, application)
    padding = (-len(inner)) % 16
    plaintext = inner + b"\x00" * padding + struct.pack("<I", padding)
    secret = ephemeral.exchange(ec.ECDH(), receiver_prekey.public_key())
    material = HKDF(algorithm=hashes.SHA256(), length=48, salt=b"LastPawn-MessageKeys", info=b"").derive(secret)
    encrypt = Cipher(algorithms.AES(material[:32]), modes.CTR(material[32:])).encryptor()
    ciphertext = encrypt.update(plaintext) + encrypt.finalize()
    signed = (secret + compact_public(receiver_prekey) + compact_public(ephemeral)
              + compact_public(receiver) + ciphertext)
    validator = compact_public(sender)[:2] + compact_public(receiver)[:2] + compact_public(receiver_prekey)[:2] + b"\x0c"
    outer = (bytes_field(1, ciphertext) + bytes_field(2, compact_public(ephemeral))
             + bytes_field(3, raw_signature(sender, signed)) + bytes_field(99, validator))
    identity = {"push-token": b"sender-token", "kt-loggable-data": kt_data(sender),
                "client-data": {"public-message-ngm-device-prekey-data-key": prekey_data(sender, sender_prekey)}}
    packet = {"c": 242, "E": "pair-ec", "P": outer, "t": b"sender-token"}
    directory = {"identities": [identity]}
    keys = {"prekey": receiver_prekey, "device": receiver}
    decrypted = decrypt_selected_message(packet, directory, keys)
    assert selected_key(decrypted, "selected-share")["private_key"] == blob
    with pytest.raises(ValueError, match="selected share"):
        selected_key(decrypted, "another-share")
    with pytest.raises(ValueError, match="Sender token"):
        decrypt_selected_message(packet | {"t": b"other-token"}, directory, keys)
    corrupted = bytes_field(1, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])) + outer[len(bytes_field(1, ciphertext)):]
    with pytest.raises(InvalidSignature):
        decrypt_selected_message(packet | {"P": corrupted}, directory, keys)
