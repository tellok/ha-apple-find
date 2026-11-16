"""Verify the selected IDS sender and extract only the selected share key."""
import gzip
import json
import plistlib
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .apple_probe import PRIVATE
from .ids_wire import compact_public, expand_compact, protobuf_fields

from ..protocol import decode_share_key, open_pair_ec, public_bytes


def one(fields, number):
    values = fields.get(number, [])
    if len(values) != 1:
        raise ValueError("Missing or duplicate required protobuf field")
    return values[0]


def der_signature(raw):
    if len(raw) != 64:
        raise ValueError("Invalid NGM signature length")
    return utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def verified_directory_keys(identity):
    kt = protobuf_fields(identity["kt-loggable-data"])
    device = expand_compact(one(protobuf_fields(one(kt, 1)), 1))
    prekey = protobuf_fields(identity["client-data"]["public-message-ngm-device-prekey-data-key"])
    device.verify(der_signature(one(prekey, 2)),
        b"NGMPrekeySignature" + one(prekey, 1) + one(prekey, 3), ec.ECDSA(hashes.SHA256()))
    return device, expand_compact(one(prekey, 1))


def decrypt_selected_message(packet, directory, keys, diagnostic=None):
    if diagnostic is None:
        diagnostic = {}
    diagnostic["step"] = "sender_directory"
    if packet.get("E") != "pair-ec" or packet.get("c") != 242:
        raise ValueError("Unexpected Find My message format")
    matches = [i for i in directory.get("identities", []) if i["push-token"] == packet.get("t")]
    if len(matches) != 1:
        raise ValueError("Sender token does not uniquely match selected friend's directory")
    sender, _ = verified_directory_keys(matches[0])
    diagnostic["step"] = "encrypted_envelope"
    outer = protobuf_fields(packet["P"])
    diagnostic["wire_fields"] = sorted(outer)
    ephemeral = expand_compact(one(outer, 2))
    diagnostic["step"] = "signature_and_decryption"
    plaintext = open_pair_ec(receiver_prekey=keys["prekey"], receiver_device=keys["device"].public_key(),
        sender_device=sender, ephemeral=public_bytes(ephemeral), validator=one(outer, 99),
        signature=der_signature(one(outer, 3)), ciphertext=one(outer, 1))
    diagnostic["step"] = "plaintext_framing"
    if len(plaintext) < 4:
        raise ValueError("Truncated NGM padding")
    padding = int.from_bytes(plaintext[-4:], "little")
    if padding > 15 or padding + 4 > len(plaintext):
        raise ValueError("Invalid NGM padding")
    application = one(protobuf_fields(plaintext[:len(plaintext) - padding - 4]), 1)
    if application.startswith(b"\x1f\x8b"):
        application = gzip.decompress(application)
    diagnostic["step"] = "application_wrapper"
    wrapper = plistlib.loads(application)
    if isinstance(wrapper, dict):
        for field in ("T", "V"):
            value = wrapper.get(field)
            if type(value) is int and 0 <= value <= 255:
                diagnostic[field] = value
    if not isinstance(wrapper, dict) or wrapper.get("T") != 10 or wrapper.get("V") != 1:
        raise ValueError("Unexpected Find My application type/version")
    diagnostic["step"] = "application_payload"
    return plistlib.loads(wrapper["P"])


def selected_key(envelopes, fm_id):
    if not isinstance(envelopes, list) or len(envelopes) > 100:
        raise ValueError("Invalid application envelope list")
    matches = [entry for entry in envelopes if entry.get("entityIdentifier") == fm_id]
    if len(matches) != 1:
        raise ValueError("No unique envelope for selected share")
    entry = matches[0]
    blob = entry["privateKey"]["key"]["data"]
    advertised = entry["hashedAdvertisement"]["key"]["data"]
    if not isinstance(advertised, bytes) or len(advertised) != 32:
        raise ValueError("Invalid advertised location identifier")
    decode_share_key(blob)
    return {"fm_id": fm_id, "advertised": advertised, "private_key": blob, "index": entry["index"]}


if __name__ == "__main__":
    directory = plistlib.loads((PRIVATE / "selected-directory.plist").read_bytes())
    verified = [verified_directory_keys(i) for i in directory.get("identities", [])]
    print(json.dumps({"stage": "selected_directory_crypto", "verified_identities": len(verified)}))
