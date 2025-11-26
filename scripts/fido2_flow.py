#!/usr/bin/env python3
import os
import sys
import time
from typing import Any, Dict, Tuple

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import AttestationResponse, Ctap2, PinProtocolV2
from fido2.ctap2.pin import _pad_pin
from fido2.cose import CoseKey
from fido2.hid import CAPABILITY, CTAPHID, CtapHidDevice
from fido2.utils import sha256
from fido2.webauthn import AttestedCredentialData


CMD_GET_INFO = 0x04
CMD_CLIENT_PIN = 0x06


def first_device() -> CtapHidDevice:
    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise RuntimeError("No CTAP HID device found")
    dev = devices[0]
    if not (dev.capabilities & CAPABILITY.CBOR):
        raise RuntimeError("Device does not support CTAP2/CBOR")
    return dev


def send_cbor_raw(
    dev: CtapHidDevice, cmd: int, payload: Dict[int, Any] | None
) -> Tuple[int, Dict[int, Any] | None, bytes]:
    req = bytes([cmd])
    if payload is not None:
        req += cbor.encode(payload)
    resp = dev.call(CTAPHID.CBOR, req)
    status = resp[0]
    body = resp[1:]
    decoded = None
    if body:
        try:
            decoded = cbor.decode(body)
        except Exception as exc:  # noqa: BLE001
            decoded = {"decode_error": str(exc), "raw": body.hex()}
    return status, decoded, body


def get_key_agreement(dev: CtapHidDevice, proto: PinProtocolV2):
    status, decoded, _ = send_cbor_raw(
        dev, CMD_CLIENT_PIN, {1: proto.VERSION, 2: 2}
    )
    if status != 0 or not decoded or 1 not in decoded:
        raise RuntimeError(f"getKeyAgreement failed status=0x{status:02x} decoded={decoded}")
    peer_key = CoseKey.parse(decoded[1])
    key_agree, shared = proto.encapsulate(peer_key)
    return key_agree, shared, decoded


def set_pin(dev: CtapHidDevice, proto: PinProtocolV2, pin: str):
    key_agree, shared, decoded = get_key_agreement(dev, proto)
    print(f"setPIN: keyAgreement debug={decoded}")
    new_pin_enc = proto.encrypt(shared, _pad_pin(pin))
    pin_auth = proto.authenticate(shared, new_pin_enc)
    status, decoded, _ = send_cbor_raw(
        dev,
        CMD_CLIENT_PIN,
        {1: proto.VERSION, 2: 3, 3: key_agree, 4: pin_auth, 5: new_pin_enc},
    )
    return status, decoded


def change_pin(dev: CtapHidDevice, proto: PinProtocolV2, old_pin: str, new_pin: str):
    key_agree, shared, decoded = get_key_agreement(dev, proto)
    print(f"changePIN: keyAgreement debug={decoded}")
    new_pin_enc = proto.encrypt(shared, _pad_pin(new_pin))
    pin_hash_enc = proto.encrypt(shared, sha256(old_pin.encode())[:16])
    pin_auth = proto.authenticate(shared, new_pin_enc + pin_hash_enc)
    status, decoded, _ = send_cbor_raw(
        dev,
        CMD_CLIENT_PIN,
        {
            1: proto.VERSION,
            2: 4,
            3: key_agree,
            4: pin_auth,
            5: new_pin_enc,
            6: pin_hash_enc,
        },
    )
    return status, decoded


def get_pin_token(dev: CtapHidDevice, proto: PinProtocolV2, pin: str):
    key_agree, shared, decoded = get_key_agreement(dev, proto)
    print(f"getPINToken: keyAgreement debug={decoded}")
    pin_hash_enc = proto.encrypt(shared, sha256(pin.encode())[:16])
    status, decoded, body = send_cbor_raw(
        dev,
        CMD_CLIENT_PIN,
        {1: proto.VERSION, 2: 5, 3: key_agree, 6: pin_hash_enc},
    )
    if status != 0:
        return status, None, decoded
    if not decoded or 2 not in decoded:
        raise RuntimeError("No PIN token in response")
    token_enc = decoded[2]
    token = proto.decrypt(shared, token_enc)
    return status, token, decoded


def make_credential(ctap: Ctap2, proto: PinProtocolV2, pin_token: bytes):
    cdh = os.urandom(32)
    rp = {"id": "example.com", "name": "Example"}
    user = {"id": os.urandom(16), "name": "testuser", "displayName": "Test User"}
    key_params = [{"type": "public-key", "alg": -7}]
    pin_param = proto.authenticate(pin_token, cdh)
    print("Press the button for makeCredential…")
    resp = ctap.make_credential(
        cdh,
        rp,
        user,
        key_params,
        options={"rk": False, "uv": False},
        pin_uv_param=pin_param,
        pin_uv_protocol=proto.VERSION,
    )
    return resp, cdh


def get_assertion(
    ctap: Ctap2,
    proto: PinProtocolV2,
    pin_token: bytes,
    rp_id: str,
    cred_id: bytes,
):
    cdh = os.urandom(32)
    pin_param = proto.authenticate(pin_token, cdh)
    allow_list = [{"type": "public-key", "id": cred_id}]
    print("Press the button for getAssertion…")
    resp = ctap.get_assertion(
        rp_id,
        cdh,
        allow_list=allow_list,
        pin_uv_param=pin_param,
        pin_uv_protocol=proto.VERSION,
        options={"up": True, "uv": False},
    )
    return resp, cdh


def main():
    dev = first_device()
    print(f"Using device: {dev}")
    ctap = Ctap2(dev)
    proto = PinProtocolV2()

    first_pin = os.environ.get("FIDO_PIN", "123456")
    new_pin = os.environ.get("FIDO_PIN_NEW", "654321")

    print("=== setPIN ===")
    status, decoded = set_pin(dev, proto, first_pin)
    print(f"setPIN status=0x{status:02x} decoded={decoded}")
    pin_current = first_pin
    if status == 0:
        # Only attempt changePIN when we just set the first PIN
        print("=== changePIN ===")
        status_cp, decoded_cp = change_pin(dev, proto, first_pin, new_pin)
        print(f"changePIN status=0x{status_cp:02x} decoded={decoded_cp}")
        if status_cp == 0:
            pin_current = new_pin
        else:
            print("changePIN failed; continuing with original PIN")
    else:
        print("PIN already set; skipping changePIN and assuming current PIN is the new PIN value")
        pin_current = new_pin

    print("=== getPINToken ===")
    status, token, decoded = get_pin_token(dev, proto, pin_current)
    print(f"getPINToken status=0x{status:02x} decoded={decoded}")
    if status != 0 or token is None:
        sys.exit(1)
    print(f"PIN token len={len(token)}")

    try:
        att_resp, mc_cdh = make_credential(ctap, proto, token)
    except CtapError as e:
        print(f"makeCredential error: {e}")
        sys.exit(1)
    auth_data = att_resp.auth_data
    if not isinstance(auth_data.credential_data, AttestedCredentialData):
        print("No attested credential data returned")
        sys.exit(1)
    cred_id = auth_data.credential_data.credential_id
    print(f"Created credential id (hex): {cred_id.hex()}")

    try:
        ga_resp, ga_cdh = get_assertion(ctap, proto, token, "example.com", cred_id)
    except CtapError as e:
        print(f"getAssertion error: {e}")
        sys.exit(1)

    print("Assertion received")
    print(f"makeCredential clientDataHash: {mc_cdh.hex()}")
    print(f"getAssertion clientDataHash: {ga_cdh.hex()}")
    print(f"authData flags: 0x{auth_data.flags:02x} counter: {auth_data.counter}")
    sig = None
    if hasattr(ga_resp, "signature"):
        sig = ga_resp.signature
    elif isinstance(ga_resp, (list, tuple)) and ga_resp:
        first = ga_resp[0]
        sig = getattr(first, "signature", None)
    if sig is not None:
        print(f"assertion sig len: {len(sig)}")


if __name__ == "__main__":
    main()
