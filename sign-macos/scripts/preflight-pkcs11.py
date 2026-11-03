"""Discover the configured PKCS#11 key without invoking any signing operation."""

import ctypes
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa


class Attribute(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_ulong),
        ("value", ctypes.c_void_p),
        ("length", ctypes.c_ulong),
    ]


def preflight(library: Path, certificate: Path) -> None:
    """Use the provider's read-only key discovery, not a trial signature."""
    if os.environ.get("AKV_PKCS11_BACKEND") != "signer-service":
        raise ValueError("PKCS#11 preflight requires the signer-service backend")
    module = ctypes.CDLL(str(library))
    ulong = ctypes.c_ulong
    pointer = ctypes.c_void_p
    signatures = {
        "C_Initialize": [pointer],
        "C_Finalize": [pointer],
        "C_GetSlotList": [ctypes.c_ubyte, ctypes.POINTER(ulong), ctypes.POINTER(ulong)],
        "C_OpenSession": [ulong, ulong, pointer, pointer, ctypes.POINTER(ulong)],
        "C_CloseSession": [ulong],
        "C_FindObjectsInit": [ulong, ctypes.POINTER(Attribute), ulong],
        "C_FindObjects": [ulong, ctypes.POINTER(ulong), ulong, ctypes.POINTER(ulong)],
        "C_FindObjectsFinal": [ulong],
        "C_GetAttributeValue": [ulong, ulong, ctypes.POINTER(Attribute), ulong],
    }
    for name, arguments in signatures.items():
        function = getattr(module, name)
        function.argtypes = arguments
        function.restype = ulong

    def call(name: str, *arguments: object) -> None:
        result = getattr(module, name)(*arguments)
        if result:
            raise ValueError(
                f"PKCS#11 preflight {name} failed (0x{result:08x}); "
                "key discovery is not verified"
            )

    call("C_Initialize", None)
    try:
        slot, count = ulong(), ulong(1)
        call("C_GetSlotList", 1, ctypes.byref(slot), ctypes.byref(count))
        if count.value != 1:
            raise ValueError("PKCS#11 preflight requires exactly one slot")
        session = ulong()
        # CKF_SERIAL_SESSION, without CKF_RW_SESSION.
        call("C_OpenSession", slot, 4, None, None, ctypes.byref(session))
        try:
            key_class = ulong(3)  # CKO_PRIVATE_KEY: discovery only.
            label = ctypes.create_string_buffer(
                os.environ["SIGNER_SERVICE_KEY_LABEL"].encode()
            )
            template = (Attribute * 2)(
                Attribute(
                    0,
                    ctypes.cast(ctypes.byref(key_class), pointer),
                    ctypes.sizeof(key_class),
                ),
                Attribute(3, ctypes.cast(label, pointer), len(label.value)),
            )
            call("C_FindObjectsInit", session, template, 2)
            try:
                objects, count = (ulong * 2)(), ulong()
                # This forces the real provider's OIDC/GetPublicKeys path.
                call("C_FindObjects", session, objects, 2, ctypes.byref(count))
                if count.value != 1:
                    raise ValueError(
                        "PKCS#11 preflight did not discover exactly one key"
                    )
            finally:
                call("C_FindObjectsFinal", session)

            def attribute(kind: int) -> bytes:
                value = Attribute(kind, None, 0)
                call("C_GetAttributeValue", session, objects[0], ctypes.byref(value), 1)
                if not 0 < value.length <= 16384:
                    raise ValueError("Invalid PKCS#11 public attribute length")
                buffer = ctypes.create_string_buffer(value.length)
                value.value = ctypes.cast(buffer, pointer)
                call("C_GetAttributeValue", session, objects[0], ctypes.byref(value), 1)
                return buffer.raw[: value.length]

            if attribute(0x102) != os.environ["SIGNER_SERVICE_KEY_ID"].encode():
                raise ValueError("PKCS#11 preflight returned a different key ID")
            public_key = x509.load_pem_x509_certificate(
                certificate.read_bytes()
            ).public_key()
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TypeError("PKCS#11 preflight requires an RSA certificate")
            numbers = public_key.public_numbers()
            if (
                int.from_bytes(attribute(0x120), "big") != numbers.n
                or int.from_bytes(attribute(0x122), "big") != numbers.e
            ):
                raise ValueError(
                    "PKCS#11 preflight key does not match the pinned certificate"
                )
        finally:
            call("C_CloseSession", session)
    finally:
        call("C_Finalize", None)
    print(
        "PKCS#11 key discovery and pinned certificate verified; no signature requested."
    )


if __name__ == "__main__":
    try:
        preflight(Path(sys.argv[1]), Path(sys.argv[2]))
    except (
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as error:
        sys.exit(str(error))
