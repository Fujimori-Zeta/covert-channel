"""Reversible text encodings used by the offline simulations."""

import base64


SCHEMES = ("base32", "hex", "urlsafe")


def encode_bytes(payload: bytes, scheme: str) -> str:
    """Encode bytes without padding so a frame stays easy to inspect."""
    if scheme == "base32":
        return base64.b32encode(payload).decode("ascii").rstrip("=").lower()
    if scheme == "hex":
        return payload.hex()
    if scheme == "urlsafe":
        return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    raise ValueError(f"unknown encoding scheme: {scheme}")


def decode_bytes(value: str, scheme: str) -> bytes:
    """Reverse :func:`encode_bytes`, restoring any required padding."""
    try:
        if scheme == "base32":
            padded = value.upper() + "=" * (-len(value) % 8)
            return base64.b32decode(padded)
        if scheme == "hex":
            return bytes.fromhex(value)
        if scheme == "urlsafe":
            padded = value + "=" * (-len(value) % 4)
            return base64.urlsafe_b64decode(padded)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"invalid {scheme} data") from exc
    raise ValueError(f"unknown encoding scheme: {scheme}")
