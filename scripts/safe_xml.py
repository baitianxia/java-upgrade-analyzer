"""Small ElementTree-compatible facade that rejects DTD/entity declarations."""

import xml.etree.ElementTree as _ET
from pathlib import Path

ParseError = _ET.ParseError


def _checked(data):
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    # XML declaration tokens are ASCII code points in every supported Unicode
    # encoding.  UTF-16/UTF-32 interleave NUL bytes, so a direct byte substring
    # search can miss a BOM-encoded DTD.  Removing NULs preserves those tokens
    # without decoding or expanding any untrusted entity content.
    upper = raw.replace(b"\x00", b"").upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ParseError("DTD and entity declarations are not allowed")
    return raw


def fromstring(text):
    return _ET.fromstring(_checked(text))


def parse(source):
    if hasattr(source, "read"):
        data = source.read()
    else:
        data = Path(source).read_bytes()
    return _ET.ElementTree(fromstring(data))
