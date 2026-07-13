"""Small ElementTree-compatible facade that rejects DTD/entity declarations."""

import xml.etree.ElementTree as _ET
from pathlib import Path

ParseError = _ET.ParseError


def _checked(data):
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    upper = raw.upper()
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
