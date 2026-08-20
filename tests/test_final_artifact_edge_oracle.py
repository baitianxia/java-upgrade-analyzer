import base64
import errno
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import edge_truth  # noqa: E402
import binary_asm_helper  # noqa: E402
import binary_artifact_diff  # noqa: E402
import binary_validation_oracle  # noqa: E402
import final_artifact_edge_oracle as oracle  # noqa: E402
from binary_asm_helper import BinaryClassInput  # noqa: E402
from binary_fact_store import BinaryFactStore  # noqa: E402
from binary_first_model import ArtifactInstance  # noqa: E402


JDK_TOOLS = shutil.which("javac") and shutil.which("jar") and shutil.which("javap")

# Real JVM classfiles generated once with ASM. Keeping the bytes in the test
# makes the historical/source-illegal name boundary and ConstantDynamic
# coverage reproducible without adding ASM as a test dependency.
SAME_NAME_METHOD_CLASS = base64.b64decode(
    "yv66vgAAADAAGQEAAWEHAAEBABBqYXZhL2xhbmcvT2JqZWN0BwADAQAHY2xhc3MkMAEA"
    "EUxqYXZhL2xhbmcvQ2xhc3M7AQAGPGluaXQ+AQADKClWDAAHAAgKAAQACQEARihMY29t"
    "L2NzaWkvcGUvc2VjdXJpdHkvRW5EZWNyeXB0O0xqYXZhL2xhbmcvU3RyaW5nOylMamF2"
    "YS9sYW5nL1N0cmluZzsBAB5jb20vY3NpaS9wZS9zZWN1cml0eS9FbkRlY3J5cHQHAAwB"
    "AAdlbkNyeXB0AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsM"
    "AA4ADwsADQAQAQAHZGVDcnlwdAwAEgAPCwANABMMAAUABgkAAgAVAQAJU3ludGhldGlj"
    "AQAEQ29kZQABAAIABAAAAAEACAAFAAYAAQAXAAAAAAACAAEABwAIAAEAGAAAABEAAQAB"
    "AAAABSq3AAqxAAAAAAABAAEACwABABgAAACgAAIAAwAAAJQrLLkAEQIATSssuQAUAgBN"
    "Kyy5ABECAE0rLLkAFAIATSssuQARAgBNKyy5ABQCAE0rLLkAEQIATSssuQAUAgBNKyy5"
    "ABECAE0rLLkAFAIATSssuQARAgBNKyy5ABQCAE0rLLkAEQIATSssuQAUAgBNKyy5ABEC"
    "AE0rLLkAFAIATbIAFlcSDbMAFrIAFlcSDbMAFiywAAAAAAAA"
)
CONSTANT_DYNAMIC_CLASS = base64.b64decode(
    "yv66vgAAADcAKQEAFGZpeHR1cmUvQ29uZHlGaXh0dXJlBwABAQAQamF2YS9sYW5nL09i"
    "amVjdAcAAwEABGxvYWQBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwEADmZpeHR1cmUvVGFy"
    "Z2V0BwAHAQAEY2FsbAEAAygpVgwACQAKCgAIAAsPBgAMAQAFVkFMVUUBAAFJDAAOAA8J"
    "AAgAEA8CABEBABFmaXh0dXJlL0Jvb3RzdHJhcAcAEwEACWJvb3RzdHJhcAEAnChMamF2"
    "YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cDtMamF2YS9sYW5nL1N0cmlu"
    "ZztMamF2YS9sYW5nL0NsYXNzO0xqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZTtM"
    "amF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGU7KUxqYXZhL2xhbmcvT2JqZWN0OwwA"
    "FQAWCgAUABcPBgAYAQAFdmFsdWUBABJMamF2YS9sYW5nL09iamVjdDsMABoAGxEAAAAc"
    "AQAGaGFuZGxlAQAhKClMamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGU7AQAGbmVz"
    "dGVkAQAFaW5uZXIMACEAGxEAAAAiAQAFb3V0ZXIMACQAGxEAAQAlAQAEQ29kZQEAEEJv"
    "b3RzdHJhcE1ldGhvZHMAAQACAAQAAAAAAAMACQAFAAYAAQAnAAAADwABAAAAAAADEh2w"
    "AAAAAAAJAB4AHwABACcAAAAPAAEAAAAAAAMSDbAAAAAAAAkAIAAGAAEAJwAAAA8AAQAA"
    "AAAAAxImsAAAAAAAAQAoAAAAEAACABkAAgANABIAGQABACM="
)
SOURCE_ILLEGAL_MEMBER_NAMES_CLASS = base64.b64decode(
    "yv66vgAAAD0AGgEAEUlkZW50aWZpZXJGaXh0dXJlBwABAQAQamF2YS9sYW5nL09i"
    "amVjdAcAAwEACnNwYWNlIG5hbWUBAAMoKVYBAApxdW90ZSJuYW1lAQAKYmFja1xz"
    "bGFzaAEACWxpbmUKZmVlZAEACHRhYgluYW1lAQAI57uE5ZCIzIEBAAZjYWxsZXIM"
    "AAUABgoAAgANDAAHAAYKAAIADwwACAAGCgACABEMAAkABgoAAgATDAAKAAYKAAIA"
    "FQwACwAGCgACABcBAARDb2RlACEAAgAEAAAAAAAHAAkABQAGAAEAGQAAAA0AAAAA"
    "AAAAAbEAAAAAAAkABwAGAAEAGQAAAA0AAAAAAAAAAbEAAAAAAAkACAAGAAEAGQAA"
    "AA0AAAAAAAAAAbEAAAAAAAkACQAGAAEAGQAAAA0AAAAAAAAAAbEAAAAAAAkACgAG"
    "AAEAGQAAAA0AAAAAAAAAAbEAAAAAAAkACwAGAAEAGQAAAA0AAAAAAAAAAbEAAAAA"
    "AAkADAAGAAEAGQAAAB8AAAAAAAAAE7gADrgAELgAErgAFLgAFrgAGLEAAAAAAAA="
)
BOOTSTRAP_TYPE_CONSTANTS_CLASS = base64.b64decode(
    "yv66vgAAADcATwEAFGF1ZGl0L0Jvb3RzdHJhcFR5cGVzBwABAQAQamF2YS9sYW5nL09iamVj"
    "dAcAAwEABGluZHkBAAMoKVYBADEoTGphdmEvbGFuZy9TdHJpbmc7W0xhdWRpdC9UaGluZzsp"
    "TGphdmEvdXRpbC9NYXA7EAAHAQAOamF2YS91dGlsL0xpc3QHAAkBACcoTGphdmEvdGltZS9J"
    "bnN0YW50OylMamF2YS90aW1lL1pvbmVJZDsQAAsBABBbTGphdmEvdXRpbC9TZXQ7BwANAQAO"
    "Y29uZHlCb290c3RyYXABAIIoTGphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcyRMb29r"
    "dXA7TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9DbGFzcztMamF2YS9sYW5nL09iamVj"
    "dDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DAAPABAKAAIAEQ8GABIB"
    "AAZuZXN0ZWQBABRMamF2YS91dGlsL09wdGlvbmFsOwwAFAAVEQAAABYBAA1pbmR5Qm9vdHN0"
    "cmFwAQCpKExqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwO0xqYXZhL2xh"
    "bmcvU3RyaW5nO0xqYXZhL2xhbmcvaW52b2tlL01ldGhvZFR5cGU7TGphdmEvbGFuZy9PYmpl"
    "Y3Q7TGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvaW52"
    "b2tlL0NhbGxTaXRlOwwAGAAZCgACABoPBgAbAQAEY2FsbAEAJChMamF2YS9pby9GaWxlOylM"
    "amF2YS9uaW8vZmlsZS9QYXRoOwwAHQAeEgABAB8BAAVjb25keQEALihMamF2YS9tYXRoL0Jp"
    "Z0RlY2ltYWw7KUxqYXZhL21hdGgvQmlnSW50ZWdlcjsQACIBAAxqYXZhL25ldC9VUkkHACQB"
    "AAVvdXRlcgEAHUxqYXZhL3V0aWwvY29uY3VycmVudC9GdXR1cmU7DAAmACcRAAIAKAEABmRp"
    "cmVjdAEAVShMamF2YS9sYW5nL1N0cmluZztbTGphdmEvdXRpbC9MaXN0O1tbTGF1ZGl0L1Ro"
    "aW5nO0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS91dGlsL01hcDsQACsBAAxkaXJlY3RIYW5k"
    "bGUBABJhdWRpdC9IYW5kbGVUYXJnZXQHAC4BAAdjb252ZXJ0AQAgKExqYXZhL3NxbC9EYXRl"
    "OylMamF2YS9zcWwvVGltZTsMADAAMQoALwAyDwYAMwEAEWRpcmVjdEZpZWxkSGFuZGxlAQAF"
    "VkFMVUUBABJMamF2YS91dGlsL0xvY2FsZTsMADYANwkALwA4DwIAOQEACm1lbWJlclJlZnMB"
    "ABVhdWRpdC9JbnRlcmZhY2VUYXJnZXQHADwBAAZhY2NlcHQBADsoTGphdmEvdXRpbC9VVUlE"
    "O1tMamF2YS91dGlsL0N1cnJlbmN5OylMamF2YS91dGlsL0NhbGVuZGFyOwwAPgA/CwA9AEAB"
    "ABFhdWRpdC9GaWVsZFRhcmdldAcAQgEAFFtbTGphdmEvdXRpbC9Mb2NhbGU7DAA2AEQJAEMA"
    "RQEAEWF1ZGl0L0NoaWxkVGFyZ2V0BwBHAQAJaW5oZXJpdGVkAQAoKExqYXZhL3RpbWUvRHVy"
    "YXRpb247KUxqYXZhL3RpbWUvUGVyaW9kOwwASQBKCgBIAEsBAARDb2RlAQAQQm9vdHN0cmFw"
    "TWV0aG9kcwAhAAIABAAAAAAABgAJAAUABgABAE0AAAAUAAEAAAAAAAgBugAgAABXsQAAAAAA"
    "CQAhAAYAAQBNAAAAEAABAAAAAAAEEilXsQAAAAAACQAqAAYAAQBNAAAAEAABAAAAAAAEEixX"
    "sQAAAAAACQAtAAYAAQBNAAAAEAABAAAAAAAEEjRXsQAAAAAACQA1AAYAAQBNAAAAEAABAAAA"
    "AAAEEjpXsQAAAAAACQA7AAYAAQBNAAAAHwADAAAAAAATAQEBuQBBAwBXsgBGVwG4AExXsQAA"
    "AAAAAQBOAAAAHgADABMAAgAMAA4AHAADAAgACgAXABMAAwAjACUAFw=="
)


def _modified_utf8(value: str) -> bytes:
    encoded = bytearray()
    utf16 = value.encode("utf-16-be", errors="surrogatepass")
    for offset in range(0, len(utf16), 2):
        code_unit = int.from_bytes(utf16[offset:offset + 2], "big")
        if code_unit == 0:
            encoded.extend(b"\xc0\x80")
        elif code_unit <= 0x7F:
            encoded.append(code_unit)
        elif code_unit <= 0x7FF:
            encoded.extend((
                0xC0 | (code_unit >> 6),
                0x80 | (code_unit & 0x3F),
            ))
        else:
            encoded.extend((
                0xE0 | (code_unit >> 12),
                0x80 | ((code_unit >> 6) & 0x3F),
                0x80 | (code_unit & 0x3F),
            ))
    return bytes(encoded)


def _minimal_static_edge_class(
    owner: str, member: str, descriptor: str = "()V",
) -> bytes:
    """Build a Java-8 class whose sole method invokes System.gc()."""
    u2 = lambda value: int(value).to_bytes(2, "big")
    u4 = lambda value: int(value).to_bytes(4, "big")

    def utf8(value: str) -> bytes:
        encoded = _modified_utf8(value)
        return b"\x01" + u2(len(encoded)) + encoded

    constant_pool = b"".join((
        utf8(owner),                         # 1
        b"\x07" + u2(1),                   # 2 Class owner
        utf8("java/lang/Object"),            # 3
        b"\x07" + u2(3),                   # 4 Class Object
        utf8(member),                        # 5
        utf8(descriptor),                    # 6
        utf8("Code"),                       # 7
        utf8("java/lang/System"),            # 8
        b"\x07" + u2(8),                   # 9 Class System
        utf8("gc"),                          # 10
        utf8("()V"),                         # 11
        b"\x0c" + u2(10) + u2(11),         # 12 NameAndType gc:()V
        b"\x0a" + u2(9) + u2(12),          # 13 Methodref System.gc
    ))
    code = b"\xb8\x00\x0d\xb1"
    code_attribute = b"".join((
        u2(7), u4(16),
        u2(0),       # max_stack
        u2(8),       # max_locals (safely covers unusual test descriptors)
        u4(len(code)), code,
        u2(0),       # exception_table_length
        u2(0),       # Code attributes_count
    ))
    method_info = b"".join((
        u2(0x0009), u2(5), u2(6), u2(1), code_attribute,
    ))
    return b"".join((
        b"\xca\xfe\xba\xbe", u2(0), u2(52),
        u2(14), constant_pool,
        u2(0x0021), u2(2), u2(4),
        u2(0),       # interfaces_count
        u2(0),       # fields_count
        u2(1), method_info,
        u2(0),       # class attributes_count
    ))


def _minimal_ldc_handle_class(
    *, member_reference_tag: int, handle_kind: int,
) -> bytes:
    """Build an LDC MethodHandle class with no BootstrapMethods attribute."""
    u2 = lambda value: int(value).to_bytes(2, "big")
    u4 = lambda value: int(value).to_bytes(4, "big")

    def utf8(value: str) -> bytes:
        encoded = _modified_utf8(value)
        return b"\x01" + u2(len(encoded)) + encoded

    field = member_reference_tag == 9
    member = "VALUE" if field else "call"
    descriptor = "I" if field else "()V"
    owner = f"LdcHandle{member_reference_tag}"
    constant_pool = b"".join((
        utf8(owner),                         # 1
        b"\x07" + u2(1),                   # 2 Class owner
        utf8("java/lang/Object"),            # 3
        b"\x07" + u2(3),                   # 4 Class Object
        utf8("load"),                        # 5
        utf8("()V"),                         # 6
        utf8("Code"),                       # 7
        utf8("SameOwner"),                   # 8
        b"\x07" + u2(8),                   # 9 Class SameOwner
        utf8(member),                        # 10
        utf8(descriptor),                    # 11
        b"\x0c" + u2(10) + u2(11),         # 12 NameAndType
        bytes((member_reference_tag,)) + u2(9) + u2(12),  # 13 member ref
        b"\x0f" + bytes((handle_kind,)) + u2(13),         # 14 handle
    ))
    code = b"\x12\x0e\x57\xb1"  # ldc #14; pop; return
    code_attribute = b"".join((
        u2(7), u4(16), u2(1), u2(0), u4(4), code, u2(0), u2(0),
    ))
    method_info = b"".join((
        u2(0x0009), u2(5), u2(6), u2(1), code_attribute,
    ))
    return b"".join((
        b"\xca\xfe\xba\xbe", u2(0), u2(52),
        u2(15), constant_pool,
        u2(0x0021), u2(2), u2(4),
        u2(0), u2(0), u2(1), method_info, u2(0),
    ))


def _minimal_ldc_method_type_class(
    method_type_descriptor: str, *, owner: str = "MethodTypeFixture",
) -> bytes:
    """Build a real LDC CONSTANT_MethodType class without javac normalization."""
    u2 = lambda value: int(value).to_bytes(2, "big")
    u4 = lambda value: int(value).to_bytes(4, "big")

    def utf8(value: str) -> bytes:
        encoded = _modified_utf8(value)
        return b"\x01" + u2(len(encoded)) + encoded

    constant_pool = b"".join((
        utf8(owner),                         # 1
        b"\x07" + u2(1),                   # 2 Class owner
        utf8("java/lang/Object"),            # 3
        b"\x07" + u2(3),                   # 4 Class Object
        utf8("load"),                        # 5
        utf8("()V"),                         # 6
        utf8("Code"),                       # 7
        utf8(method_type_descriptor),         # 8 MethodType descriptor
        b"\x10" + u2(8),                   # 9 CONSTANT_MethodType
    ))
    code = b"\x12\x09\x57\xb1"  # ldc #9; pop; return
    code_attribute = b"".join((
        u2(7), u4(16), u2(1), u2(0), u4(4), code, u2(0), u2(0),
    ))
    method_info = b"".join((
        u2(0x0009), u2(5), u2(6), u2(1), code_attribute,
    ))
    return b"".join((
        b"\xca\xfe\xba\xbe", u2(0), u2(52),
        u2(10), constant_pool,
        u2(0x0021), u2(2), u2(4),
        u2(0), u2(0), u2(1), method_info, u2(0),
    ))


def _minimal_reference_edge_class(
    *, target_owner: str, target_member: str, target_descriptor: str,
    literal_owner: str = "java/lang/String",
) -> bytes:
    """Build one invokestatic plus one class-literal reference."""
    u2 = lambda value: int(value).to_bytes(2, "big")
    u4 = lambda value: int(value).to_bytes(4, "big")

    def utf8(value: str) -> bytes:
        encoded = _modified_utf8(value)
        return b"\x01" + u2(len(encoded)) + encoded

    constant_pool = b"".join((
        utf8("ReferenceCaller"),              # 1
        b"\x07" + u2(1),                    # 2 Class caller
        utf8("java/lang/Object"),             # 3
        b"\x07" + u2(3),                    # 4 Class Object
        utf8("run"),                          # 5
        utf8("()V"),                          # 6
        utf8("Code"),                        # 7
        utf8(target_owner),                   # 8
        b"\x07" + u2(8),                    # 9 Class target
        utf8(target_member),                  # 10
        utf8(target_descriptor),              # 11
        b"\x0c" + u2(10) + u2(11),          # 12 NameAndType
        b"\x0a" + u2(9) + u2(12),           # 13 Methodref
        utf8(literal_owner),                  # 14
        b"\x07" + u2(14),                   # 15 Class literal
    ))
    prefix = b"\x01" if target_descriptor != "()V" else b""
    code = prefix + b"\xb8\x00\x0d\x12\x0f\x57\xb1"
    code_attribute = b"".join((
        u2(7), u4(12 + len(code)), u2(1), u2(0),
        u4(len(code)), code, u2(0), u2(0),
    ))
    method_info = b"".join((
        u2(0x0009), u2(5), u2(6), u2(1), code_attribute,
    ))
    return b"".join((
        b"\xca\xfe\xba\xbe", u2(0), u2(52),
        u2(16), constant_pool,
        u2(0x0021), u2(2), u2(4),
        u2(0), u2(0), u2(1), method_info, u2(0),
    ))


def _fake_artifact(path: Path, class_entries: list[str], marker: bytes = b"class") -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for index, entry in enumerate(class_entries):
            archive.writestr(entry, marker + str(index).encode("ascii"))
    return path


def _fake_parse_result(entry, artifact_sha256, *, failure: str = "") -> dict:
    member = Path(entry.artifact_entry).stem.lower()
    row = oracle._edge_row(
        artifact_sha256,
        entry.artifact_entry,
        "21.0.1",
        "fixture.Caller",
        member,
        "()V",
        ("fixture.Dependency", member, "()V"),
        "invokestatic",
        0,
    )
    return {
        "rows": [row],
        "failures": [f"{entry.artifact_entry}: {failure}"] if failure else [],
        "completed": True,
        "parsed": True,
    }


class FinalArtifactEdgeOraclePerformanceTest(unittest.TestCase):
    def setUp(self):
        oracle.clear_immutable_oracle_cache()

    def test_javap_command_contract_fixes_locale_and_output_encoding(self):
        command = oracle._javap_command("javap", "-version")

        self.assertEqual(command[0], "javap")
        self.assertEqual(command[-1], "-version")
        self.assertEqual(
            tuple(command[1:-1]), oracle.JAVAP_STABLE_JVM_OPTIONS
        )
        self.assertIn("-J-Dfile.encoding=UTF-8", command)
        self.assertIn("-J-Dsun.stdout.encoding=UTF-8", command)
        self.assertIn("-J-Dstdout.encoding=UTF-8", command)
        self.assertIn("-J-Duser.language=en", command)
        self.assertIn("-J-Duser.country=US", command)

        completed = subprocess.CompletedProcess(
            command, 0, stdout="21.0.8\n", stderr=""
        )
        with patch.object(
            oracle, "run_managed_subprocess", return_value=completed
        ) as run:
            self.assertEqual(
                oracle._javap_version("javap", timeout=1.0), "21.0.8"
            )
        self.assertEqual(run.call_args.args[0], command)

    def test_scan_rejects_unsafe_private_snapshot_before_extraction(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "unsafe.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("../escaped.class", b"not-a-class")

            result = oracle.scan_final_artifact(artifact)

        self.assertFalse(result["complete"])
        self.assertTrue(any(
            "ARCHIVE_ENTRY_PATH_UNSAFE" in failure
            for failure in result["failures"]
        ), result["failures"])

    def test_atomic_replace_after_inspection_cannot_change_scanned_bytes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "artifact.jar"
            replacement = root / "replacement.jar"
            safe_class = _minimal_static_edge_class("safe/Snapshot", "run")
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("safe/Snapshot.class", safe_class)
            expected_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr("../Evil.class", b"unchecked replacement")

            inspected_paths = []
            parsed_entries = []
            real_inspect = oracle.inspect_archive_stream
            original_read_bytes = Path.read_bytes

            def inspect_then_replace(snapshot_handle, **limits):
                inspected_paths.append(Path(snapshot_handle.name))
                result = real_inspect(snapshot_handle, **limits)
                os.replace(replacement, artifact)
                return result

            def forbid_whole_artifact_read(path):
                if Path(path) == artifact:
                    raise AssertionError("original artifact must be streamed")
                return original_read_bytes(path)

            def parse_group(entries, artifact_sha256, *_args, **_kwargs):
                parsed_entries.extend(entry.artifact_entry for entry in entries)
                return [
                    _fake_parse_result(entry, artifact_sha256)
                    for entry in entries
                ]

            with patch.object(
                oracle,
                "inspect_archive_stream",
                side_effect=inspect_then_replace,
            ), patch.object(
                Path, "read_bytes", forbid_whole_artifact_read,
            ), patch.object(
                oracle, "_javap_version", return_value="21.0.1",
            ), patch.object(
                oracle, "_parse_entry_group_with_javap", side_effect=parse_group,
            ):
                result = oracle.scan_final_artifact(
                    artifact, max_workers=1, cache_result=False,
                )

            self.assertTrue(result["complete"], result["failures"])
            self.assertEqual(result["artifact_sha256"], expected_digest)
            self.assertEqual(parsed_entries, ["safe/Snapshot.class"])
            self.assertEqual(len(inspected_paths), 1)
            self.assertNotEqual(inspected_paths[0], artifact)
            snapshot_directory = inspected_paths[0].parent

        self.assertFalse(snapshot_directory.exists())

    def test_expired_budget_stops_snapshot_before_safety_or_javap(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "fixture.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("fixture/A.class", b"class")
            with patch.object(
                oracle, "inspect_archive_stream"
            ) as inspect, patch.object(
                oracle, "_javap_version",
                side_effect=AssertionError("javap must not start"),
            ):
                result = oracle.scan_final_artifact(
                    artifact, time_budget_seconds=1e-12,
                )

        self.assertFalse(result["complete"])
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["failures"], ["oracle_time_budget_exceeded:0.000s"])
        inspect.assert_not_called()

    def test_boot_archive_ignores_duplicate_root_class_entries(self):
        """Only BOOT-INF/classes is on a Spring Boot archive's application classpath."""
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "boot.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("sample/App.class", b"root-copy")
                archive.writestr("BOOT-INF/classes/sample/App.class", b"runtime-copy")
                archive.writestr("BOOT-INF/classes/sample/OnlyRuntime.class", b"runtime-only")

            with tempfile.TemporaryDirectory() as extracted:
                entries, failures = oracle._extract_packaged_classes(
                    artifact.read_bytes(), Path(extracted), target_major=21
                )

        self.assertEqual(failures, [])
        self.assertEqual(
            [entry.artifact_entry for entry in entries],
            [
                "BOOT-INF/classes/sample/App.class",
                "BOOT-INF/classes/sample/OnlyRuntime.class",
            ],
        )

    def test_boot_archive_can_exclude_external_target_provider_from_consumer_oracle(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            provider = root / "provider.jar"
            consumer = root / "consumer.jar"
            with zipfile.ZipFile(provider, "w") as archive:
                archive.writestr("vendor/Provider.class", b"provider")
            with zipfile.ZipFile(consumer, "w") as archive:
                archive.writestr("app/Bridge.class", b"consumer")
            artifact = root / "boot.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/app/App.class", b"business")
                archive.writestr("BOOT-INF/lib/provider-1.0.jar", provider.read_bytes())
                archive.writestr("BOOT-INF/lib/consumer-1.0.jar", consumer.read_bytes())

            with tempfile.TemporaryDirectory() as extracted:
                entries, failures = oracle._extract_packaged_classes(
                    artifact.read_bytes(),
                    Path(extracted),
                    target_major=21,
                    excluded_nested_jars={"BOOT-INF/lib/provider-1.0.jar"},
                )

        self.assertEqual(failures, [])
        self.assertEqual(
            [entry.artifact_entry for entry in entries],
            [
                "BOOT-INF/classes/app/App.class",
                "BOOT-INF/lib/consumer-1.0.jar!/app/Bridge.class",
            ],
        )

    def test_sequential_concurrent_and_cached_scans_are_edge_equivalent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(
                Path(temp_dir) / "fixture.jar",
                ["fixture/C.class", "fixture/A.class", "fixture/B.class"],
            )

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                return _fake_parse_result(entry, artifact_sha256)

            def parse_group(entries, artifact_sha256, *_args, **_kwargs):
                return [parse_entry(entry, artifact_sha256) for entry in entries]

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_group_with_javap", side_effect=parse_group
            ):
                sequential = oracle.scan_final_artifact(artifact, max_workers=1)
                oracle.clear_immutable_oracle_cache()
                concurrent = oracle.scan_final_artifact(artifact, max_workers=3)
                cached = oracle.scan_final_artifact(artifact, max_workers=3)

        self.assertEqual(sequential["edges"], concurrent["edges"])
        self.assertEqual(sequential["failures"], concurrent["failures"])
        self.assertEqual(concurrent["edges"], cached["edges"])
        self.assertEqual(concurrent["failures"], cached["failures"])
        self.assertEqual(sequential["parsed_class_count"], 3)
        self.assertEqual(concurrent["parsed_class_count"], 3)
        self.assertEqual(cached["parsed_class_count"], 0)
        self.assertEqual(cached["cached_class_count"], 3)
        self.assertEqual(cached["cache_hits"], 1)

    def test_cache_can_be_disabled_without_changing_scan_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(
                Path(temp_dir) / "fixture.jar", ["fixture/A.class"]
            )

            def parse_group(entries, artifact_sha256, *_args, **_kwargs):
                return [
                    _fake_parse_result(entry, artifact_sha256)
                    for entry in entries
                ]

            with patch.object(
                oracle, "_javap_version", return_value="21.0.1"
            ), patch.object(
                oracle, "_parse_entry_group_with_javap", side_effect=parse_group
            ) as parse:
                first = oracle.scan_final_artifact(
                    artifact, max_workers=1, cache_result=False
                )
                second = oracle.scan_final_artifact(
                    artifact, max_workers=1, cache_result=False
                )

        self.assertEqual(first["edges"], second["edges"])
        self.assertEqual(first["failures"], second["failures"])
        self.assertEqual(first["cache_hits"], 0)
        self.assertEqual(second["cache_hits"], 0)
        self.assertEqual(parse.call_count, 2)

    def test_full_scan_batches_classes_into_bounded_javap_invocations(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            class_count = oracle.MAX_CLASSES_PER_JAVAP_BATCH * 2 + 5
            artifact = _fake_artifact(
                Path(temp_dir) / "many-classes.jar",
                [f"fixture/Class{index}.class" for index in range(class_count)],
            )
            observed_group_sizes = []

            def parse_group(entries, artifact_sha256, *_args, **_kwargs):
                observed_group_sizes.append(len(entries))
                return [
                    _fake_parse_result(entry, artifact_sha256) for entry in entries
                ]

            with patch.object(
                oracle, "_javap_version", return_value="21.0.1"
            ), patch.object(
                oracle, "_parse_entry_group_with_javap", side_effect=parse_group
            ):
                result = oracle.scan_final_artifact(artifact, max_workers=2)

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["parsed_class_count"], class_count)
        self.assertEqual(sum(observed_group_sizes), class_count)
        self.assertEqual(len(observed_group_sizes), 3)
        self.assertLessEqual(
            max(observed_group_sizes), oracle.MAX_CLASSES_PER_JAVAP_BATCH
        )

    def test_javap_batch_groups_use_rendered_command_budget(self):
        entries = [
            oracle.PackagedClass(
                f"fixture/C{index}.class",
                Path("C:/") / ("long-path-segment-" * 5)
                / f"class-{index:03d}.class",
            )
            for index in range(12)
        ]
        three_entry_chars = oracle._javap_batch_command_chars(
            "javap", entries[:3]
        )
        with patch.object(
            oracle, "MAX_CLASSES_PER_JAVAP_BATCH", 128
        ), patch.object(
            oracle, "MAX_JAVAP_COMMAND_CHARS", three_entry_chars - 1
        ):
            groups = oracle._javap_batch_groups(entries, 1, "javap")

        self.assertEqual(
            [entry for group in groups for entry in group], entries
        )
        self.assertTrue(all(len(group) <= 2 for group in groups))
        self.assertTrue(all(
            oracle._javap_batch_command_chars("javap", group)
            < three_entry_chars
            for group in groups
        ))

    def test_large_windows_safe_batch_reduces_jvm_start_count(self):
        entries = [
            oracle.PackagedClass(
                f"fixture/C{index}.class", Path(f"class-{index:06d}.class")
            )
            for index in range(256)
        ]
        with patch.object(
            oracle, "MAX_CLASSES_PER_JAVAP_BATCH", 128
        ), patch.object(
            oracle, "MAX_JAVAP_COMMAND_CHARS", 24_000
        ):
            groups = oracle._javap_batch_groups(entries, 1, "javap")

        self.assertEqual([len(group) for group in groups], [128, 128])
        self.assertGreaterEqual(oracle.MAX_CLASSES_PER_JAVAP_BATCH, 128)

    def test_command_line_overflow_recursively_splits_without_losing_classes(self):
        entries = [
            oracle.PackagedClass(
                f"fixture/C{index}.class", Path(f"unused-{index}.class")
            )
            for index in range(4)
        ]

        def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
            return _fake_parse_result(entry, artifact_sha256)

        with patch.object(
            oracle,
            "managed_popen",
            side_effect=OSError(errno.E2BIG, "argument list too long"),
        ) as popen, patch.object(
            oracle,
            "_parse_entry_with_javap",
            side_effect=parse_entry,
        ) as individual:
            results = oracle._parse_entry_group_with_javap(
                entries,
                "a" * 64,
                "javap",
                "21",
                oracle.Event(),
                time.perf_counter() + 5,
                force_verbose=False,
            )

        self.assertEqual(len(results), len(entries))
        self.assertTrue(all(result["parsed"] for result in results))
        self.assertEqual(popen.call_count, 3)
        self.assertEqual(individual.call_count, 4)

    def test_concurrent_scan_retains_every_class_parse_failure_in_entry_order(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entries = [f"fixture/Bad{index}.class" for index in range(4)]
            artifact = _fake_artifact(Path(temp_dir) / "broken.jar", entries)

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                time.sleep(0.01 if entry.artifact_entry.endswith("0.class") else 0.001)
                return _fake_parse_result(entry, artifact_sha256, failure="synthetic parse failure")

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=parse_entry
            ):
                result = oracle.scan_final_artifact(artifact, max_workers=4)

        self.assertFalse(result["complete"])
        self.assertEqual(result["parsed_class_count"], 4)
        self.assertEqual(result["parse_failure_count"], 4)
        self.assertEqual(
            result["failures"],
            [f"{entry}: synthetic parse failure" for entry in entries],
        )

    def test_explicit_worker_count_is_capped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(
                Path(temp_dir) / "many.jar",
                [
                    f"fixture/Class{index}.class"
                    for index in range(oracle.MAX_JAVAP_WORKERS * 2)
                ],
            )

            def parse_group(entries, artifact_sha256, *_args, **_kwargs):
                return [
                    _fake_parse_result(entry, artifact_sha256) for entry in entries
                ]

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_group_with_javap", side_effect=parse_group
            ):
                result = oracle.scan_final_artifact(artifact, max_workers=999)

        self.assertEqual(result["worker_count"], oracle.MAX_JAVAP_WORKERS)

    def test_selected_target_frontier_uses_requested_bounded_workers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(
                Path(temp_dir) / "targeted.jar",
                [f"fixture/Caller{index}.class" for index in range(4)],
                marker=b"fixture/Targetchanged()V",
            )

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                return _fake_parse_result(entry, artifact_sha256)

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=parse_entry
            ):
                result = oracle.scan_final_artifact(
                    artifact,
                    max_workers=4,
                    selected_targets=[{
                        "owner": "fixture.Target",
                        "member": "changed",
                        "descriptor": "()V",
                    }],
                )

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["parsed_class_count"], 4)
        self.assertEqual(result["worker_count"], 4)

    def test_immutable_cache_does_not_cross_artifact_sha(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first_artifact = _fake_artifact(root / "first.jar", ["fixture/A.class"], b"first")
            second_artifact = _fake_artifact(root / "second.jar", ["fixture/A.class"], b"second")
            parsed_shas = []

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                parsed_shas.append(artifact_sha256)
                return _fake_parse_result(entry, artifact_sha256)

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=parse_entry
            ):
                first = oracle.scan_final_artifact(first_artifact, max_workers=1)
                second = oracle.scan_final_artifact(second_artifact, max_workers=1)

        self.assertNotEqual(first["artifact_sha256"], second["artifact_sha256"])
        self.assertEqual(parsed_shas, [first["artifact_sha256"], second["artifact_sha256"]])
        self.assertEqual(first["cache_hits"], 0)
        self.assertEqual(second["cache_hits"], 0)
        self.assertTrue(all(row["artifact_sha256"] == first["artifact_sha256"] for row in first["edges"]))
        self.assertTrue(all(row["artifact_sha256"] == second["artifact_sha256"] for row in second["edges"]))

    def test_successful_javap_version_probe_is_reused_across_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first_artifact = _fake_artifact(
                root / "first.jar", ["fixture/A.class"], b"first"
            )
            second_artifact = _fake_artifact(
                root / "second.jar", ["fixture/B.class"], b"second"
            )

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                return _fake_parse_result(entry, artifact_sha256)

            with patch.object(
                oracle, "_javap_version", return_value="21.0.1"
            ) as version_probe, patch.object(
                oracle, "_parse_entry_with_javap", side_effect=parse_entry
            ):
                first = oracle.scan_final_artifact(first_artifact)
                second = oracle.scan_final_artifact(second_artifact)

        self.assertTrue(first["complete"], first["failures"])
        self.assertTrue(second["complete"], second["failures"])
        self.assertEqual(version_probe.call_count, 1)

    def test_missing_javap_command_does_not_reuse_another_command_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(Path(temp_dir) / "fixture.jar", ["fixture/A.class"])

            first = oracle.scan_final_artifact(artifact, javap="missing-javap-first-command")
            second = oracle.scan_final_artifact(artifact, javap="missing-javap-second-command")

        self.assertFalse(first["complete"])
        self.assertFalse(second["complete"])
        self.assertEqual(first["cache_hits"], 0)
        self.assertEqual(second["cache_hits"], 0)
        self.assertTrue(all("missing-javap-first-command" in failure for failure in first["failures"]))
        self.assertTrue(all("missing-javap-second-command" in failure for failure in second["failures"]))
        self.assertFalse(any("missing-javap-first-command" in failure for failure in second["failures"]))

    def test_time_budget_cancels_concurrent_scan_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(
                Path(temp_dir) / "slow.jar",
                [f"fixture/Slow{index}.class" for index in range(4)],
            )

            def parse_group(entries, artifact_sha256, _javap, _version, cancellation_event, deadline):
                while not cancellation_event.is_set() and time.perf_counter() < deadline:
                    time.sleep(0.005)
                return [
                    {"rows": [], "failures": [], "completed": False, "parsed": False}
                    for _entry in entries
                ]

            started_at = time.perf_counter()
            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_group_with_javap", side_effect=parse_group
            ):
                result = oracle.scan_final_artifact(
                    artifact, max_workers=2, time_budget_seconds=0.05
                )
            elapsed = time.perf_counter() - started_at

        self.assertLess(elapsed, 1.0)
        self.assertFalse(result["complete"])
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["interrupted"])
        self.assertEqual(result["cache_hits"], 0)
        self.assertTrue(any("oracle_time_budget_exceeded" in failure for failure in result["failures"]))

    def test_hung_javap_version_probe_returns_a_structured_incomplete_result(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(Path(temp_dir) / "version-hang.jar", ["fixture/A.class"])
            with patch.object(
                oracle,
                "run_managed_subprocess",
                side_effect=subprocess.TimeoutExpired(["javap", "-version"], 0.05),
            ) as mocked_run:
                result = oracle.scan_final_artifact(artifact, time_budget_seconds=0.05)

        self.assertFalse(result["complete"])
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["interrupted"])
        self.assertEqual(result["class_count"], 0)
        self.assertEqual(result["failures"], ["oracle_javap_version_timeout"])
        timeout = mocked_run.call_args.kwargs["timeout"]
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 0.05)

    def test_version_probe_exception_returns_a_non_cacheable_incomplete_result(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(Path(temp_dir) / "version-error.jar", ["fixture/A.class"])
            with patch.object(
                oracle, "_javap_version", side_effect=ValueError("synthetic version failure")
            ) as probe:
                first = oracle.scan_final_artifact(artifact)
                second = oracle.scan_final_artifact(artifact)

        for result in (first, second):
            self.assertFalse(result["complete"])
            self.assertFalse(result["timed_out"])
            self.assertFalse(result["interrupted"])
            self.assertEqual(result["cache_hits"], 0)
            self.assertEqual(result["cache_misses"], 1)
            self.assertEqual(
                result["failures"],
                ["oracle_javap_version_failed:ValueError: synthetic version failure"],
            )
        self.assertEqual(probe.call_count, 2)

    def test_concurrent_worker_exception_is_class_specific_and_does_not_stop_peers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entries = ["fixture/A.class", "fixture/B.class", "fixture/C.class"]
            artifact = _fake_artifact(Path(temp_dir) / "worker-error.jar", entries)

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                if entry.artifact_entry == "fixture/B.class":
                    raise ValueError("synthetic worker failure")
                return _fake_parse_result(entry, artifact_sha256)

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=parse_entry
            ):
                result = oracle.scan_final_artifact(artifact, max_workers=3)

        self.assertFalse(result["complete"])
        self.assertEqual(result["completed_class_count"], 3)
        self.assertEqual(result["parsed_class_count"], 2)
        self.assertEqual(result["parse_failure_count"], 1)
        self.assertEqual(
            result["failures"],
            ["fixture/B.class: oracle worker failed: ValueError: synthetic worker failure"],
        )
        self.assertEqual(
            [row["artifact_entry"] for row in result["edges"]],
            ["fixture/A.class", "fixture/C.class"],
        )

    def test_interrupted_worker_returns_incomplete_result_without_propagating(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(Path(temp_dir) / "interrupted.jar", ["fixture/A.class"])

            def interrupt(*_args, **_kwargs):
                raise KeyboardInterrupt()

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=interrupt
            ):
                result = oracle.scan_final_artifact(artifact, max_workers=1)

        self.assertFalse(result["complete"])
        self.assertFalse(result["timed_out"])
        self.assertTrue(result["interrupted"])
        self.assertIn("oracle_interrupted", result["failures"])


def _write_source(root: Path, relative_path: str, text: str) -> Path:
    source = root / relative_path
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(text, encoding="utf-8")
    return source


def _compile(classes: Path, sources: list[Path], classpath: Path | None = None) -> None:
    command = ["javac", "-d", str(classes)]
    if classpath is not None:
        command.extend(["-classpath", str(classpath)])
    command.extend(str(source) for source in sources)
    subprocess.run(command, check=True, capture_output=True, text=True)


@unittest.skipUnless(JDK_TOOLS, "JDK tools required")
class FinalArtifactEdgeOracleTest(unittest.TestCase):
    def test_procedure_version_matches_support_manifest(self):
        support = json.loads(
            (SCRIPTS / "binary_first_support_manifest.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(
            support["oracle_support_manifest"][
                "final_artifact_edge_oracle_procedure_version"
            ],
            oracle.ORACLE_PROCEDURE_VERSION,
        )
        self.assertIn("structurally valid", oracle.PROCEDURE)
        self.assertIn("malformed ACC_MODULE", oracle.PROCEDURE)

    def test_method_types_and_classes_expand_through_real_bootstrap_pipeline(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "bootstrap-types.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                entry = zipfile.ZipInfo(
                    "audit/BootstrapTypes.class",
                    date_time=(2020, 1, 1, 0, 0, 0),
                )
                archive.writestr(entry, BOOTSTRAP_TYPE_CONSTANTS_CLASS)
            artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
            instance = ArtifactInstance(
                outer_artifact_sha256=artifact_sha,
                container_entry="<artifact>",
                content_sha256=artifact_sha,
                runtime_profile_identity="runtime-1",
                path_owner_loader_realm_identity="application-loader",
                runtime_path_kind="classpath",
                runtime_classpath_index=0,
                container_loader_policy_version="flat-parent-first-v1",
                runtime_code_source_origin_identity="bootstrap-types-origin",
                coord="audit:bootstrap-types:1",
            )
            asm_jar = binary_asm_helper.resolve_asm_jar()
            snapshot = binary_artifact_diff.snapshot_archive(
                artifact,
                artifact_instance_identity=instance.identity,
                expected_sha256=artifact_sha,
                asm_jar=asm_jar,
            )
            scanned = oracle.scan_final_artifact(
                artifact,
                include_structural_facts=True,
                cache_result=False,
            )
            artifact_binding = {
                "path": str(artifact),
                "sha256": artifact_sha,
                "loader_realm": "application-loader",
                "slot": 0,
            }
            inventory = {
                "classes": {
                    "audit/BootstrapTypes": "audit/BootstrapTypes.class"
                }
            }
            with BinaryFactStore() as store:
                store.add_artifact_snapshot(instance, snapshot)
                production = set()
                for row in store.connection.execute(
                    """
                    SELECT m.member_name,e.symbolic_owner,e.edge_kind,
                           e.edge_json
                    FROM direct_edges AS e
                    JOIN members AS m
                      ON m.member_identity=e.caller_member_identity
                    """
                ):
                    payload = json.loads(row["edge_json"])
                    if row["edge_kind"] == "type":
                        production.add((
                            row["member_name"], row["symbolic_owner"],
                            payload["type_use_kind"],
                        ))
                    for referenced_owner in payload.get(
                        "loading_constraint_type_owners", ()
                    ):
                        production.add((
                            row["member_name"], referenced_owner,
                            "member_reference_descriptor",
                        ))
                issues, truth = (
                    binary_validation_oracle._validate_structural_edges(
                        store.connection,
                        [artifact_binding],
                        [inventory],
                        javap=str(shutil.which("javap")),
                        scan_cache={},
                        direct_scan_cache={
                            (artifact_sha, str(shutil.which("javap"))):
                            binary_validation_oracle._pack_oracle_scan(scanned)
                        },
                    )
                )
            missing_reason_codes = {}
            packed_scan = binary_validation_oracle._pack_oracle_scan(scanned)
            for type_use_kind in (
                "invokedynamic_callsite_descriptor",
                "constant_dynamic_descriptor",
                "method_handle_descriptor",
            ):
                with BinaryFactStore() as mutated_store:
                    mutated_store.add_artifact_snapshot(instance, snapshot)
                    identities = [
                        row["direct_edge_identity"]
                        for row in mutated_store.connection.execute(
                            """
                            SELECT direct_edge_identity,edge_json
                            FROM direct_edges
                            WHERE edge_kind='type'
                            """
                        )
                        if json.loads(row["edge_json"])["type_use_kind"]
                        == type_use_kind
                    ]
                    mutated_store.connection.executemany(
                        "DELETE FROM direct_edges "
                        "WHERE direct_edge_identity=?",
                        ((identity,) for identity in identities),
                    )
                    mutated_issues, _mutated_truth = (
                        binary_validation_oracle._validate_structural_edges(
                            mutated_store.connection,
                            [artifact_binding],
                            [inventory],
                            javap=str(shutil.which("javap")),
                            scan_cache={},
                            direct_scan_cache={
                                (
                                    artifact_sha,
                                    str(shutil.which("javap")),
                                ): packed_scan
                            },
                        )
                    )
                missing_reason_codes[type_use_kind] = {
                    item["reason_code"] for item in mutated_issues
                }
            constraint_mutation_reasons = {}
            for mutation in ("missing", "extra", "tampered", "invalid"):
                with BinaryFactStore() as mutated_store:
                    mutated_store.add_artifact_snapshot(instance, snapshot)
                    rows = list(mutated_store.connection.execute(
                        """
                        SELECT e.direct_edge_identity,e.edge_json,e.edge_kind,
                               e.symbolic_name,
                               m.member_name AS caller_member_name
                        FROM direct_edges AS e
                        JOIN members AS m
                          ON m.member_identity=e.caller_member_identity
                        ORDER BY direct_edge_identity
                        """
                    ))
                    candidates = [
                        row for row in rows
                        if "loading_constraint_type_owners"
                        in json.loads(row["edge_json"])
                    ]
                    self.assertTrue(candidates)
                    if mutation == "tampered":
                        # Select a semantic occurrence that is unique in this
                        # fixture.  Ordering by the content-derived edge hash
                        # made this mutation depend on ZIP metadata and could
                        # instead choose one of two equivalent condy rows,
                        # where replacing one declaration correctly produces
                        # EXTRA without MISSING because its twin remains.
                        selected = [
                            row for row in candidates
                            if row["caller_member_name"]
                            == "directFieldHandle"
                            and row["edge_kind"] == "ldc_handle"
                            and row["symbolic_name"] == "VALUE"
                        ]
                        self.assertEqual(len(selected), 1)
                    else:
                        selected = (
                            candidates
                            if mutation in {"missing", "invalid"}
                            else candidates[:1]
                        )
                    for row in selected:
                        payload = json.loads(row["edge_json"])
                        owners = list(payload[
                            "loading_constraint_type_owners"
                        ])
                        if mutation == "missing":
                            payload.pop("loading_constraint_type_owners")
                        elif mutation == "extra":
                            payload["loading_constraint_type_owners"] = sorted({
                                *owners, "mutation/ExtraOwner",
                            })
                        elif mutation == "invalid":
                            payload["loading_constraint_type_owners"] = [
                                "mutation/Z", "mutation/A",
                            ]
                        else:
                            payload["loading_constraint_type_owners"] = sorted({
                                "mutation/TamperedOwner", *owners[1:],
                            })
                        mutated_store.connection.execute(
                            "UPDATE direct_edges SET edge_json=? "
                            "WHERE direct_edge_identity=?",
                            (
                                json.dumps(
                                    payload, ensure_ascii=False,
                                    sort_keys=True, separators=(",", ":"),
                                ),
                                row["direct_edge_identity"],
                            ),
                        )
                    mutated_issues, _mutated_truth = (
                        binary_validation_oracle._validate_structural_edges(
                            mutated_store.connection,
                            [artifact_binding],
                            [inventory],
                            javap=str(shutil.which("javap")),
                            scan_cache={},
                            direct_scan_cache={
                                (
                                    artifact_sha,
                                    str(shutil.which("javap")),
                                ): packed_scan
                            },
                        )
                    )
                constraint_mutation_reasons[mutation] = {
                    item["reason_code"] for item in mutated_issues
                }

        self.assertTrue(scanned["complete"], scanned["failures"])
        expected = {
            *(('indy', owner, 'method_type_descriptor') for owner in (
                'java/lang/String', 'audit/Thing', 'java/util/Map',
                'java/time/Instant', 'java/time/ZoneId',
            )),
            ('indy', 'java/util/List', 'bootstrap_class_constant'),
            ('indy', '[Ljava/util/Set;', 'bootstrap_class_constant'),
            *(('indy', owner, 'invokedynamic_callsite_descriptor') for owner in (
                'java/io/File', 'java/nio/file/Path',
            )),
            ('indy', 'java/util/Optional', 'constant_dynamic_descriptor'),
            *(('indy', owner, 'method_handle_descriptor') for owner in (
                'java/lang/invoke/MethodHandles$Lookup', 'java/lang/String',
                'java/lang/invoke/MethodType', 'java/lang/Object',
                'java/lang/invoke/CallSite', 'java/lang/Class',
            )),
            *(('indy', owner, 'member_reference_descriptor') for owner in (
                'java/lang/invoke/MethodHandles$Lookup', 'java/lang/String',
                'java/lang/invoke/MethodType', 'java/lang/Object',
                'java/lang/invoke/CallSite', 'java/lang/Class',
            )),
            *(('condy', owner, 'method_type_descriptor') for owner in (
                'java/math/BigDecimal', 'java/math/BigInteger',
                'java/time/Instant', 'java/time/ZoneId',
            )),
            ('condy', 'java/net/URI', 'bootstrap_class_constant'),
            ('condy', '[Ljava/util/Set;', 'bootstrap_class_constant'),
            *(('condy', owner, 'constant_dynamic_descriptor') for owner in (
                'java/util/concurrent/Future', 'java/util/Optional',
            )),
            *(('condy', owner, 'method_handle_descriptor') for owner in (
                'java/lang/invoke/MethodHandles$Lookup', 'java/lang/String',
                'java/lang/Class', 'java/lang/Object',
            )),
            *(('condy', owner, 'member_reference_descriptor') for owner in (
                'java/lang/invoke/MethodHandles$Lookup', 'java/lang/String',
                'java/lang/Class', 'java/lang/Object',
            )),
            *(('direct', owner, 'method_type_descriptor') for owner in (
                'java/lang/String', 'java/util/List', 'audit/Thing',
                'java/util/Map',
            )),
            *(
                ('directHandle', owner, 'method_handle_descriptor')
                for owner in ('java/sql/Date', 'java/sql/Time')
            ),
            (
                'directFieldHandle', 'java/util/Locale',
                'method_handle_descriptor',
            ),
            *(
                ('directHandle', owner, 'member_reference_descriptor')
                for owner in ('java/sql/Date', 'java/sql/Time')
            ),
            (
                'directFieldHandle', 'java/util/Locale',
                'member_reference_descriptor',
            ),
            *(
                ('memberRefs', owner, 'member_reference_descriptor')
                for owner in (
                    'java/util/UUID', 'java/util/Currency',
                    'java/util/Calendar', 'java/util/Locale',
                    'java/time/Duration', 'java/time/Period',
                )
            ),
        }
        self.assertEqual(production, expected)
        self.assertEqual(issues, [])
        self.assertEqual(
            {
                (edge[1], edge[4], edge[5])
                for edge in truth["type_edges"]
            },
            expected,
        )
        self.assertEqual(missing_reason_codes, {
            type_use_kind: {"ORACLE_TYPE_EDGE_MISSING"}
            for type_use_kind in (
                "invokedynamic_callsite_descriptor",
                "constant_dynamic_descriptor",
                "method_handle_descriptor",
            )
        })
        self.assertEqual(
            constraint_mutation_reasons["missing"],
            {"ORACLE_TYPE_EDGE_MISSING"},
        )
        self.assertEqual(
            constraint_mutation_reasons["extra"],
            {"ORACLE_TYPE_EDGE_EXTRA"},
        )
        self.assertEqual(
            constraint_mutation_reasons["tampered"],
            {"ORACLE_TYPE_EDGE_MISSING", "ORACLE_TYPE_EDGE_EXTRA"},
        )
        self.assertEqual(
            constraint_mutation_reasons["invalid"],
            {
                "ORACLE_LOADING_CONSTRAINT_DECLARATION_INVALID",
                "ORACLE_TYPE_EDGE_MISSING",
            },
        )

    def test_method_type_raw_identifiers_are_preserved_or_fail_closed(self):
        self.assertEqual(
            oracle._method_type_reference_owners("(Lraw/)name;)V"),
            ("raw/)name",),
        )
        self.assertIsNone(
            oracle._method_type_reference_owners(
                "(" + "J" * 128 + ")V"
            )
        )
        self.assertIsNone(
            oracle._method_type_reference_owners(
                "([" + "[" * 255 + "Ljava/lang/String;)V"
            )
        )
        cases = (
            (
                "preserved",
                "(Lraw/space name;Lraw/quote\"name;Lraw/组合;)Lraw/$Dollar;",
                True,
            ),
            ("newline", "(Lraw/line\nname;)V", False),
            ("surrogate", "(Lraw/\ud800;)V", False),
        )
        try:
            asm_jar = binary_asm_helper.resolve_asm_jar()
        except binary_asm_helper.BinaryAsmError as error:
            self.skipTest(str(error))

        for label, method_type_descriptor, should_complete in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                content = _minimal_ldc_method_type_class(
                    method_type_descriptor
                )
                artifact = root / f"{label}.jar"
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr("MethodTypeFixture.class", content)
                result = oracle.scan_final_artifact(
                    artifact,
                    include_structural_facts=True,
                    cache_result=False,
                )
                production = binary_asm_helper.extract_class_facts(
                    [BinaryClassInput(
                        f"{label}-instance",
                        "MethodTypeFixture.class",
                        content,
                    )],
                    asm_jar=asm_jar,
                )
                production_owners = {
                    edge["symbolic_owner"]
                    for record in production.records
                    for method in record.get("methods") or ()
                    for instruction in method.get("instructions") or ()
                    for edge in BinaryFactStore._instruction_edges(instruction)
                    if edge["edge_kind"] == "type"
                }

            if should_complete:
                self.assertTrue(result["complete"], result["failures"])
                oracle_owners = {
                    edge[4]
                    for edge in result["structural_facts"]["type_edges"]
                    if edge[5] == "method_type_descriptor"
                }
                self.assertEqual(oracle_owners, production_owners)
                self.assertEqual(oracle_owners, {
                    "raw/space name", 'raw/quote"name', "raw/组合",
                    "raw/$Dollar",
                })
            else:
                self.assertFalse(result["complete"])
                self.assertTrue(result["failures"])
                self.assertTrue(production_owners)

    def test_module_descriptor_filter_uses_classfile_access_flag(self):
        self.assertTrue(oracle._is_runtime_class("module-info.class"))
        self.assertTrue(oracle._is_runtime_class("audit/module-info.class"))
        self.assertTrue(oracle._is_runtime_class("audit/notmodule-info.class"))
        self.assertTrue(oracle._is_runtime_class("audit/package-info.class"))
        self.assertTrue(oracle._is_runtime_class("audit/notpackage-info.class"))
        self.assertEqual(
            oracle._logical_class_entry(zipfile.ZipInfo(
                "META-INF/versions/9/module-info.class"
            )),
            ("module-info.class", 9),
        )
        self.assertEqual(
            oracle._logical_class_entry(zipfile.ZipInfo(
                "META-INF/versions/9/audit/module-info.class"
            )),
            ("audit/module-info.class", 9),
        )
        self.assertEqual(
            oracle._logical_class_entry(zipfile.ZipInfo(
                "META-INF/versions/9/audit/notmodule-info.class"
            )),
            ("audit/notmodule-info.class", 9),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ordinary_root_content = _minimal_static_edge_class(
                "module-info", "rootDescriptor"
            )
            self.assertEqual(
                oracle._classfile_header_facts(ordinary_root_content)[1]
                & oracle.ACC_MODULE,
                0,
            )
            artifact = root / "module-name-ordinary-classes.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "module-info.class",
                    ordinary_root_content,
                )
                archive.writestr(
                    "audit/module-info.class",
                    _minimal_static_edge_class(
                        "audit/module-info", "nestedDescriptor"
                    ),
                )
                archive.writestr(
                    "audit/notmodule-info.class",
                    _minimal_static_edge_class(
                        "audit/notmodule-info", "notDescriptor"
                    ),
                )
                archive.writestr(
                    "audit/package-info.class",
                    _minimal_static_edge_class(
                        "audit/package-info", "packageMetadata"
                    ),
                )
                archive.writestr(
                    "audit/notpackage-info.class",
                    _minimal_static_edge_class(
                        "audit/notpackage-info", "notPackageMetadata"
                    ),
                )

            result = oracle.scan_final_artifact(
                artifact, max_workers=1, cache_result=False
            )

            module_source = _write_source(
                root / "module-src",
                "module-info.java",
                "module fixture.module { }",
            )
            module_classes = root / "module-classes"
            module_classes.mkdir()
            _compile(module_classes, [module_source])
            descriptor_content = (module_classes / "module-info.class").read_bytes()
            self.assertNotEqual(
                oracle._classfile_header_facts(descriptor_content)[1]
                & oracle.ACC_MODULE,
                0,
            )
            descriptor_artifact = root / "real-module-descriptor.jar"
            with zipfile.ZipFile(descriptor_artifact, "w") as archive:
                archive.writestr("module-info.class", descriptor_content)
            descriptor_result = oracle.scan_final_artifact(
                descriptor_artifact, max_workers=1, cache_result=False
            )

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["class_count"], 5)
        self.assertEqual(
            {
                (edge["caller_owner"], edge["caller_member"])
                for edge in result["edges"]
            },
            {
                ("module-info", "rootDescriptor"),
                ("audit.module-info", "nestedDescriptor"),
                ("audit.notmodule-info", "notDescriptor"),
                ("audit.package-info", "packageMetadata"),
                ("audit.notpackage-info", "notPackageMetadata"),
            },
        )
        self.assertTrue(all(
            edge["callee_owner"] == "java.lang.System"
            and edge["callee_member"] == "gc"
            for edge in result["edges"]
        ))
        self.assertTrue(
            descriptor_result["complete"], descriptor_result["failures"]
        )
        self.assertEqual(descriptor_result["class_count"], 0)
        self.assertEqual(descriptor_result["edges"], [])

    def test_javap_child_is_killed_when_pipe_communication_is_interrupted(self):
        class InterruptingProcess:
            def __init__(self):
                self.pid = 43210
                self.returncode = None
                self.communicate_count = 0
                self.kill_count = 0

            def poll(self):
                return None

            def kill(self):
                self.kill_count += 1

            def communicate(self, **_kwargs):
                self.communicate_count += 1
                if self.communicate_count == 1:
                    raise KeyboardInterrupt()
                self.returncode = -9
                return "", ""

        entry = oracle.PackagedClass(
            "fixture/A.class", Path("unused-A.class")
        )
        for grouped in (False, True):
            with self.subTest(grouped=grouped):
                process = InterruptingProcess()
                with patch.object(
                    oracle.subprocess, "Popen", return_value=process
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        if grouped:
                            oracle._parse_entry_group_with_javap(
                                [entry, oracle.PackagedClass(
                                    "fixture/B.class", Path("unused-B.class")
                                )],
                                "a" * 64,
                                "javap",
                                "21",
                                oracle.Event(),
                                time.perf_counter() + 5,
                                force_verbose=False,
                            )
                        else:
                            oracle._parse_entry_with_javap(
                                entry,
                                "a" * 64,
                                "javap",
                                "21",
                                oracle.Event(),
                                time.perf_counter() + 5,
                                verbose=False,
                            )
                self.assertEqual(process.kill_count, 1)
                self.assertEqual(process.communicate_count, 2)

    def test_executor_submission_failure_cancels_and_shuts_down_workers(self):
        class SubmissionFailureExecutor:
            instance = None

            def __init__(self, **_kwargs):
                type(self).instance = self
                self.submit_count = 0
                self.shutdown_args = None

            def submit(self, *_args, **_kwargs):
                self.submit_count += 1
                if self.submit_count == 2:
                    raise RuntimeError("synthetic submit failure")
                return object()

            def shutdown(self, **kwargs):
                self.shutdown_args = kwargs

        cancellation = oracle.Event()
        entries = [
            oracle.PackagedClass("fixture/A.class", Path("unused-A.class")),
            oracle.PackagedClass("fixture/B.class", Path("unused-B.class")),
        ]
        with patch.object(
            oracle, "ThreadPoolExecutor", SubmissionFailureExecutor
        ), self.assertRaisesRegex(RuntimeError, "synthetic submit failure"):
            oracle._parse_entry_batch(
                entries,
                "a" * 64,
                "javap",
                "21",
                cancellation,
                time.perf_counter() + 5,
                2,
                batch_javap=False,
            )

        self.assertTrue(cancellation.is_set())
        self.assertEqual(
            SubmissionFailureExecutor.instance.shutdown_args,
            {"wait": True, "cancel_futures": True},
        )

    def _compile_single_class(self, root: Path, method_name: str) -> Path:
        source = _write_source(
            root / "src",
            "fixture/Versioned.java",
            "package fixture; public class Versioned { public String " + method_name
            + "() { return String.valueOf(1); } }",
        )
        classes = root / "classes"
        classes.mkdir()
        _compile(classes, [source])
        return classes / "fixture/Versioned.class"

    def _build_artifact(self, root: Path) -> Path:
        dependency_source = _write_source(
            root / "dependency-src",
            "fixture/Dependency.java",
            """
            package fixture;
            public class Dependency {
              public static int staticValue;
              public int value;
              public Dependency() {}
              public void virtualCall() {}
              public static void staticCall() {}
            }
            """,
        )
        dependency_classes = root / "dependency-classes"
        dependency_classes.mkdir()
        _compile(dependency_classes, [dependency_source])
        dependency_jar = root / "dependency.jar"
        with zipfile.ZipFile(dependency_jar, "w") as archive:
            archive.write(
                dependency_classes / "fixture/Dependency.class",
                "fixture/Dependency.class",
            )

        worker_source = _write_source(
            root / "app-src",
            "fixture/Worker.java",
            "package fixture; public interface Worker { void run(); }",
        )
        app_source = _write_source(
            root / "app-src",
            "fixture/App.java",
            """
            package fixture;
            public class App {
              private Dependency dependency = new Dependency();
              public void use(Worker worker) {
                dependency.virtualCall();
                worker.run();
                Dependency.staticCall();
                new Dependency();
                int instance = dependency.value;
                dependency.value = instance;
                int statik = Dependency.staticValue;
                Dependency.staticValue = statik;
                Runnable callback = () -> Dependency.staticCall();
                callback.run();
              }
              public void throwing() throws java.io.IOException {
                Dependency.staticCall();
              }
              static {
                Dependency.staticCall();
              }
            }
            """,
        )
        app_classes = root / "app-classes"
        app_classes.mkdir()
        _compile(app_classes, [worker_source, app_source], dependency_jar)

        artifact = root / "app.jar"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.write(app_classes / "fixture/App.class", "BOOT-INF/classes/fixture/App.class")
            archive.write(app_classes / "fixture/Worker.class", "BOOT-INF/classes/fixture/Worker.class")
            archive.write(dependency_jar, "BOOT-INF/lib/dependency.jar")
        return artifact

    def test_selected_api_scan_exhausts_reverse_callers_without_parsing_unrelated_classes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "src"
            sources = [
                _write_source(
                    source_root,
                    "fixture/Target.java",
                    "package fixture; public class Target { public void changed() {} }",
                ),
                _write_source(
                    source_root,
                    "fixture/Bridge.java",
                    "package fixture; public class Bridge { public void call(Target target) { target.changed(); } }",
                ),
                _write_source(
                    source_root,
                    "fixture/App.java",
                    "package fixture; public class App { public void run(Bridge bridge, Target target) { bridge.call(target); } }",
                ),
                _write_source(
                    source_root,
                    "fixture/Unrelated.java",
                    "package fixture; public class Unrelated { public String text() { return String.valueOf(1); } }",
                ),
            ]
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, sources)
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                for class_file in sorted(classes.rglob("*.class")):
                    archive.write(
                        class_file,
                        "BOOT-INF/classes/" + class_file.relative_to(classes).as_posix(),
                    )

            result = oracle.scan_final_artifact(
                artifact,
                selected_targets=[{
                    "owner": "fixture.Target",
                    "member": "changed",
                    "descriptor": "()V",
                }],
            )

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["inventory_class_count"], 4)
        self.assertLess(result["parsed_class_count"], result["inventory_class_count"])
        relations = {
            (
                row["caller_owner"], row["caller_member"],
                row["callee_owner"], row["callee_member"],
            )
            for row in result["edges"]
        }
        self.assertIn(("fixture.Bridge", "call", "fixture.Target", "changed"), relations)
        self.assertIn(("fixture.App", "run", "fixture.Bridge", "call"), relations)
        self.assertFalse(any(row["caller_owner"] == "fixture.Unrelated" for row in result["edges"]))

    def test_selected_api_scan_reuses_prior_class_edges_for_intra_class_reverse_hops(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "src"
            sources = [
                _write_source(
                    source_root, "fixture/Target.java",
                    "package fixture; public class Target { public static void changed() {} }",
                ),
                _write_source(
                    source_root, "fixture/Bridge.java",
                    "package fixture; public class Bridge { public static void top() { middle(); } public static void middle() { Target.changed(); } }",
                ),
                _write_source(
                    source_root, "fixture/App.java",
                    "package fixture; public class App { public void run() { Bridge.top(); } }",
                ),
            ]
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, sources)
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                for class_file in sorted(classes.rglob("*.class")):
                    archive.write(
                        class_file,
                        "BOOT-INF/classes/" + class_file.relative_to(classes).as_posix(),
                    )

            result = oracle.scan_final_artifact(
                artifact,
                selected_targets=[{
                    "owner": "fixture.Target", "member": "changed", "descriptor": "()V",
                }],
            )

        self.assertTrue(result["complete"], result["failures"])
        relations = {
            (row["caller_owner"], row["caller_member"], row["callee_owner"], row["callee_member"])
            for row in result["edges"]
        }
        self.assertIn(("fixture.Bridge", "middle", "fixture.Target", "changed"), relations)
        self.assertIn(("fixture.Bridge", "top", "fixture.Bridge", "middle"), relations)
        self.assertIn(("fixture.App", "run", "fixture.Bridge", "top"), relations)

    def test_selected_api_scan_keeps_same_class_field_edges(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _write_source(
                root / "src",
                "fixture/Settings.java",
                "package fixture; public class Settings { "
                "private boolean enabled; "
                "public boolean enabled() { return enabled; } "
                "public void enable() { enabled = true; } }",
            )
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, [source])
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(
                    classes / "fixture/Settings.class",
                    "BOOT-INF/classes/fixture/Settings.class",
                )

            result = oracle.scan_final_artifact(
                artifact,
                selected_targets=[{
                    "owner": "fixture.Settings",
                    "member": "enabled",
                    "descriptor": "Z",
                }],
            )

        self.assertTrue(result["complete"], result["failures"])
        relations = {
            (row["caller_member"], row["callee_member"], row["opcode_family"])
            for row in result["edges"]
        }
        self.assertIn(("enabled", "enabled", "getfield"), relations)
        self.assertIn(("enable", "enabled", "putfield"), relations)

    def test_selected_api_scan_excludes_unrelated_edges_from_a_candidate_class(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "src"
            sources = [
                _write_source(
                    source_root,
                    "fixture/Target.java",
                    "package fixture; public class Target { public static void changed() {} }",
                ),
                _write_source(
                    source_root,
                    "fixture/Bridge.java",
                    "package fixture; public class Bridge { public String call() { "
                    "Target.changed(); return String.valueOf(1); } }",
                ),
            ]
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, sources)
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                for class_file in sorted(classes.rglob("*.class")):
                    archive.write(
                        class_file,
                        "BOOT-INF/classes/" + class_file.relative_to(classes).as_posix(),
                    )

            result = oracle.scan_final_artifact(
                artifact,
                selected_targets=[{
                    "owner": "fixture.Target", "member": "changed", "descriptor": "()V",
                }],
            )

        self.assertTrue(result["complete"], result["failures"])
        relations = {
            (row["callee_owner"], row["callee_member"])
            for row in result["edges"]
        }
        self.assertIn(("fixture.Target", "changed"), relations)
        self.assertNotIn(("java.lang.String", "valueOf"), relations)

    def test_batched_javap_keeps_each_class_bound_to_its_artifact_entry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sources = [
                _write_source(
                    root / "src", "fixture/First.java",
                    "package fixture; public class First { public String call() { return String.valueOf(1); } }",
                ),
                _write_source(
                    root / "src", "fixture/Second.java",
                    "package fixture; public class Second { public String call() { return String.valueOf(2); } }",
                ),
            ]
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, sources)
            entries = [
                oracle.PackagedClass(
                    f"BOOT-INF/classes/fixture/{name}.class",
                    classes / f"fixture/{name}.class",
                )
                for name in ("First", "Second")
            ]
            results = oracle._parse_entry_group_with_javap(
                entries, "a" * 64, "javap", "24.0.2", oracle.Event(), None
            )

        self.assertTrue(all(result["completed"] and result["parsed"] for result in results))
        self.assertTrue(all(not result["failures"] for result in results))
        for name, result in zip(("First", "Second"), results):
            self.assertTrue(result["rows"])
            self.assertEqual(
                {row["caller_owner"] for row in result["rows"]},
                {f"fixture.{name}"},
            )
            self.assertEqual(
                {row["artifact_entry"] for row in result["rows"]},
                {f"BOOT-INF/classes/fixture/{name}.class"},
            )

    @unittest.skipUnless(JDK_TOOLS, "JDK tools are required")
    def test_source_illegal_raw_names_keep_one_jvm_per_full_batch(self):
        class_count = oracle.MAX_CLASSES_PER_JAVAP_BATCH
        raw_fragments = (
            'quote"line\nbreak',
            "[leading-bracket",
            "space name",
            "tab\tname",
            "colon:name",
            "unicode-组合",
        )
        member_fragments = (
            "call line\nbreak",
            "[call",
            'quote"call',
            "tab\tcall",
            "colon:call",
            "unicode-方法",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            entries = []
            expected_owners = []
            expected_members = []
            for index in range(class_count):
                if index % 4 == 0:
                    owner = f"normal/Batch{index}"
                    member = f"call{index}"
                else:
                    raw_index = (index - 1) % len(raw_fragments)
                    owner = (
                        f"raw/{raw_fragments[raw_index]}"
                        f"{index}"
                    )
                    member = f"{member_fragments[raw_index]}{index}"
                content = _minimal_static_edge_class(owner, member)
                path = root / f"class-{index:06d}.class"
                path.write_bytes(content)
                entries.append(oracle.PackagedClass(
                    f"fixture/Class{index}.class",
                    path,
                    None,
                    False,
                ))
                expected_owners.append(owner.replace("/", "."))
                expected_members.append(member)

            with patch.object(
                oracle, "managed_popen", wraps=oracle.managed_popen,
            ) as starts, patch.object(
                oracle,
                "_parse_entry_with_javap",
                wraps=oracle._parse_entry_with_javap,
            ) as individual:
                results = oracle._parse_entry_group_with_javap(
                    entries,
                    "a" * 64,
                    "javap",
                    "24.0.2",
                    oracle.Event(),
                    None,
                )

        self.assertEqual(starts.call_count, 1)
        individual.assert_not_called()
        self.assertEqual(len(results), class_count)
        for expected_owner, expected_member, result in zip(
            expected_owners, expected_members, results
        ):
            self.assertTrue(result["completed"] and result["parsed"], result)
            self.assertEqual(result["failures"], [])
            self.assertEqual(
                {row["caller_owner"] for row in result["rows"]},
                {expected_owner},
            )
            self.assertEqual(
                {row["caller_member"] for row in result["rows"]},
                {expected_member},
            )

    def test_batched_javap_falls_back_per_class_to_isolate_malformed_input(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _write_source(
                root / "src",
                "fixture/Valid.java",
                "package fixture; public class Valid { "
                "public String call() { return String.valueOf(1); } }",
            )
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, [source])
            artifact = root / "mixed.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(
                    classes / "fixture/Valid.class", "fixture/Valid.class"
                )
                archive.writestr("fixture/Broken.class", b"not-a-class")

            result = oracle.scan_final_artifact(artifact, max_workers=1)

        self.assertFalse(result["complete"])
        self.assertEqual(result["completed_class_count"], 2)
        self.assertEqual(result["parsed_class_count"], 1)
        self.assertTrue(all(
            failure.startswith("fixture/Broken.class:")
            for failure in result["failures"]
        ), result["failures"])
        self.assertTrue(any(
            row["caller_owner"] == "fixture.Valid" for row in result["edges"]
        ))

    def test_only_invokedynamic_classes_require_verbose_javap(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sources = [
                _write_source(
                    root / "src", "fixture/Plain.java",
                    "package fixture; public class Plain { public int value() { return 1; } }",
                ),
                _write_source(
                    root / "src", "fixture/Lambda.java",
                    "package fixture; public class Lambda { public Runnable value() { return () -> {}; } }",
                ),
            ]
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, sources)
            plain = classes / "fixture/Plain.class"
            dynamic = classes / "fixture/Lambda.class"

            plain_entry = oracle.PackagedClass("fixture/Plain.class", plain, plain.read_bytes())
            dynamic_entry = oracle.PackagedClass("fixture/Lambda.class", dynamic, dynamic.read_bytes())

        self.assertFalse(oracle._entry_requires_verbose_javap(plain_entry))
        self.assertTrue(oracle._entry_requires_verbose_javap(dynamic_entry))

        marker_only = _minimal_static_edge_class(
            "MarkerOnly", "BootstrapMethods"
        )
        self.assertIn(b"BootstrapMethods", marker_only)
        self.assertFalse(
            oracle._classfile_has_method_handle_constant(marker_only)
        )
        self.assertFalse(oracle._entry_requires_verbose_javap(
            oracle.PackagedClass(
                "MarkerOnly.class", Path("/not-used.class"), marker_only
            )
        ))

    def test_ldc_method_handles_without_bootstrap_attribute_use_verbose_javap(self):
        cases = (
            ("field", 9, 2, "REF_getStatic", False, "VALUE", "I"),
            ("method", 10, 6, "REF_invokeStatic", False, "call", "()V"),
            ("interface", 11, 6, "REF_invokeStatic", True, "call", "()V"),
        )
        for (
            label, reference_tag, handle_kind, expected_kind,
            expected_interface, expected_member, expected_descriptor,
        ) in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                content = _minimal_ldc_handle_class(
                    member_reference_tag=reference_tag,
                    handle_kind=handle_kind,
                )
                self.assertNotIn(b"BootstrapMethods", content)
                self.assertTrue(
                    oracle._classfile_has_method_handle_constant(content)
                )
                artifact = Path(temp_dir) / f"{label}.jar"
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr(f"LdcHandle{reference_tag}.class", content)

                result = oracle.scan_final_artifact(
                    artifact, max_workers=1, cache_result=False
                )

            self.assertTrue(result["complete"], result["failures"])
            self.assertEqual(len(result["edges"]), 1)
            edge = result["edges"][0]
            self.assertEqual(edge["opcode_family"], "ldc_handle")
            self.assertEqual(edge["reference_kind"], expected_kind)
            self.assertIs(
                edge["reference_interface"], expected_interface
            )
            self.assertEqual(edge["callee_member"], expected_member)
            self.assertEqual(
                edge["callee_descriptor"], expected_descriptor
            )

    def test_cached_bootstrap_marker_avoids_rereading_extracted_class(self):
        missing = Path("/fixture/not-materialized.class")
        plain = oracle.PackagedClass(
            "fixture/Plain.class", missing, None, False
        )
        dynamic = oracle.PackagedClass(
            "fixture/Lambda.class", missing, None, True
        )
        with patch.object(
            Path, "read_bytes", side_effect=AssertionError("unexpected read")
        ) as read_bytes:
            self.assertFalse(oracle._entry_requires_verbose_javap(plain))
            self.assertTrue(oracle._entry_requires_verbose_javap(dynamic))

        read_bytes.assert_not_called()

    def test_scans_each_jvm_instruction_family_from_final_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = self._build_artifact(Path(temp_dir))
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            result = oracle.scan_final_artifact(artifact)

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["artifact_sha256"], digest)
        self.assertEqual(result["class_count"], 3)
        app_edges = [
            row for row in result["edges"]
            if row["caller_owner"] == "fixture.App" and row["caller_member"] == "use"
        ]
        edge_rows = [
            (
                row["caller_descriptor"], row["callee_owner"], row["callee_member"],
                row["callee_descriptor"], row["opcode_family"], row["artifact_entry"],
                row["instruction_offset"],
            )
            for row in app_edges
        ]
        expected = [
            ("(Lfixture/Worker;)V", "fixture.App", "dependency", "Lfixture/Dependency;", "getfield", "BOOT-INF/classes/fixture/App.class", 1),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "<init>", "()V", "invokespecial", "BOOT-INF/classes/fixture/App.class", 20),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "staticCall", "()V", "invokestatic", "BOOT-INF/classes/fixture/App.class", 13),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "staticValue", "I", "getstatic", "BOOT-INF/classes/fixture/App.class", 40),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "staticValue", "I", "putstatic", "BOOT-INF/classes/fixture/App.class", 45),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "value", "I", "getfield", "BOOT-INF/classes/fixture/App.class", 28),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "value", "I", "putfield", "BOOT-INF/classes/fixture/App.class", 37),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "virtualCall", "()V", "invokevirtual", "BOOT-INF/classes/fixture/App.class", 4),
            ("(Lfixture/Worker;)V", "fixture.Worker", "run", "()V", "invokeinterface", "BOOT-INF/classes/fixture/App.class", 8),
            ("(Lfixture/Worker;)V", "java.lang.Runnable", "run", "()V", "invokeinterface", "BOOT-INF/classes/fixture/App.class", 57),
            ("(Lfixture/Worker;)V", "fixture.App", "lambda$use$0", "()V", "invokedynamic", "BOOT-INF/classes/fixture/App.class", 48),
            ("(Lfixture/Worker;)V", "fixture.App", "dependency", "Lfixture/Dependency;", "getfield", "BOOT-INF/classes/fixture/App.class", 25),
            ("(Lfixture/Worker;)V", "fixture.App", "dependency", "Lfixture/Dependency;", "getfield", "BOOT-INF/classes/fixture/App.class", 33),
        ]
        self.assertListEqual(edge_rows, sorted(expected))
        self.assertTrue(all(row["authority"] == "jdk-javap" for row in app_edges))
        self.assertTrue(all(row["authority_version"] for row in app_edges))
        self.assertTrue(all(row["procedure"] for row in app_edges))
        lifecycle_rows = sorted(
            (
                row["caller_member"], row["caller_descriptor"], row["callee_owner"],
                row["callee_member"], row["callee_descriptor"], row["opcode_family"],
                row["artifact_entry"], row["instruction_offset"],
            )
            for row in result["edges"]
            if row["caller_owner"] == "fixture.App" and row["caller_member"] in {"throwing", "<clinit>"}
        )
        self.assertListEqual(lifecycle_rows, [
            ("<clinit>", "()V", "fixture.Dependency", "staticCall", "()V", "invokestatic", "BOOT-INF/classes/fixture/App.class", 0),
            ("throwing", "()V", "fixture.Dependency", "staticCall", "()V", "invokestatic", "BOOT-INF/classes/fixture/App.class", 0),
        ])

    def test_invalid_header_cannot_reuse_the_previous_member_context(self):
        output = """
public class fixture.Leak {
  public void first();
    descriptor: ()V
    Code:
       0: invokestatic #7 // Method fixture/Dependency.staticCall:()V
  public void broken(;
    descriptor: ()V
    Code:
       0: invokestatic #7 // Method fixture/Dependency.staticCall:()V
}
"""
        rows, failures = oracle._parse_javap_output(output, "a" * 64, "fixture/Leak.class", "24.0.2")

        self.assertEqual([row["caller_member"] for row in rows], ["first"])
        self.assertTrue(any("without a valid header" in failure for failure in failures))

    def test_method_named_like_its_class_is_not_rewritten_as_constructor(self):
        invoke_instructions = "\n".join(
            f"       {20 + index * 5}: invokeinterface #7 // InterfaceMethod "
            f"com/csii/pe/security/EnDecrypt."
            f"{'enCrypt' if index % 2 == 0 else 'deCrypt'}:"
            f"(Ljava/lang/String;)Ljava/lang/String;"
            for index in range(16)
        )
        instructions = "\n".join([
            "       0: getstatic #3 // Field class$0:Ljava/lang/Class;",
            "       3: putstatic #3 // Field class$0:Ljava/lang/Class;",
            "       6: getstatic #3 // Field class$0:Ljava/lang/Class;",
            "       9: putstatic #3 // Field class$0:Ljava/lang/Class;",
            invoke_instructions,
        ])
        output = f"""
class a {{
  public a();
    descriptor: ()V
    Code:
       0: invokespecial #1 // Method java/lang/Object.\"<init>\":()V
  public java.lang.String a(com.csii.pe.security.EnDecrypt, java.lang.String);
    descriptor: (Lcom/csii/pe/security/EnDecrypt;Ljava/lang/String;)Ljava/lang/String;
    Code:
{instructions}
}}
"""

        rows, failures = oracle._parse_javap_output(
            output, "a" * 64, "a.class", "21.0.8"
        )
        structural = oracle.parse_structural_javap(output)

        self.assertEqual(failures, [])
        self.assertEqual(len(rows), 21)
        self.assertEqual(rows[0]["caller_member"], "<init>")
        self.assertEqual(
            {row["caller_member"] for row in rows[1:]}, {"a"}
        )
        self.assertIn(("a", "method", "<init>", "()V", 0x0001), structural["declared_members"])
        self.assertIn(
            (
                "a", "method", "a",
                "(Lcom/csii/pe/security/EnDecrypt;Ljava/lang/String;)Ljava/lang/String;",
                0x0001,
            ),
            structural["declared_members"],
        )

    def test_real_major48_same_name_method_survives_batched_javap_scan(self):
        self.assertEqual(int.from_bytes(SAME_NAME_METHOD_CLASS[6:8], "big"), 48)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            companion = self._compile_single_class(root / "companion", "value")
            artifact = root / "same-name.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("a.class", SAME_NAME_METHOD_CLASS)
                archive.write(companion, "fixture/Versioned.class")
            # One worker puts both non-verbose classes through the real
            # multi-class javap section splitter, not the text-only parser.
            with patch.object(
                oracle,
                "_parse_entry_with_javap",
                wraps=oracle._parse_entry_with_javap,
            ) as individual_javap:
                result = oracle.scan_final_artifact(
                    artifact,
                    max_workers=1,
                    include_structural_facts=True,
                    cache_result=False,
                )

        self.assertTrue(result["complete"], result["failures"])
        individual_javap.assert_not_called()
        rows = [row for row in result["edges"] if row["caller_owner"] == "a"]
        self.assertEqual(len(rows), 21)
        self.assertEqual(
            [row["caller_member"] for row in rows].count("<init>"), 1
        )
        self.assertEqual([row["caller_member"] for row in rows].count("a"), 20)
        self.assertEqual(
            sum(
                row["callee_owner"] == "com.csii.pe.security.EnDecrypt"
                for row in rows
            ),
            16,
        )
        declared = result["structural_facts"]["declared_members"]
        self.assertIn(["a", "method", "<init>", "()V", 0x0001], declared)
        self.assertIn(
            [
                "a", "method", "a",
                "(Lcom/csii/pe/security/EnDecrypt;Ljava/lang/String;)Ljava/lang/String;",
                0x0001,
            ],
            declared,
        )

        try:
            asm_jar = binary_asm_helper.resolve_asm_jar()
        except binary_asm_helper.BinaryAsmError as error:
            self.skipTest(str(error))
        production_run = binary_asm_helper.extract_class_facts(
            [BinaryClassInput("same-name-instance", "a.class", SAME_NAME_METHOD_CLASS)],
            asm_jar=asm_jar,
        )
        self.assertEqual(production_run.coverage_status, "complete")
        opcode_names = {
            178: "getstatic", 179: "putstatic", 180: "getfield", 181: "putfield",
            182: "invokevirtual", 183: "invokespecial", 184: "invokestatic",
            185: "invokeinterface",
        }
        production_edges = set()
        for record in production_run.records:
            for method in record.get("methods") or ():
                contract = method.get("contract") or {}
                for instruction in method.get("instructions") or ():
                    for edge in BinaryFactStore._instruction_edges(instruction):
                        if edge["edge_kind"] not in {"method", "field"}:
                            continue
                        production_edges.add((
                            str(record["class_name"]).replace("/", "."),
                            str(contract.get("name") or ""),
                            str(contract.get("descriptor") or ""),
                            str(edge["symbolic_owner"]).replace("/", "."),
                            str(edge["symbolic_name"]),
                            str(edge["symbolic_descriptor"]),
                            opcode_names[int(edge["opcode"])],
                            int(edge["bytecode_offset"]),
                        ))
        oracle_edges = {
            (
                row["caller_owner"], row["caller_member"],
                row["caller_descriptor"], row["callee_owner"],
                row["callee_member"], row["callee_descriptor"],
                row["opcode_family"], row["instruction_offset"],
            )
            for row in rows
        }
        self.assertSetEqual(oracle_edges, production_edges)

    def test_quoted_legal_jvm_member_names_are_preserved(self):
        output = """
public class fixture.OddNames {
  public void has space();
    descriptor: ()V
    Code:
       0: getstatic #7 // Field fixture/OddNames."field name":I
       3: invokestatic #8 // Method fixture/OddNames."callee:name":()V
}
"""

        rows, failures = oracle._parse_javap_output(
            output, "a" * 64, "fixture/OddNames.class", "21.0.8"
        )
        structural = oracle.parse_structural_javap(output)

        self.assertEqual(failures, [])
        self.assertEqual(
            [(row["caller_member"], row["callee_member"]) for row in rows],
            [("has space", "field name"), ("has space", "callee:name")],
        )
        self.assertIn(
            ("fixture/OddNames", "method", "has space", "()V", 0x0001),
            structural["declared_members"],
        )

    def test_modified_utf8_decoder_is_strict_and_preserves_utf16_units(self):
        self.assertEqual(oracle._decode_modified_utf8(b""), "")
        self.assertEqual(
            oracle._decode_modified_utf8(
                b"A\xc0\x80\xdf\xbf\xe0\xa0\x80"
                b"\xed\xa0\xbd\xed\xb8\x80"
            ),
            "A\x00\u07ff\u0800\U0001f600",
        )
        self.assertEqual(
            oracle._decode_modified_utf8(b"\xed\xa0\x80"), "\ud800"
        )
        self.assertEqual(
            oracle._decode_modified_utf8(b"\xed\xb0\x80"), "\udc00"
        )
        for malformed in (
            b"\x00",                    # raw NUL
            b"\xf0\x9f\x98\x80",    # standard four-byte UTF-8
            b"\xc0\x81",              # overlong ASCII
            b"\xc1\xbf",              # overlong ASCII
            b"\xe0\x80\x80",        # overlong three-byte NUL
            b"\xc2",                    # truncated two-byte sequence
            b"\xe1\x80",              # truncated three-byte sequence
            b"\xc2A",                   # invalid continuation
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(UnicodeDecodeError):
                    oracle._decode_modified_utf8(malformed)

    @unittest.skipUnless(JDK_TOOLS, "JDK tools are required")
    def test_raw_owner_member_and_descriptor_survive_real_javap(self):
        raw_owner = 'odd/Owner"line\nbreak'
        raw_member = 'call"line\nbreak'
        raw_descriptor = '(Lodd/Type"line\nbreak;)V'
        content = _minimal_static_edge_class(
            raw_owner, raw_member, raw_descriptor
        )
        inventory = oracle._classfile_member_inventory(content)
        self.assertEqual(inventory.owner, raw_owner)
        self.assertEqual(
            (inventory.members[0].name, inventory.members[0].descriptor),
            (raw_member, raw_descriptor),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            class_file = root / "odd.class"
            class_file.write_bytes(content)
            loader = _write_source(
                root / "src",
                "Loader.java",
                "import java.nio.file.*; public class Loader { "
                "static class L extends ClassLoader { Class<?> d(byte[] b) { "
                "return defineClass(null, b, 0, b.length); } } "
                "public static void main(String[] a) throws Exception { "
                "Class<?> c = new L().d(Files.readAllBytes(Paths.get(a[0]))); "
                "String n = c.getName(); if (n.indexOf('\\n') < 0 || "
                "n.indexOf('\\\"') < 0) throw new AssertionError(n); "
                "System.out.print(\"loaded\"); } }",
            )
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, [loader])
            loaded = subprocess.run(
                [
                    "java", "-Xverify:all", "-cp", str(classes), "Loader",
                    str(class_file),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(loaded.returncode, 0, loaded.stderr)
            self.assertEqual(loaded.stdout, "loaded")

            artifact = root / "odd.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("odd.class", content)
            result = oracle.scan_final_artifact(
                artifact,
                max_workers=1,
                include_structural_facts=True,
                cache_result=False,
            )

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(len(result["edges"]), 1)
        edge = result["edges"][0]
        self.assertEqual(edge["caller_owner"], raw_owner.replace("/", "."))
        self.assertEqual(edge["caller_member"], raw_member)
        self.assertEqual(edge["caller_descriptor"], raw_descriptor)
        self.assertEqual(
            (edge["callee_owner"], edge["callee_member"]),
            ("java.lang.System", "gc"),
        )
        self.assertIn(
            (raw_owner, "method", raw_member, raw_descriptor, 0x0009),
            {
                tuple(item)
                for item in result["structural_facts"]["declared_members"]
            },
        )

        try:
            asm_jar = binary_asm_helper.resolve_asm_jar()
        except binary_asm_helper.BinaryAsmError as error:
            self.skipTest(str(error))
        production = binary_asm_helper.extract_class_facts(
            [BinaryClassInput("odd-instance", "odd.class", content)],
            asm_jar=asm_jar,
        )
        contract = production.records[0]["methods"][0]["contract"]
        self.assertEqual(
            (
                production.records[0]["class_name"],
                contract["name"],
                contract["descriptor"],
            ),
            (raw_owner, raw_member, raw_descriptor),
        )

    def test_source_illegal_callee_and_class_literal_preserve_or_fail_closed(self):
        cases = (
            (
                "callee_owner",
                'odd/Target"line\nbreak', "call", "()V",
                "java/lang/String",
            ),
            (
                "callee_member",
                "odd/Target", 'call"line\nbreak', "()V",
                "java/lang/String",
            ),
            (
                "callee_descriptor",
                "odd/Target", "call", '(Lodd/Param"line\nbreak;)V',
                "java/lang/String",
            ),
            (
                "class_literal",
                "java/lang/System", "gc", "()V",
                'odd/Literal"line\nbreak',
            ),
            (
                "callee_owner_surrogate",
                "odd/Target\ud800", "call", "()V",
                "java/lang/String",
            ),
            (
                "callee_member_surrogate",
                "odd/Target", "call\ud800", "()V",
                "java/lang/String",
            ),
            (
                "callee_descriptor_surrogate",
                "odd/Target", "call", "(Lodd/Param\ud800;)V",
                "java/lang/String",
            ),
            (
                "class_literal_surrogate",
                "java/lang/System", "gc", "()V",
                "odd/Literal\ud800",
            ),
        )
        for (
            label, target_owner, target_member, target_descriptor,
            literal_owner,
        ) in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                content = _minimal_reference_edge_class(
                    target_owner=target_owner,
                    target_member=target_member,
                    target_descriptor=target_descriptor,
                    literal_owner=literal_owner,
                )
                artifact = Path(temp_dir) / f"{label}.jar"
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr("ReferenceCaller.class", content)
                result = oracle.scan_final_artifact(
                    artifact,
                    max_workers=1,
                    include_structural_facts=True,
                    cache_result=False,
                )

            method_edges = [
                row for row in result["edges"]
                if row["opcode_family"] == "invokestatic"
            ]
            # Partial/truncated javap text must never become an apparently
            # authoritative edge.  In particular the old ``\(.*`` method
            # descriptor regex accepted the first physical line.
            self.assertTrue(all(
                (
                    row["callee_owner"], row["callee_member"],
                    row["callee_descriptor"],
                )
                == (
                    target_owner.replace("/", "."), target_member,
                    target_descriptor,
                )
                for row in method_edges
            ), method_edges)
            class_literals = [
                tuple(item)
                for item in result["structural_facts"]["type_edges"]
                if item[-1] == "class_literal"
            ]
            self.assertTrue(all(
                item[-2] == literal_owner for item in class_literals
            ), class_literals)
            if result["complete"]:
                self.assertEqual(len(method_edges), 1)
                self.assertEqual(len(class_literals), 1)
            else:
                self.assertTrue(result["failures"])

            try:
                asm_jar = binary_asm_helper.resolve_asm_jar()
            except binary_asm_helper.BinaryAsmError as error:
                self.skipTest(str(error))
            production = binary_asm_helper.extract_class_facts(
                [BinaryClassInput(
                    f"{label}-instance", "ReferenceCaller.class", content,
                )],
                asm_jar=asm_jar,
            )
            production_edges = [
                edge
                for record in production.records
                for method in record.get("methods") or ()
                for instruction in method.get("instructions") or ()
                for edge in BinaryFactStore._instruction_edges(instruction)
            ]
            self.assertTrue(any(
                edge["edge_kind"] == "method"
                and edge["symbolic_owner"] == target_owner
                and edge["symbolic_name"] == target_member
                and edge["symbolic_descriptor"] == target_descriptor
                for edge in production_edges
            ))
            self.assertTrue(any(
                edge["edge_kind"] == "type"
                and edge["symbolic_owner"] == literal_owner
                and edge["payload"].get("type_use_kind") == "class_literal"
                for edge in production_edges
            ))

    @unittest.skipUnless(JDK_TOOLS, "JDK tools are required")
    def test_unpaired_surrogate_method_name_round_trips_through_jvm(self):
        raw_member = "\ud800"
        content = _minimal_static_edge_class(
            "SurrogateFixture", raw_member
        )
        inventory = oracle._classfile_member_inventory(content)
        self.assertEqual(inventory.members[0].name, raw_member)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            class_file = root / "SurrogateFixture.class"
            class_file.write_bytes(content)
            loader = _write_source(
                root / "src",
                "Loader.java",
                "import java.lang.reflect.*; import java.nio.file.*; "
                "public class Loader { static class L extends ClassLoader { "
                "Class<?> d(byte[] b) { return defineClass(null, b, 0, b.length); } "
                "} public static void main(String[] a) throws Exception { "
                "Class<?> c = new L().d(Files.readAllBytes(Paths.get(a[0]))); "
                "Method m = c.getDeclaredMethods()[0]; String n = m.getName(); "
                "if (n.length() != 1 || n.charAt(0) != 0xd800) "
                "throw new AssertionError(); System.out.print(\"loaded\"); } }",
            )
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, [loader])
            loaded = subprocess.run(
                [
                    "java", "-Xverify:all", "-cp", str(classes), "Loader",
                    str(class_file),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(loaded.returncode, 0, loaded.stderr)
            self.assertEqual(loaded.stdout, "loaded")

            artifact = root / "surrogate.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("SurrogateFixture.class", content)
            result = oracle.scan_final_artifact(
                artifact, max_workers=1, cache_result=False
            )

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(len(result["edges"]), 1)
        self.assertEqual(result["edges"][0]["caller_member"], raw_member)

    def test_raw_member_info_binds_source_illegal_jvm_method_names(self):
        expected_callees = {
            "space name",
            'quote"name',
            "back\\slash",
            "line\nfeed",
            "tab\tname",
            "组合́",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            runtime = root / "runtime"
            runtime.mkdir()
            (runtime / "IdentifierFixture.class").write_bytes(
                SOURCE_ILLEGAL_MEMBER_NAMES_CLASS
            )
            loader = _write_source(
                root / "src",
                "Loader.java",
                "public class Loader { public static void main(String[] args) "
                "throws Exception { System.out.println(Class.forName("
                '"IdentifierFixture").getDeclaredMethods().length); } }',
            )
            _compile(runtime, [loader])
            loaded = subprocess.run(
                [
                    "java", "-Xverify:all", "-cp", str(runtime), "Loader",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(loaded.returncode, 0, loaded.stderr)
            self.assertEqual(loaded.stdout.strip(), "7")

            artifact = root / "identifier.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "IdentifierFixture.class",
                    SOURCE_ILLEGAL_MEMBER_NAMES_CLASS,
                )
            result = oracle.scan_final_artifact(
                artifact,
                max_workers=1,
                include_structural_facts=True,
                cache_result=False,
            )

        self.assertTrue(result["complete"], result["failures"])
        caller_edges = [
            row for row in result["edges"]
            if row["caller_member"] == "caller"
        ]
        self.assertEqual(
            {row["callee_member"] for row in caller_edges},
            expected_callees,
        )
        self.assertEqual(len(caller_edges), len(expected_callees))
        declared = {
            item[2]
            for item in result["structural_facts"]["declared_members"]
            if item[1] == "method"
        }
        self.assertEqual(declared, expected_callees | {"caller"})

        try:
            asm_jar = binary_asm_helper.resolve_asm_jar()
        except binary_asm_helper.BinaryAsmError as error:
            self.skipTest(str(error))
        production_run = binary_asm_helper.extract_class_facts(
            [BinaryClassInput(
                "identifier-instance",
                "IdentifierFixture.class",
                SOURCE_ILLEGAL_MEMBER_NAMES_CLASS,
            )],
            asm_jar=asm_jar,
        )
        production_callees = {
            str(edge["symbolic_name"])
            for record in production_run.records
            for method in record.get("methods") or ()
            if (method.get("contract") or {}).get("name") == "caller"
            for instruction in method.get("instructions") or ()
            for edge in BinaryFactStore._instruction_edges(instruction)
            if edge["edge_kind"] == "method"
        }
        self.assertEqual(production_callees, expected_callees)

    def test_structural_active_use_preserves_unicode_owner(self):
        output = """
public class fixture.NormalCaller {
  public void call();
    descriptor: ()V
    Code:
       0: invokestatic #7 // Method missing/Á.go:()V
       3: getstatic #8 // Field missing/Á.value:I
}
"""

        structural = oracle.parse_structural_javap(output)

        self.assertEqual(structural["failures"], set())
        self.assertEqual(
            structural["class_init_edges"],
            {
                ("fixture/NormalCaller", "call", "()V", 0, "missing/Á", "invokestatic"),
                ("fixture/NormalCaller", "call", "()V", 3, "missing/Á", "getstatic"),
            },
        )

    def test_structural_class_reference_preserves_quoted_spaces(self):
        output = """
public class fixture.NormalCaller {
  public void call();
    descriptor: ()V
    Code:
       0: new #7 // class "missing/Has Space"
}
"""

        structural = oracle.parse_structural_javap(output)

        self.assertEqual(structural["failures"], set())
        self.assertIn(
            (
                "fixture/NormalCaller", "call", "()V", 0,
                "missing/Has Space", "new",
            ),
            structural["class_init_edges"],
        )

    def test_structural_active_use_parse_failure_is_explicit(self):
        output = """
public class fixture.NormalCaller {
  public void call();
    descriptor: ()V
    Code:
       0: invokestatic #7 // malformed
}
"""

        structural = oracle.parse_structural_javap(output)

        self.assertEqual(structural["class_init_edges"], set())
        self.assertTrue(
            any("unparseable invokestatic" in item for item in structural["failures"])
        )

    def test_unresolved_invokedynamic_is_a_parse_failure(self):
        output = """
public class fixture.Dynamic {
  public void use();
    descriptor: ()V
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #0:run:()Ljava/lang/Runnable;
}
"""
        rows, failures = oracle._parse_javap_output(output, "a" * 64, "fixture/Dynamic.class", "24.0.2")

        self.assertEqual(rows, [])
        self.assertTrue(any("unresolved invokedynamic bootstrap" in failure for failure in failures))

    def test_invokedynamic_uses_lambda_implementation_handle_not_metafactory(self):
        output = """
public class fixture.LambdaCaller {
  java.lang.Runnable call();
    descriptor: ()Ljava/lang/Runnable;
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #0:run:()Ljava/lang/Runnable;
       5: areturn
}
BootstrapMethods:
  0: #20 REF_invokeStatic java/lang/invoke/LambdaMetafactory.metafactory:(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;
    Method arguments:
      #27 REF_invokeStatic fixture/LambdaCaller.lambda$call$0:()V
"""

        rows, failures = oracle._parse_javap_output(
            output,
            "a" * 64,
            "BOOT-INF/classes/fixture/LambdaCaller.class",
            "24.0.2",
        )

        self.assertEqual(failures, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["callee_owner"], "fixture.LambdaCaller")
        self.assertEqual(rows[0]["callee_member"], "lambda$call$0")
        self.assertEqual(rows[0]["callee_descriptor"], "()V")

    def test_real_bootstrap_section_stops_before_later_ref_text(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _write_source(
                root / "src",
                "fixture/BootstrapTail.java",
                (
                    "package fixture; public class BootstrapTail { "
                    "static class REF_X {} "
                    "public Runnable lambda() { return () -> {}; } }"
                ),
            )
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, [source])
            artifact = root / "bootstrap-tail.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                for class_file in sorted(classes.rglob("*.class")):
                    archive.write(
                        class_file, class_file.relative_to(classes).as_posix()
                    )

            result = oracle.scan_final_artifact(
                artifact, max_workers=1, cache_result=False
            )

        self.assertTrue(result["complete"], result["failures"])
        lambda_edges = [
            row for row in result["edges"]
            if row["caller_owner"] == "fixture.BootstrapTail"
            and row["caller_member"] == "lambda"
            and row["opcode_family"] == "invokedynamic"
        ]
        self.assertEqual(len(lambda_edges), 1)
        self.assertTrue(lambda_edges[0]["callee_member"].startswith("lambda$"))

    def test_real_string_concat_ref_prefix_is_not_a_bootstrap_handle(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _write_source(
                root / "src",
                "fixture/ConcatRef.java",
                (
                    "package fixture; public class ConcatRef { "
                    "public String join(String value) { return \"REF_\" + value; } }"
                ),
            )
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, [source])
            artifact = root / "concat-ref.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(
                    classes / "fixture" / "ConcatRef.class",
                    "fixture/ConcatRef.class",
                )

            result = oracle.scan_final_artifact(
                artifact,
                max_workers=1,
                include_structural_facts=True,
                cache_result=False,
            )

        self.assertTrue(result["complete"], result["failures"])
        self.assertTrue(any(
            instruction[1] == "join" and instruction[4] == "invokedynamic"
            for instruction in result["structural_facts"][
                "semantic_instructions"
            ]
        ))
        self.assertFalse(any(
            row["callee_owner"].startswith("REF_")
            for row in result["edges"]
        ))

    def test_real_interface_methodrefs_keep_cp_kind_for_static_and_special(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sources = [
                _write_source(
                    root / "src",
                    "fixture/Api.java",
                    (
                        "package fixture; public interface Api { "
                        "static Object staticCall(Object value) { return value; } "
                        "default Object defaultCall(Object value) { return value; } "
                        "static void staticVoid() {} "
                        "default void defaultVoid() {} }"
                    ),
                ),
                _write_source(
                    root / "src",
                    "fixture/InterfaceCalls.java",
                    (
                        "package fixture; public class InterfaceCalls implements Api { "
                        "public Object callStatic(Object value) { "
                        "return Api.staticCall(value); } "
                        "public Object callSpecial(Object value) { "
                        "return Api.super.defaultCall(value); } "
                        "public void callStaticVoid() { Api.staticVoid(); } "
                        "public void callSpecialVoid() { "
                        "Api.super.defaultVoid(); } }"
                    ),
                ),
            ]
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, sources)
            caller_class = classes / "fixture" / "InterfaceCalls.class"
            artifact = root / "interface-calls.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                for class_file in sorted(classes.rglob("*.class")):
                    archive.write(
                        class_file, class_file.relative_to(classes).as_posix()
                    )

            scanned = oracle.scan_final_artifact(
                artifact,
                max_workers=1,
                include_structural_facts=True,
                cache_result=False,
            )

            artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
            instance = ArtifactInstance(
                outer_artifact_sha256=artifact_sha,
                container_entry="<artifact>",
                content_sha256=artifact_sha,
                runtime_profile_identity="interface-calls-runtime",
                path_owner_loader_realm_identity="application-loader",
                runtime_path_kind="classpath",
                runtime_classpath_index=0,
                container_loader_policy_version="flat-parent-first-v1",
                runtime_code_source_origin_identity="interface-calls-origin",
                coord="fixture:interface-calls:1",
            )
            asm_jar = binary_asm_helper.resolve_asm_jar()
            snapshot = binary_artifact_diff.snapshot_archive(
                artifact,
                artifact_instance_identity=instance.identity,
                expected_sha256=artifact_sha,
                asm_jar=asm_jar,
            )
            javap = str(shutil.which("javap"))
            artifact_config = [{
                "path": str(artifact),
                "sha256": artifact_sha,
                "loader_realm": "application-loader",
                "slot": 0,
            }]
            direct_scan_cache = {
                (artifact_sha, javap):
                binary_validation_oracle._pack_oracle_scan(scanned)
            }
            with BinaryFactStore() as store:
                store.add_artifact_snapshot(instance, snapshot)
                direct_issues, direct_truth = (
                    binary_validation_oracle._validate_direct_edges(
                        store.connection,
                        artifact_config,
                        javap=javap,
                        scan_cache=direct_scan_cache,
                        truth_cache={},
                    )
                )
                structural_issues, _structural_truth = (
                    binary_validation_oracle._validate_structural_edges(
                        store.connection,
                        artifact_config,
                        [{"classes": {
                            "fixture/Api": "fixture/Api.class",
                            "fixture/InterfaceCalls": (
                                "fixture/InterfaceCalls.class"
                            ),
                        }}],
                        javap=javap,
                        direct_scan_cache=direct_scan_cache,
                    )
                )
                tampered_edge = store.connection.execute(
                    """
                    SELECT e.direct_edge_identity,e.edge_json
                    FROM direct_edges AS e
                    JOIN members AS m
                      ON m.member_identity=e.caller_member_identity
                    WHERE m.member_name='callStaticVoid'
                      AND e.edge_kind='method'
                      AND e.symbolic_owner='fixture/Api'
                    """
                ).fetchone()
                self.assertIsNotNone(tampered_edge)
                tampered_payload = json.loads(tampered_edge["edge_json"])
                tampered_payload["interface"] = False
                store.connection.execute(
                    "UPDATE direct_edges SET edge_json=? "
                    "WHERE direct_edge_identity=?",
                    (
                        json.dumps(tampered_payload, sort_keys=True),
                        tampered_edge["direct_edge_identity"],
                    ),
                )
                tampered_issues, _tampered_truth = (
                    binary_validation_oracle._validate_direct_edges(
                        store.connection,
                        artifact_config,
                        javap=javap,
                        scan_cache=direct_scan_cache,
                        truth_cache={},
                    )
                )

            production = binary_asm_helper.extract_class_facts(
                [BinaryClassInput(
                    "interface-calls-instance",
                    "fixture/InterfaceCalls.class",
                    caller_class.read_bytes(),
                )],
                asm_jar=binary_asm_helper.resolve_asm_jar(),
            )

        self.assertTrue(scanned["complete"], scanned["failures"])
        self.assertEqual(direct_issues, [])
        self.assertEqual(structural_issues, [])
        oracle_calls = {
            (row["caller_member"], row["opcode_family"]): row
            for row in scanned["edges"]
            if row["caller_owner"] == "fixture.InterfaceCalls"
            and row["callee_owner"] == "fixture.Api"
        }
        self.assertEqual(
            set(oracle_calls),
            {
                ("callStatic", "invokestatic"),
                ("callSpecial", "invokespecial"),
                ("callStaticVoid", "invokestatic"),
                ("callSpecialVoid", "invokespecial"),
            },
        )
        self.assertTrue(all(
            row["reference_kind"] == "interface_method"
            and row["reference_interface"] is True
            for row in oracle_calls.values()
        ))
        self.assertIn(
            (
                "fixture.InterfaceCalls", "callStaticVoid", "()V",
                "fixture.Api", "staticVoid", "()V", "invokestatic", 0,
                "interface_method",
            ),
            direct_truth["direct_edges"],
        )
        self.assertEqual(
            {
                issue["reason_code"]
                for issue in tampered_issues
            },
            {"ORACLE_DIRECT_EDGE_MISSING", "ORACLE_DIRECT_EDGE_EXTRA"},
        )
        structural_kinds = {
            (edge[1], edge[-1])
            for edge in scanned["structural_facts"]["type_edges"]
            if len(edge) == 10
            and edge[6] == "fixture/Api"
            and edge[7] in {"staticCall", "defaultCall"}
        }
        self.assertEqual(
            structural_kinds,
            {
                ("callStatic", "interface_method"),
                ("callSpecial", "interface_method"),
            },
        )

        production_calls = {}
        for record in production.records:
            for method in record.get("methods") or ():
                caller = str((method.get("contract") or {}).get("name") or "")
                for instruction in method.get("instructions") or ():
                    for edge in BinaryFactStore._instruction_edges(instruction):
                        if (
                            edge["edge_kind"] == "method"
                            and edge["symbolic_owner"] == "fixture/Api"
                        ):
                            production_calls[caller] = edge
        self.assertEqual(
            set(production_calls),
            {
                "callStatic", "callSpecial",
                "callStaticVoid", "callSpecialVoid",
            },
        )
        self.assertTrue(all(
            edge["payload"]["interface"] is True
            for edge in production_calls.values()
        ))

    def test_invokedynamic_preserves_unicode_bootstrap_handle_owner(self):
        output = """
public class fixture.LambdaCaller {
  java.lang.Runnable call();
    descriptor: ()Ljava/lang/Runnable;
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #0:run:()Ljava/lang/Runnable;
}
BootstrapMethods:
  0: #20 REF_invokeStatic java/lang/invoke/LambdaMetafactory.metafactory:(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;
    Method arguments:
      #27 REF_invokeStatic fixture/Á.lambda$call$0:()V
"""

        rows, failures = oracle._parse_javap_output(
            output, "a" * 64, "fixture/LambdaCaller.class", "24.0.2"
        )

        self.assertEqual(failures, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["callee_owner"], "fixture.Á")
        self.assertEqual(rows[0]["callee_member"], "lambda$call$0")

    def test_invokedynamic_preserves_method_handle_reference_kind(self):
        cases = (
            ("REF_getStatic", "VALUE", "I"),
            ("REF_putStatic", "VALUE", "I"),
            ("REF_invokeVirtual", "call", "()V"),
            ("REF_invokeSpecial", "call", "()V"),
        )
        for reference_kind, member, descriptor in cases:
            with self.subTest(reference_kind=reference_kind):
                constant_kind = (
                    "Methodref" if descriptor.startswith("(") else "Fieldref"
                )
                output = f"""
Constant pool:
  #27 = MethodHandle       6:#28          // {reference_kind} fixture/Target.{member}:{descriptor}
  #28 = {constant_kind}          #1.#2          // fixture/Target.{member}:{descriptor}
public class fixture.HandleCaller {{
  public void use();
    descriptor: ()V
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #0:run:()V
}}
BootstrapMethods:
  0: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()Ljava/lang/invoke/CallSite;
    Method arguments:
      #27 {reference_kind} fixture/Target.{member}:{descriptor}
"""

                rows, failures = oracle._parse_javap_output(
                    output,
                    "a" * 64,
                    "fixture/HandleCaller.class",
                    "21.0.8",
                )

                self.assertEqual(failures, [])
                target = next(
                    row for row in rows
                    if row["callee_owner"] == "fixture.Target"
                )
                self.assertEqual(target["reference_kind"], reference_kind)
                self.assertIs(target["reference_interface"], False)

    def test_invokedynamic_preserves_interface_methodref_bit(self):
        for constant_kind, expected_interface in (
            ("Methodref", False),
            ("InterfaceMethodref", True),
        ):
            with self.subTest(constant_kind=constant_kind):
                output = f"""
Constant pool:
  #27 = MethodHandle       6:#28          // REF_invokeStatic fixture/Target.call:()V
  #28 = {constant_kind}          #1.#2          // fixture/Target.call:()V
public class fixture.HandleCaller {{
  public void use();
    descriptor: ()V
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #0:run:()V
}}
BootstrapMethods:
  0: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()Ljava/lang/invoke/CallSite;
    Method arguments:
      #27 REF_invokeStatic fixture/Target.call:()V
"""

                rows, failures = oracle._parse_javap_output(
                    output,
                    "a" * 64,
                    "fixture/HandleCaller.class",
                    "21.0.8",
                )

                self.assertEqual(failures, [])
                target = next(
                    row for row in rows
                    if row["callee_owner"] == "fixture.Target"
                )
                self.assertIs(
                    target["reference_interface"], expected_interface
                )

    def test_invokedynamic_linker_without_method_handle_is_a_valid_empty_edge(self):
        output = """
public class fixture.ConcatCaller {
  java.lang.String call(java.lang.String);
    descriptor: (Ljava/lang/String;)Ljava/lang/String;
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #0:makeConcatWithConstants:(Ljava/lang/String;)Ljava/lang/String;
       5: areturn
}
BootstrapMethods:
  0: #20 REF_invokeStatic java/lang/invoke/StringConcatFactory.makeConcatWithConstants:(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;
    Method arguments:
      #27 value=\u0001
"""

        rows, failures = oracle._parse_javap_output(
            output, "a" * 64, "fixture/ConcatCaller.class", "24.0.2"
        )

        self.assertEqual(rows, [])
        self.assertEqual(failures, [])

    def test_record_object_methods_field_handle_is_a_linkage_edge(self):
        output = """
public final class fixture.Dyn extends java.lang.Record {
  public final java.lang.String toString();
    descriptor: ()Ljava/lang/String;
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #2:toString:(Lfixture/Dyn;)Ljava/lang/String;
  public final int hashCode();
    descriptor: ()I
    Code:
       0: invokedynamic #8,  0 // InvokeDynamic #2:hashCode:(Lfixture/Dyn;)I
  public final boolean equals(java.lang.Object);
    descriptor: (Ljava/lang/Object;)Z
    Code:
       0: invokedynamic #9,  0 // InvokeDynamic #2:equals:(Lfixture/Dyn;Ljava/lang/Object;)Z
}
BootstrapMethods:
  2: #30 REF_invokeStatic java/lang/runtime/ObjectMethods.bootstrap:(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/TypeDescriptor;Ljava/lang/Class;Ljava/lang/String;[Ljava/lang/invoke/MethodHandle;)Ljava/lang/Object;
    Method arguments:
      #37 fixture/Dyn
      #38 value
      #40 REF_getField fixture/Dyn.value:I
"""

        rows, failures = oracle._parse_javap_output(
            output, "a" * 64, "fixture/Dyn.class", "24.0.2"
        )

        self.assertEqual(failures, [])
        self.assertEqual(len(rows), 6)
        self.assertEqual(
            {row["callee_owner"] for row in rows},
            {"fixture.Dyn", "java.lang.runtime.ObjectMethods"},
        )
        self.assertEqual(
            {row["callee_member"] for row in rows}, {"bootstrap", "value"}
        )
        self.assertEqual(
            [row["callee_descriptor"] for row in rows].count("I"), 3
        )

    def test_real_constant_dynamic_scans_bootstrap_nested_and_field_handles(self):
        self.assertEqual(int.from_bytes(CONSTANT_DYNAMIC_CLASS[6:8], "big"), 55)
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "constant-dynamic.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "fixture/CondyFixture.class", CONSTANT_DYNAMIC_CLASS
                )
            result = oracle.scan_final_artifact(
                artifact, max_workers=1, cache_result=False
            )

        self.assertTrue(result["complete"], result["failures"])
        rows = result["edges"]
        self.assertEqual(len(rows), 8)
        by_caller = {
            member: [row for row in rows if row["caller_member"] == member]
            for member in ("load", "handle", "nested")
        }
        self.assertEqual(
            {row["opcode_family"] for row in by_caller["load"]},
            {"ldc_constant_dynamic_bootstrap", "ldc_bootstrap_handle"},
        )
        self.assertEqual(
            [row["opcode_family"] for row in by_caller["handle"]],
            ["ldc_handle"],
        )
        self.assertEqual(
            [
                (row["callee_owner"], row["callee_member"], row["callee_descriptor"])
                for row in by_caller["load"]
                if row["callee_descriptor"] == "I"
            ],
            [("fixture.Target", "VALUE", "I")],
        )
        self.assertEqual(len(by_caller["nested"]), 4)
        self.assertEqual(
            [
                row["opcode_family"] for row in by_caller["nested"]
                if row["callee_owner"] == "fixture.Bootstrap"
            ],
            ["ldc_bootstrap_handle", "ldc_constant_dynamic_bootstrap"],
        )

        try:
            asm_jar = binary_asm_helper.resolve_asm_jar()
        except binary_asm_helper.BinaryAsmError as error:
            self.skipTest(str(error))
        production_run = binary_asm_helper.extract_class_facts(
            [BinaryClassInput(
                "constant-dynamic-instance",
                "fixture/CondyFixture.class",
                CONSTANT_DYNAMIC_CLASS,
            )],
            asm_jar=asm_jar,
        )
        production_edges = set()
        for record in production_run.records:
            for method in record.get("methods") or ():
                contract = method.get("contract") or {}
                for instruction in method.get("instructions") or ():
                    for edge in BinaryFactStore._instruction_edges(instruction):
                        edge_kind = str(edge["edge_kind"])
                        if edge_kind == "ldc_constant_dynamic":
                            continue
                        if edge_kind.startswith("ldc_bootstrap_handle_"):
                            edge_kind = "ldc_bootstrap_handle"
                        if edge_kind not in {
                            "ldc_constant_dynamic_bootstrap",
                            "ldc_bootstrap_handle",
                            "ldc_handle",
                        }:
                            continue
                        production_edges.add((
                            str(record["class_name"]).replace("/", "."),
                            str(contract.get("name") or ""),
                            str(contract.get("descriptor") or ""),
                            str(edge["symbolic_owner"]).replace("/", "."),
                            str(edge["symbolic_name"]),
                            str(edge["symbolic_descriptor"]),
                            edge_kind,
                            int(edge["bytecode_offset"]),
                        ))
        oracle_edges = {
            (
                row["caller_owner"], row["caller_member"],
                row["caller_descriptor"], row["callee_owner"],
                row["callee_member"], row["callee_descriptor"],
                row["opcode_family"], row["instruction_offset"],
            )
            for row in rows
        }
        self.assertSetEqual(oracle_edges, production_edges)

    def test_unresolved_constant_dynamic_is_a_parse_failure(self):
        output = """
public class fixture.CondyFixture {
  public static java.lang.Object load();
    descriptor: ()Ljava/lang/Object;
    Code:
       0: ldc #29 // Dynamic #0:value:Ljava/lang/Object;
}
"""

        rows, failures = oracle._parse_javap_output(
            output, "a" * 64, "fixture/CondyFixture.class", "21.0.8"
        )

        self.assertEqual(rows, [])
        self.assertTrue(
            any(
                "unresolved ConstantDynamic bootstrap 0" in failure
                for failure in failures
            ),
            failures,
        )

    def test_local_variable_named_record_cannot_replace_the_declared_caller_owner(self):
        output = """
public class com.example.Application {
  public void run();
    descriptor: ()V
    Code:
      LocalVariableTable:
        Start  Length  Slot  Name   Signature
            8      41     2 record   Lcom/example/Dependency;
       0: invokestatic #7 // Method com/example/Dependency.call:()V
}
"""

        rows, failures = oracle._parse_javap_output(
            output, "a" * 64, "BOOT-INF/classes/com/example/Application.class", "24.0.2"
        )

        self.assertEqual(failures, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["caller_owner"], "com.example.Application")

    def test_array_clone_instruction_is_a_valid_method_edge(self):
        output = """
public class com.example.ArrayOwner {
  public java.lang.Object[] copy(java.lang.Object[]);
    descriptor: ([Ljava/lang/Object;)[Ljava/lang/Object;
    Code:
       0: invokevirtual #7 // Method "[Ljava/lang/Object;".clone:()Ljava/lang/Object;
}
"""

        rows, failures = oracle._parse_javap_output(
            output, "a" * 64, "BOOT-INF/classes/com/example/ArrayOwner.class", "24.0.2"
        )

        self.assertEqual(failures, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["callee_owner"], "[Ljava.lang.Object;")
        self.assertEqual(rows[0]["callee_member"], "clone")
        self.assertEqual(rows[0]["callee_descriptor"], "()Ljava/lang/Object;")

    def test_duplicate_nested_class_entry_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            class_file = self._compile_single_class(root, "duplicate")
            nested = root / "duplicate.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.write(class_file, "fixture/Versioned.class")
                archive.write(class_file, "fixture/Versioned.class")
            artifact = root / "outer.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(nested, "BOOT-INF/lib/duplicate.jar")
            result = oracle.scan_final_artifact(artifact)

        self.assertFalse(result["complete"])
        self.assertEqual(result["class_count"], 0)
        self.assertTrue(any(
            "ARCHIVE_DUPLICATE_ENTRY" in failure
            for failure in result["failures"]
        ), result["failures"])

    def test_multi_release_nested_jar_uses_highest_entry_supported_by_javap(self):
        version_text = subprocess.run(
            ["javap", "-version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        target_major = int(re.search(r"(?:1\.)?(\d+)", version_text).group(1))
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_class = self._compile_single_class(root / "base", "base")
            selected_class = self._compile_single_class(root / "selected", "selected")
            nested = root / "versioned.jar"
            versioned_entry = f"META-INF/versions/{target_major}/fixture/Versioned.class"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nmUlTi-ReLeAsE: TrUe\n\n")
                archive.write(base_class, "fixture/Versioned.class")
                archive.write(selected_class, versioned_entry)
            artifact = root / "outer.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(nested, "BOOT-INF/lib/versioned.jar")
            result = oracle.scan_final_artifact(artifact)

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["class_count"], 1)
        self.assertTrue(any(row["caller_member"] == "selected" for row in result["edges"]))
        self.assertTrue(all(
            row["artifact_entry"] == f"BOOT-INF/lib/versioned.jar!/{versioned_entry}"
            for row in result["edges"]
        ))

    def test_materialized_runtime_artifact_scan_does_not_expand_nested_jars(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            class_file = self._compile_single_class(root / "nested", "nested")
            nested = root / "dependency.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.write(class_file, "fixture/Versioned.class")
            artifact = root / "runtime-artifact.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(nested, "BOOT-INF/lib/dependency.jar")

            expanded = oracle.scan_final_artifact(artifact)
            materialized = oracle.scan_final_artifact(
                artifact, include_nested_runtime_jars=False
            )

        self.assertTrue(expanded["complete"], expanded["failures"])
        self.assertEqual(expanded["class_count"], 1)
        self.assertTrue(materialized["complete"], materialized["failures"])
        self.assertEqual(materialized["class_count"], 0)
        self.assertEqual(materialized["edges"], [])

    def test_multi_release_entries_without_manifest_opt_in_use_base_class(self):
        version_text = subprocess.run(
            ["javap", "-version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        target_major = int(re.search(r"(?:1\.)?(\d+)", version_text).group(1))
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_class = self._compile_single_class(root / "base", "base")
            ignored_class = self._compile_single_class(root / "ignored", "ignored")
            nested = root / "versioned.jar"
            versioned_entry = f"META-INF/versions/{target_major}/fixture/Versioned.class"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n\n")
                archive.write(base_class, "fixture/Versioned.class")
                archive.write(ignored_class, versioned_entry)
            artifact = root / "outer.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(nested, "BOOT-INF/lib/versioned.jar")
            result = oracle.scan_final_artifact(artifact)

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["class_count"], 1)
        self.assertTrue(any(row["caller_member"] == "base" for row in result["edges"]))
        self.assertFalse(any(row["caller_member"] == "ignored" for row in result["edges"]))
        self.assertTrue(all(
            row["artifact_entry"] == "BOOT-INF/lib/versioned.jar!/fixture/Versioned.class"
            for row in result["edges"]
        ))

    def test_unicode_nel_inside_manifest_value_cannot_activate_multi_release(self):
        version_text = subprocess.run(
            ["javap", "-version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        target_major = int(re.search(r"(?:1\.)?(\d+)", version_text).group(1))
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_class = self._compile_single_class(root / "base", "base")
            ignored_class = self._compile_single_class(
                root / "ignored", "ignored"
            )
            artifact = root / "nel-manifest.jar"
            versioned_entry = (
                f"META-INF/versions/{target_major}/fixture/Versioned.class"
            )
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\r\n"
                    "X-Note: before\u0085Multi-Release: true\r\n\r\n",
                )
                archive.write(base_class, "fixture/Versioned.class")
                archive.write(ignored_class, versioned_entry)
            with zipfile.ZipFile(artifact) as archive:
                self.assertFalse(oracle._is_multi_release_archive(archive))
            result = oracle.scan_final_artifact(
                artifact, cache_result=False,
            )

        self.assertTrue(result["complete"], result["failures"])
        self.assertTrue(any(
            row["caller_member"] == "base" for row in result["edges"]
        ))
        self.assertFalse(any(
            row["caller_member"] == "ignored" for row in result["edges"]
        ))

    def test_pre_java8_version_directory_uses_base_class(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_class = self._compile_single_class(root / "base", "base")
            ignored_class = self._compile_single_class(
                root / "ignored", "ignored"
            )
            nested = root / "versioned.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nMulti-Release: true\n\n",
                )
                archive.write(base_class, "fixture/Versioned.class")
                archive.write(
                    ignored_class,
                    "META-INF/versions/7/fixture/Versioned.class",
                )
            artifact = root / "outer.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(nested, "BOOT-INF/lib/versioned.jar")

            result = oracle.scan_final_artifact(artifact)

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["class_count"], 1)
        self.assertTrue(
            any(row["caller_member"] == "base" for row in result["edges"])
        )
        self.assertFalse(
            any(row["caller_member"] == "ignored" for row in result["edges"])
        )

    def test_named_manifest_section_cannot_activate_multi_release(self):
        version_text = subprocess.run(
            ["javap", "-version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        target_major = int(re.search(r"(?:1\.)?(\d+)", version_text).group(1))
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_class = self._compile_single_class(root / "base", "base")
            ignored_class = self._compile_single_class(root / "ignored", "ignored")
            nested = root / "versioned.jar"
            versioned_entry = f"META-INF/versions/{target_major}/fixture/Versioned.class"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\r\n\r\nName: fixture/Versioned.class\r\nMulti-Release: true\r\n\r\n",
                )
                archive.write(base_class, "fixture/Versioned.class")
                archive.write(ignored_class, versioned_entry)
            artifact = root / "outer.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(nested, "BOOT-INF/lib/versioned.jar")
            result = oracle.scan_final_artifact(artifact)

        self.assertTrue(result["complete"], result["failures"])
        self.assertTrue(any(row["caller_member"] == "base" for row in result["edges"]))
        self.assertFalse(any(row["caller_member"] == "ignored" for row in result["edges"]))

    def test_malformed_class_is_recorded_as_an_incomplete_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "broken.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/fixture/Broken.class", b"not-a-class")
            result = oracle.scan_final_artifact(artifact)

        self.assertFalse(result["complete"])
        self.assertEqual(result["class_count"], 1)
        self.assertEqual(len(result["failures"]), 1)
        self.assertIn("BOOT-INF/classes/fixture/Broken.class", result["failures"][0])

    def test_scans_package_classes_in_a_plain_executable_jar(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _write_source(
                root / "src",
                "fixture/Standalone.java",
                "package fixture; public class Standalone { public String text() { return String.valueOf(1); } }",
            )
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, [source])
            artifact = root / "standalone.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(classes / "fixture/Standalone.class", "fixture/Standalone.class")
            result = oracle.scan_final_artifact(artifact)

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["class_count"], 1)
        self.assertTrue(any(
            row["caller_owner"] == "fixture.Standalone" and row["callee_owner"] == "java.lang.String"
            for row in result["edges"]
        ))

    def test_same_javap_scan_exposes_independently_parsed_structural_facts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _write_source(
                root / "src",
                "fixture/Structural.java",
                "package fixture; public class Structural { "
                "static Object value; public static Object make() { "
                "value = new String(); return value; } }",
            )
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, [source])
            artifact = root / "structural.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(
                    classes / "fixture/Structural.class",
                    "fixture/Structural.class",
                )
            result = oracle.scan_final_artifact(
                artifact, include_structural_facts=True
            )
            cached = oracle.scan_final_artifact(
                artifact, include_structural_facts=True
            )

        self.assertTrue(result["complete"], result["failures"])
        facts = result["structural_facts"]
        self.assertEqual(facts["class_names"], ["fixture/Structural"])
        self.assertTrue(any(
            row[0] == "fixture/Structural" and row[4] == "java/lang/String"
            for row in facts["type_edges"]
        ))
        self.assertTrue(any(
            row[0] == "fixture/Structural"
            and row[1] == "method"
            and row[2] == "make"
            for row in facts["declared_members"]
        ))
        self.assertEqual(cached["cache_hits"], 1)
        self.assertEqual(cached["structural_facts"], facts)

    def test_missing_javap_is_recorded_as_an_incomplete_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = self._build_artifact(Path(temp_dir))
            result = oracle.scan_final_artifact(artifact, javap="missing-javap-command")

        self.assertFalse(result["complete"])
        self.assertEqual(result["class_count"], 0)
        self.assertEqual(result["cache_hits"], 0)
        self.assertEqual(len(result["failures"]), 1)
        self.assertTrue(result["failures"][0].startswith("oracle_javap_version_failed:OSError:"))
        self.assertIn("missing-javap-command", result["failures"][0])


if __name__ == "__main__":
    unittest.main()
