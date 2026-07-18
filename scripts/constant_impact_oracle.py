#!/usr/bin/env python3
"""Independent javap authority for compile-time constant and field-link facts."""

from dataclasses import asdict, dataclass
import hashlib
import io
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

from signature_utils import canonical_api_identity


@dataclass(frozen=True)
class ConstantOracleRecord:
    identity: str
    coord: str
    api_name: str
    descriptor: str
    has_constant_value: bool
    constant_value: object
    runtime_links: tuple[dict, ...]
    old_artifact_sha256: str
    authority: str
    authority_version: str
    procedure: str
    evidence_sha256: str

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class ConstantOracleLedger:
    complete: bool
    records: tuple[ConstantOracleRecord, ...]
    failures: tuple[str, ...]

    def to_dict(self):
        return {
            "complete": self.complete,
            "records": [record.to_dict() for record in self.records],
            "failures": list(self.failures),
        }


def _sha256_bytes(content):
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _owner_from_entry(entry):
    value = str(entry or "").replace("\\", "/")
    for prefix in ("BOOT-INF/classes/", "WEB-INF/classes/"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    match = re.match(r"META-INF/versions/\d+/(.+)", value)
    if match:
        value = match.group(1)
    return value[:-6].replace("/", ".") if value.endswith(".class") else ""


def _iter_zip_classes(payload, prefix="", depth=0):
    if depth > 3:
        return
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for info in sorted(archive.infolist(), key=lambda item: item.filename):
            if info.is_dir():
                continue
            full_entry = f"{prefix}{info.filename}"
            lower = info.filename.lower()
            if lower.endswith(".class"):
                yield _owner_from_entry(info.filename), full_entry, archive.read(info)
            elif lower.endswith((".jar", ".war", ".zip")):
                nested = archive.read(info)
                yield from _iter_zip_classes(nested, f"{full_entry}!/", depth + 1)


def _iter_classes(path):
    artifact = Path(path)
    if artifact.is_dir():
        for class_file in sorted(artifact.rglob("*.class")):
            entry = class_file.relative_to(artifact).as_posix()
            yield _owner_from_entry(entry), entry, class_file.read_bytes()
        return
    yield from _iter_zip_classes(artifact.read_bytes())


def _javap_version(javap):
    completed = subprocess.run(
        [javap, "-version"], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False, timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"javap_version_failed:{completed.stderr.strip()}")
    return (completed.stdout or completed.stderr).strip()


def _javap_class(content, javap, *args):
    with tempfile.TemporaryDirectory() as tmp:
        class_file = Path(tmp) / "Evidence.class"
        class_file.write_bytes(content)
        completed = subprocess.run(
            [javap, *args, str(class_file)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=False, timeout=60,
        )
    if completed.returncode != 0:
        raise RuntimeError(f"javap_failed:{completed.stderr.strip()}")
    return completed.stdout


def _normalize_constant_value(raw):
    value = str(raw or "").strip()
    if value.startswith("String "):
        return value[7:]
    for prefix in ("int ", "long "):
        if value.startswith(prefix):
            numeric = value[len(prefix):].rstrip("lL")
            try:
                return int(numeric)
            except ValueError:
                return value
    for prefix in ("float ", "double "):
        if value.startswith(prefix):
            numeric = value[len(prefix):].rstrip("fFdD")
            try:
                return float(numeric)
            except ValueError:
                return value
    return value


def _field_fact(javap_output, field_name, descriptor):
    lines = javap_output.splitlines()
    declaration = re.compile(rf"\b{re.escape(field_name)};$")
    for index, line in enumerate(lines):
        if not declaration.search(line.strip()):
            continue
        block = []
        for candidate in lines[index + 1:]:
            stripped = candidate.strip()
            if stripped == "}":
                break
            if candidate.startswith("  ") and not candidate.startswith("    ") and stripped.endswith(";"):
                break
            block.append(stripped)
        actual_descriptor = next(
            (item.split(":", 1)[1].strip() for item in block if item.startswith("descriptor:")),
            "",
        )
        if actual_descriptor != descriptor:
            continue
        constant_line = next(
            (item.split(":", 1)[1].strip() for item in block if item.startswith("ConstantValue:")),
            None,
        )
        return True, constant_line is not None, (
            _normalize_constant_value(constant_line) if constant_line is not None else None
        )
    return False, False, None


def _field_links(javap_output, target_owner, field_name, descriptor, artifact_sha, entry):
    owner_path = target_owner.replace(".", "/")
    pattern = re.compile(
        rf"^\s*(\d+):\s+(getstatic|putstatic|getfield|putfield)\b.*"
        rf"//\s+Field\s+{re.escape(owner_path)}\.{re.escape(field_name)}:"
        rf"{re.escape(descriptor)}\s*$"
    )
    links = []
    for line in javap_output.splitlines():
        match = pattern.search(line)
        if match:
            links.append({
                "opcode": match.group(2),
                "instruction_offset": int(match.group(1)),
                "artifact_sha256": artifact_sha,
                "artifact_entry": entry,
            })
    return links


def run_constant_oracle(old_jar, consumer_artifacts, api_rows, javap="javap"):
    failures = []
    records = []
    try:
        version = _javap_version(javap)
        old_sha = _sha256_file(old_jar)
        old_classes = list(_iter_classes(old_jar))
        consumers = []
        for artifact in consumer_artifacts or ():
            artifact_sha = _sha256_file(artifact)
            consumers.extend(
                (owner, entry, content, artifact_sha)
                for owner, entry, content in _iter_classes(artifact)
            )
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        return ConstantOracleLedger(False, (), (f"{type(exc).__name__}:{exc}",))
    old_javap_cache = {}
    consumer_javap_cache = {}
    for row in api_rows or ():
        api_name = str(row.get("api_name") or "")
        owner, separator, field_name = api_name.rpartition(".")
        descriptor = str(row.get("field_descriptor") or "")
        identity = canonical_api_identity({
            **dict(row), "api_signature": "", "symbol_kind": "field",
        })
        if not separator or not descriptor:
            failures.append(f"{identity}:constant_oracle_identity_incomplete")
            continue
        matches = [(entry, content) for class_owner, entry, content in old_classes if class_owner == owner]
        if len(matches) != 1:
            failures.append(f"{identity}:old_owner_match_count:{len(matches)}")
            continue
        old_entry, old_content = matches[0]
        try:
            old_output = old_javap_cache.get(old_entry)
            if old_output is None:
                old_output = _javap_class(
                    old_content, javap, "-verbose", "-p", "-s"
                )
                old_javap_cache[old_entry] = old_output
            found, has_constant, constant_value = _field_fact(
                old_output, field_name, descriptor
            )
            if not found:
                failures.append(f"{identity}:old_field_not_found")
                continue
            runtime_links = []
            evidence_parts = [old_output]
            for consumer_owner, entry, content, artifact_sha in consumers:
                output = consumer_javap_cache.get((artifact_sha, entry))
                if output is None:
                    output = _javap_class(content, javap, "-c", "-p", "-s")
                    consumer_javap_cache[(artifact_sha, entry)] = output
                evidence_parts.append(output)
                for link in _field_links(
                    output, owner, field_name, descriptor, artifact_sha, entry
                ):
                    runtime_links.append({"consumer_owner": consumer_owner, **link})
        except (OSError, RuntimeError) as exc:
            failures.append(f"{identity}:{type(exc).__name__}:{exc}")
            continue
        evidence_text = "\n".join(evidence_parts).encode("utf-8")
        records.append(ConstantOracleRecord(
            identity=identity,
            coord=str(row.get("coord") or ""),
            api_name=api_name,
            descriptor=descriptor,
            has_constant_value=has_constant,
            constant_value=constant_value,
            runtime_links=tuple(sorted(runtime_links, key=lambda item: (
                item["artifact_sha256"], item["artifact_entry"],
                item["instruction_offset"],
            ))),
            old_artifact_sha256=old_sha,
            authority="jdk-javap-constant-oracle",
            authority_version=version,
            procedure="javap -verbose -p -s old-field; javap -c -p -s consumers",
            evidence_sha256=_sha256_bytes(evidence_text),
        ))
    return ConstantOracleLedger(
        complete=not failures and len(records) == len(api_rows or ()),
        records=tuple(records),
        failures=tuple(failures),
    )


def audit_constant_evidence(analyzer_rows, oracle_rows):
    analyzer = {str(row.get("identity") or ""): row for row in analyzer_rows or ()}
    expected = {str(row.get("identity") or ""): row for row in oracle_rows or ()}
    missing = sorted(set(expected) - set(analyzer))
    extra = sorted(set(analyzer) - set(expected))
    incorrect = []
    for identity in sorted(set(expected) & set(analyzer)):
        left = analyzer[identity]
        right = expected[identity]
        if (
            bool(left.get("has_constant_value"))
            != bool(right.get("has_constant_value"))
            or bool(left.get("runtime_link_present"))
            != bool(right.get("runtime_link_present"))
        ):
            incorrect.append(identity)
    return {
        "missing_identities": missing,
        "extra_identities": extra,
        "incorrect_identities": incorrect,
        "blocking": bool(missing or extra or incorrect),
    }
