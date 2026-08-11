#!/usr/bin/env python3
"""Compare database access contracts retained in the base/current artifacts.

This scan intentionally does not inspect DDL or migration files.  It reports
changes in the database contract required by packaged MyBatis/ORM metadata so
that a human can verify the matching database rollout independently.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
import xml.etree.ElementTree as ET
import zipfile

from binary_asm_helper import BinaryAsmError, BinaryClassInput, extract_class_facts
from csv_io import open_csv_write


SCHEMA = "java-upgrade-analyzer.database-contract-changes.v1"
CSV_NAME = "s3_database_contract_changes.csv"
SUMMARY_NAME = "s3_database_contract_summary.json"
REVIEW_NAME = "s3_database_contract_changes.md"
MAX_XML_BYTES = 8 * 1024 * 1024
MAX_CLASS_BYTES = 16 * 1024 * 1024

CSV_FIELDS = (
    "依赖包",
    "旧版本",
    "新版本",
    "变化类型",
    "契约类型",
    "可信度",
    "表",
    "列",
    "契约位置",
    "语句或字段",
    "旧契约",
    "新契约",
    "证据",
    "人工复核建议",
)

SQL_ANNOTATIONS = {
    "Lorg/apache/ibatis/annotations/Select;": "select",
    "Lorg/apache/ibatis/annotations/Insert;": "insert",
    "Lorg/apache/ibatis/annotations/Update;": "update",
    "Lorg/apache/ibatis/annotations/Delete;": "delete",
}
SQL_PROVIDER_ANNOTATIONS = {
    "Lorg/apache/ibatis/annotations/SelectProvider;",
    "Lorg/apache/ibatis/annotations/InsertProvider;",
    "Lorg/apache/ibatis/annotations/UpdateProvider;",
    "Lorg/apache/ibatis/annotations/DeleteProvider;",
}
ENTITY_ANNOTATIONS = {
    "Ljavax/persistence/Entity;",
    "Ljakarta/persistence/Entity;",
    "Lcom/baomidou/mybatisplus/annotation/TableName;",
}
JPA_ENTITY_ANNOTATIONS = {
    "Ljavax/persistence/Entity;",
    "Ljakarta/persistence/Entity;",
}
MYBATIS_PLUS_ENTITY_ANNOTATION = "Lcom/baomidou/mybatisplus/annotation/TableName;"
JPA_ID_ANNOTATIONS = {
    "Ljavax/persistence/Id;",
    "Ljakarta/persistence/Id;",
    "Ljavax/persistence/EmbeddedId;",
    "Ljakarta/persistence/EmbeddedId;",
}
TABLE_ANNOTATIONS = {
    "Ljavax/persistence/Table;",
    "Ljakarta/persistence/Table;",
    "Lcom/baomidou/mybatisplus/annotation/TableName;",
}
COLUMN_ANNOTATIONS = {
    "Ljavax/persistence/Column;",
    "Ljakarta/persistence/Column;",
    "Lcom/baomidou/mybatisplus/annotation/TableField;",
    "Lcom/baomidou/mybatisplus/annotation/TableId;",
}
TRANSIENT_ANNOTATIONS = {
    "Ljavax/persistence/Transient;",
    "Ljakarta/persistence/Transient;",
}
CLASS_MARKERS = tuple(
    descriptor.encode("ascii")
    for descriptor in sorted(
        set(SQL_ANNOTATIONS)
        | SQL_PROVIDER_ANNOTATIONS
        | ENTITY_ANNOTATIONS
        | TABLE_ANNOTATIONS
        | COLUMN_ANNOTATIONS
    )
) + (b'com/baomidou/mybatisplus/core/mapper/BaseMapper',)

SQL_KEYWORDS = {
    "all", "and", "as", "asc", "between", "by", "case", "delete",
    "desc", "distinct", "else", "end", "exists", "false", "from",
    "full", "group", "having", "in", "inner", "insert", "into", "is",
    "join", "left", "like", "limit", "not", "null", "offset", "on",
    "or", "order", "outer", "right", "select", "set", "then", "true",
    "union", "update", "values", "when", "where",
}
IDENTIFIER = r"(?:[`\"\[]?[A-Za-z_][\w$]*[`\"\]]?)(?:\.(?:[`\"\[]?[A-Za-z_][\w$]*[`\"\]]?))*"


@dataclass(frozen=True)
class ContractFact:
    key: str
    kind: str
    location: str
    member: str
    tables: tuple[str, ...] = ()
    columns: tuple[str, ...] = ()
    normalized: str = ""
    evidence: str = ""
    confidence: str = "确认"


@dataclass
class ArtifactFacts:
    coord: str
    version: str
    side: str
    path: Path
    facts: dict[str, ContractFact] = field(default_factory=dict)
    gaps: list[str] = field(default_factory=list)


def _local_name(tag: str) -> str:
    return str(tag or "").rsplit("}", 1)[-1]


def _clean_identifier(value: str) -> str:
    parts = []
    for part in str(value or "").strip().split("."):
        cleaned = part.strip().strip("`\"[]")
        if cleaned:
            parts.append(cleaned)
    return ".".join(parts)


def _simple_column(value: str) -> str:
    cleaned = _clean_identifier(value)
    return cleaned.rsplit(".", 1)[-1] if cleaned else ""


def _normalize_sql(value: str) -> str:
    value = re.sub(r"/\*.*?\*/", " ", value or "", flags=re.S)
    value = re.sub(r"--[^\r\n]*", " ", value)
    return re.sub(r"\s+", " ", value).strip().rstrip(";")


def _sql_contract_fingerprint(
    operation: str,
    tables: tuple[str, ...],
    columns: tuple[str, ...],
    sql: str,
    ambiguous: bool,
) -> str:
    payload: dict[str, Any] = {
        'operation': operation.lower(),
        'tables': list(tables),
        'columns': list(columns),
    }
    # When identifiers are dynamic or could not be extracted, retaining the
    # normalized statement is the only conservative way to notice a change.
    if ambiguous:
        payload['ambiguous_sql'] = _normalize_sql(sql)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def extract_sql_references(sql: str) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    """Extract only explicit SQL identifiers; ambiguity lowers confidence."""
    normalized = _normalize_sql(sql)
    lowered = normalized.lower()
    # ``#{...}`` is a normal bound value and does not make table/column names
    # dynamic. ``${...}`` does, because it performs textual identifier injection.
    dynamic = bool(re.search(r"\$\{|<[^>]+>", normalized))
    tables = set()
    for match in re.finditer(
        rf"\b(?:from|join|update|insert\s+into|delete\s+from)\s+({IDENTIFIER})",
        normalized,
        flags=re.I,
    ):
        name = _clean_identifier(match.group(1))
        if name and not name.startswith(("$", "#")):
            tables.add(name)

    columns = set()

    def add_column(candidate: str) -> None:
        candidate = re.sub(r"\s+(?:as\s+)?[A-Za-z_]\w*$", "", candidate.strip(), flags=re.I)
        if re.fullmatch(IDENTIFIER, candidate):
            name = _simple_column(candidate)
            if name and name.lower() not in SQL_KEYWORDS and name != "*":
                columns.add(name)

    select_match = re.search(r"\bselect\s+(.*?)\s+from\b", normalized, flags=re.I | re.S)
    if select_match:
        for candidate in select_match.group(1).split(","):
            add_column(candidate)
    insert_match = re.search(
        rf"\binsert\s+into\s+{IDENTIFIER}\s*\(([^)]*)\)", normalized, flags=re.I | re.S
    )
    if insert_match:
        for candidate in insert_match.group(1).split(","):
            add_column(candidate)
    set_match = re.search(r"\bset\s+(.*?)(?:\bwhere\b|$)", normalized, flags=re.I | re.S)
    if set_match:
        for assignment in set_match.group(1).split(","):
            left = assignment.split("=", 1)[0]
            add_column(left)
    for match in re.finditer(
        rf"({IDENTIFIER})\s*(?:=|<>|!=|<=|>=|<|>|\blike\b|\bin\s*\(|\bis\b|\bbetween\b)",
        normalized,
        flags=re.I,
    ):
        add_column(match.group(1))
    return tuple(sorted(tables)), tuple(sorted(columns)), dynamic or not bool(tables or columns)


def extract_sql_fragment_references(
    sql: str,
) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    tables, columns, ambiguous = extract_sql_references(sql)
    if columns:
        return tables, columns, ambiguous
    # A common MyBatis <sql> fragment is only an explicit comma-separated
    # projection list, without SELECT/FROM keywords.
    candidates = [_simple_column(item.strip()) for item in _normalize_sql(sql).split(',')]
    if candidates and all(
        candidate and re.fullmatch(r"[A-Za-z_][\w$]*", candidate)
        and candidate.lower() not in SQL_KEYWORDS
        for candidate in candidates
    ):
        columns = tuple(sorted(set(candidates)))
        ambiguous = False
    return tables, columns, ambiguous


def _annotation_values(annotation: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for item in annotation.get("values") or ():
        if not isinstance(item, list) or len(item) < 2:
            continue
        name = str(item[0] or "")
        if len(item) >= 3 and item[1] == "array":
            result[name] = item[2] if isinstance(item[2], list) else []
        else:
            result[name] = item[1]
    return result


def _annotations_by_descriptor(values: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("descriptor") or "").split("@", 1)[0]: item
        for item in values or ()
        if isinstance(item, dict) and item.get("descriptor")
    }


def _first_annotation_value(
    annotations: dict[str, dict[str, Any]], descriptors: set[str], *names: str
) -> str:
    for descriptor in descriptors:
        annotation = annotations.get(descriptor)
        if not annotation:
            continue
        values = _annotation_values(annotation)
        for name in names:
            value = values.get(name)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _sql_from_annotation(annotation: dict[str, Any]) -> str:
    value = _annotation_values(annotation).get("value")
    if isinstance(value, list):
        return " ".join(str(item) for item in value if isinstance(item, str))
    return str(value or "")


def facts_from_class_record(
    record: dict[str, Any],
    entry: str,
    *,
    force_mybatis_plus_entity: bool = False,
) -> list[ContractFact]:
    facts = []
    class_name = str(record.get("class_name") or entry.removesuffix(".class")).replace("/", ".")
    class_annotations = _annotations_by_descriptor(record.get("annotations") or ())

    # MyBatis annotation SQL is part of the packaged mapper contract.
    for method in record.get("methods") or ():
        contract = method.get("contract") or {}
        member = f"{contract.get('name') or '?'}{contract.get('descriptor') or ''}"
        annotations = _annotations_by_descriptor(contract.get("annotations") or ())
        for descriptor, operation in SQL_ANNOTATIONS.items():
            annotation = annotations.get(descriptor)
            if not annotation:
                continue
            sql = _sql_from_annotation(annotation)
            tables, columns, ambiguous = extract_sql_references(sql)
            key = f"mybatis-annotation:{class_name}:{member}"
            facts.append(ContractFact(
                key=key,
                kind=f"MyBatis 注解 {operation.upper()}",
                location=class_name,
                member=member,
                tables=tables,
                columns=columns,
                normalized=_sql_contract_fingerprint(
                    operation, tables, columns, sql, ambiguous
                ),
                evidence=f"{entry}#{member}",
                confidence="需复核" if ambiguous else "确认",
            ))
        if SQL_PROVIDER_ANNOTATIONS.intersection(annotations):
            key = f"mybatis-provider:{class_name}:{member}"
            facts.append(ContractFact(
                key=key,
                kind="MyBatis SQL Provider",
                location=class_name,
                member=member,
                normalized=json.dumps(
                    {key: _annotation_values(value) for key, value in annotations.items()
                     if key in SQL_PROVIDER_ANNOTATIONS},
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                evidence=f"{entry}#{member}",
                confidence="需复核",
            ))

    if not ENTITY_ANNOTATIONS.intersection(class_annotations) and not force_mybatis_plus_entity:
        return facts

    explicit_table = _first_annotation_value(
        class_annotations, TABLE_ANNOTATIONS, "name", "value"
    )
    table = explicit_table or class_name.rsplit(".", 1)[-1]
    table_confidence = "确认" if explicit_table else "需复核"
    facts.append(ContractFact(
        key=f"orm-table:{class_name}",
        kind="ORM 实体表映射",
        location=class_name,
        member="<class>",
        tables=(table,),
        normalized=table,
        evidence=f"{entry}#<class>",
        confidence=table_confidence,
    ))
    is_mybatis_plus = (
        MYBATIS_PLUS_ENTITY_ANNOTATION in class_annotations
        or force_mybatis_plus_entity
    )
    is_jpa = bool(JPA_ENTITY_ANNOTATIONS.intersection(class_annotations))
    field_values = list(record.get("fields") or ())
    method_values = list(record.get("methods") or ())
    field_id_present = any(
        JPA_ID_ANNOTATIONS.intersection(
            _annotations_by_descriptor(value.get('annotations') or ())
        )
        for value in field_values
    )
    method_id_present = any(
        JPA_ID_ANNOTATIONS.intersection(
            _annotations_by_descriptor((value.get('contract') or {}).get('annotations') or ())
        )
        for value in method_values
    )
    # JPA access is determined by where @Id/@EmbeddedId is placed. An inherited
    # identifier cannot be resolved locally, so default-field candidates remain
    # visible but are explicitly marked for review.
    scan_fields = is_mybatis_plus or field_id_present or not method_id_present
    field_access_certain = is_mybatis_plus or (field_id_present and not method_id_present)
    for field_value in field_values if scan_fields else ():
        access = int(field_value.get("access") or 0)
        if access & 0x0008 or access & 0x0080:  # static or Java transient
            continue
        annotations = _annotations_by_descriptor(field_value.get("annotations") or ())
        if TRANSIENT_ANNOTATIONS.intersection(annotations):
            continue
        table_field = annotations.get("Lcom/baomidou/mybatisplus/annotation/TableField;")
        if table_field and _annotation_values(table_field).get("exist") is False:
            continue
        field_name = str(field_value.get("name") or "")
        if not field_name:
            continue
        explicit_column = _first_annotation_value(
            annotations, COLUMN_ANNOTATIONS, "name", "value"
        )
        column = explicit_column or field_name
        facts.append(ContractFact(
            key=f"orm-field:{class_name}:{field_name}",
            kind="ORM 持久化字段",
            location=class_name,
            member=field_name,
            tables=(table,),
            columns=(column,),
            normalized=f"{table}.{column}:{field_value.get('descriptor') or ''}",
            evidence=f"{entry}#{field_name}",
            confidence=(
                "确认"
                if explicit_table and explicit_column and field_access_certain
                else "需复核"
            ),
        ))
    for method_value in method_values if is_jpa else ():
        contract = method_value.get('contract') or {}
        access = int(contract.get('access') or 0)
        if access & 0x0008:
            continue
        annotations = _annotations_by_descriptor(contract.get('annotations') or ())
        if TRANSIENT_ANNOTATIONS.intersection(annotations):
            continue
        method_name = str(contract.get('name') or '')
        descriptor = str(contract.get('descriptor') or '')
        explicit_column = _first_annotation_value(
            annotations, COLUMN_ANNOTATIONS, 'name', 'value'
        )
        property_candidate = (
            method_id_present
            and descriptor.startswith('()')
            and (
                (method_name.startswith('get') and len(method_name) > 3)
                or (method_name.startswith('is') and len(method_name) > 2)
            )
        )
        if not explicit_column and not property_candidate:
            continue
        if method_name.startswith('get'):
            property_name = method_name[3:4].lower() + method_name[4:]
        elif method_name.startswith('is'):
            property_name = method_name[2:3].lower() + method_name[3:]
        else:
            property_name = method_name
        column = explicit_column or property_name
        facts.append(ContractFact(
            key=f"orm-property:{class_name}:{property_name}",
            kind="ORM 持久化属性",
            location=class_name,
            member=property_name,
            tables=(table,),
            columns=(column,),
            normalized=f"{table}.{column}:{descriptor}",
            evidence=f"{entry}#{method_name}{descriptor}",
            confidence=(
                "确认"
                if explicit_table and explicit_column
                and method_id_present and not field_id_present
                else "需复核"
            ),
        ))
    return facts


def _mybatis_plus_entity_targets(record: dict[str, Any]) -> set[str]:
    signature = str(record.get('class_signature') or '')
    return {
        match.group(1)
        for match in re.finditer(
            r'Lcom/baomidou/mybatisplus/core/mapper/BaseMapper<L([^;<>]+);>;',
            signature,
        )
    }


def facts_from_mapper_xml(content: bytes, entry: str) -> list[ContractFact]:
    if len(content) > MAX_XML_BYTES:
        raise ValueError(f"XML exceeds {MAX_XML_BYTES} bytes")
    root = ET.fromstring(content)
    if _local_name(root.tag) != "mapper":
        return []
    namespace = str(root.attrib.get("namespace") or entry)
    facts = []
    for element in root.iter():
        tag = _local_name(element.tag)
        if tag in {"select", "insert", "update", "delete"}:
            statement_id = str(element.attrib.get("id") or "<anonymous>")
            sql = " ".join(text for text in element.itertext() if text and text.strip())
            tables, columns, ambiguous = extract_sql_references(sql)
            dynamic = ambiguous or any(child is not element for child in element.iter())
            facts.append(ContractFact(
                key=f"mybatis-xml:{namespace}:{statement_id}",
                kind=f"MyBatis XML {tag.upper()}",
                location=namespace,
                member=statement_id,
                tables=tables,
                columns=columns,
                normalized=_sql_contract_fingerprint(
                    tag, tables, columns, sql, dynamic
                ),
                evidence=f"{entry}#{statement_id}",
                confidence="需复核" if dynamic else "确认",
            ))
        elif tag == 'sql':
            fragment_id = str(element.attrib.get('id') or '<anonymous>')
            sql = " ".join(text for text in element.itertext() if text and text.strip())
            tables, columns, ambiguous = extract_sql_fragment_references(sql)
            facts.append(ContractFact(
                key=f"mybatis-fragment:{namespace}:{fragment_id}",
                kind="MyBatis SQL 片段",
                location=namespace,
                member=fragment_id,
                tables=tables,
                columns=columns,
                normalized=_sql_contract_fingerprint(
                    'fragment', tables, columns, sql, True
                ),
                evidence=f"{entry}#{fragment_id}",
                confidence="需复核",
            ))
    for result_map in (item for item in root.iter() if _local_name(item.tag) == "resultMap"):
        result_map_id = str(result_map.attrib.get("id") or "<anonymous>")
        for element in result_map.iter():
            if _local_name(element.tag) not in {"id", "result"}:
                continue
            column = _clean_identifier(str(element.attrib.get("column") or ""))
            property_name = str(element.attrib.get("property") or "")
            if not column or not property_name:
                continue
            facts.append(ContractFact(
                key=f"mybatis-result:{namespace}:{result_map_id}:{property_name}",
                kind="MyBatis ResultMap 映射",
                location=namespace,
                member=f"{result_map_id}.{property_name}",
                columns=(_simple_column(column),),
                normalized=f"{column}->{property_name}",
                evidence=f"{entry}#{result_map_id}.{property_name}",
                confidence="需复核",
            ))
    return facts


def facts_from_orm_xml(content: bytes, entry: str) -> list[ContractFact]:
    """Extract explicit JPA orm.xml and Hibernate hbm.xml table/column mappings."""
    if len(content) > MAX_XML_BYTES:
        raise ValueError(f"XML exceeds {MAX_XML_BYTES} bytes")
    root = ET.fromstring(content)
    root_name = _local_name(root.tag)
    facts = []
    if root_name == 'entity-mappings':
        entities = [item for item in root.iter() if _local_name(item.tag) == 'entity']
        mapping_kind = 'JPA XML'
    elif root_name == 'hibernate-mapping':
        entities = [item for item in root.iter() if _local_name(item.tag) == 'class']
        mapping_kind = 'Hibernate XML'
    else:
        return []
    for entity in entities:
        class_name = str(entity.attrib.get('class') or entity.attrib.get('name') or '<anonymous>')
        table = _clean_identifier(str(entity.attrib.get('table') or ''))
        if not table:
            table_element = next(
                (child for child in entity if _local_name(child.tag) == 'table'), None
            )
            if table_element is not None:
                table = _clean_identifier(str(table_element.attrib.get('name') or ''))
        effective_table = table or class_name.rsplit('.', 1)[-1]
        facts.append(ContractFact(
            key=f"orm-xml-table:{mapping_kind}:{class_name}",
            kind=f"{mapping_kind} 实体表映射",
            location=class_name,
            member='<class>',
            tables=(effective_table,),
            normalized=effective_table,
            evidence=f"{entry}#{class_name}",
            confidence='确认' if table else '需复核',
        ))
        for element in entity.iter():
            tag = _local_name(element.tag)
            if tag not in {'id', 'basic', 'property', 'many-to-one', 'version'}:
                continue
            property_name = str(element.attrib.get('name') or '')
            column = _clean_identifier(str(element.attrib.get('column') or ''))
            if not column:
                column_element = next(
                    (child for child in element if _local_name(child.tag) == 'column'), None
                )
                if column_element is not None:
                    column = _clean_identifier(str(column_element.attrib.get('name') or ''))
            if not property_name:
                continue
            effective_column = column or property_name
            facts.append(ContractFact(
                key=f"orm-xml-field:{mapping_kind}:{class_name}:{property_name}",
                kind=f"{mapping_kind} 持久化属性",
                location=class_name,
                member=property_name,
                tables=(effective_table,),
                columns=(_simple_column(effective_column),),
                normalized=f"{effective_table}.{effective_column}",
                evidence=f"{entry}#{class_name}.{property_name}",
                confidence='确认' if table and column else '需复核',
            ))
    return facts


def _archive_class_inputs(
    archive: zipfile.ZipFile, identity: str, gaps: list[str] | None = None
):
    for info in archive.infolist():
        if info.is_dir() or not info.filename.endswith(".class"):
            continue
        if info.file_size > MAX_CLASS_BYTES:
            if gaps is not None:
                gaps.append(f"class_size_limit_exceeded:{info.filename}")
            continue
        content = archive.read(info)
        if any(marker in content for marker in CLASS_MARKERS):
            yield BinaryClassInput(identity, info.filename, content)


def scan_artifact(coord: str, version: str, side: str, path: Path) -> ArtifactFacts:
    result = ArtifactFacts(coord=coord, version=version, side=side, path=path)
    identity = f"{side}:{coord}:{version}:{hashlib.sha256(str(path).encode()).hexdigest()[:12]}"
    try:
        with zipfile.ZipFile(path) as archive:
            class_inputs = []
            for info in archive.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".xml"):
                    continue
                try:
                    if info.file_size > MAX_XML_BYTES:
                        with archive.open(info) as handle:
                            prefix = handle.read(4096)
                        if any(marker in prefix for marker in (
                            b'<mapper', b'<entity-mappings', b'<hibernate-mapping'
                        )):
                            result.gaps.append(f"xml_size_limit_exceeded:{info.filename}")
                        continue
                    content = archive.read(info)
                    for fact in facts_from_mapper_xml(content, info.filename):
                        result.facts[fact.key] = fact
                    if b'<entity-mappings' in content[:4096] or b'<hibernate-mapping' in content[:4096]:
                        for fact in facts_from_orm_xml(content, info.filename):
                            result.facts[fact.key] = fact
                except ET.ParseError:
                    # Most packaged XML files are not MyBatis mappers. Only flag
                    # files that look like one, avoiding unrelated XML noise.
                    try:
                        if b"<mapper" in content[:4096]:
                            result.gaps.append(f"mapper_xml_unreadable:{info.filename}")
                    except UnboundLocalError:
                        pass
                except (OSError, UnicodeError, ValueError) as error:
                    result.gaps.append(f"mapper_xml_unreadable:{info.filename}:{type(error).__name__}")
            try:
                class_inputs = list(_archive_class_inputs(archive, identity, result.gaps))
            except (OSError, RuntimeError) as error:
                result.gaps.append(f"class_candidate_read_failed:{type(error).__name__}")
    except (OSError, zipfile.BadZipFile) as error:
        result.gaps.append(f"artifact_unreadable:{type(error).__name__}")
        return result

    if class_inputs:
        try:
            run = extract_class_facts(class_inputs)
            class_records = {
                str(record.get('class_name') or ''): record
                for record in run.records
                if record.get('frame_type') == 'class_fact'
            }
            forced_entities = set().union(*(
                _mybatis_plus_entity_targets(record)
                for record in class_records.values()
            )) if class_records else set()
            missing_forced_entities = forced_entities - set(class_records)
            if missing_forced_entities:
                try:
                    with zipfile.ZipFile(path) as archive:
                        names = {
                            info.filename: info
                            for info in archive.infolist()
                            if not info.is_dir()
                        }
                        additional_inputs = []
                        for target in sorted(missing_forced_entities):
                            matching = [
                                name for name in names
                                if name == f'{target}.class'
                                or name.endswith(f'/{target}.class')
                            ]
                            if len(matching) != 1:
                                result.gaps.append(
                                    f"mybatis_plus_entity_resolution:{target}:{len(matching)}"
                                )
                                continue
                            info = names[matching[0]]
                            if info.file_size > MAX_CLASS_BYTES:
                                result.gaps.append(
                                    f"class_size_limit_exceeded:{matching[0]}"
                                )
                                continue
                            additional_inputs.append(BinaryClassInput(
                                identity, matching[0], archive.read(info)
                            ))
                    if additional_inputs:
                        additional_run = extract_class_facts(additional_inputs)
                        class_records.update({
                            str(record.get('class_name') or ''): record
                            for record in additional_run.records
                            if record.get('frame_type') == 'class_fact'
                        })
                        if additional_run.coverage_status != 'complete':
                            result.gaps.append(
                                f"mybatis_plus_entity_fact_coverage:{additional_run.coverage_status}"
                            )
                except (OSError, zipfile.BadZipFile, BinaryAsmError, RuntimeError) as error:
                    result.gaps.append(
                        f"mybatis_plus_entity_extraction_failed:{type(error).__name__}"
                    )
            for record in class_records.values():
                entry = str(record.get("class_entry") or "")
                internal_name = str(record.get('class_name') or '')
                for fact in facts_from_class_record(
                    record,
                    entry,
                    force_mybatis_plus_entity=internal_name in forced_entities,
                ):
                    result.facts[fact.key] = fact
            if run.coverage_status != "complete":
                result.gaps.append(f"class_fact_coverage:{run.coverage_status}")
        except (BinaryAsmError, OSError, RuntimeError) as error:
            result.gaps.append(f"class_fact_extraction_failed:{type(error).__name__}")
    return result


def _artifact_rows(manifest: dict[str, Any]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: {"base": [], "current": []}
    )
    for item in manifest.get("items") or ():
        if "binary_runtime" not in set(item.get("purposes") or ("binary_runtime",)):
            continue
        side = str(item.get("side") or "")
        coord = str(item.get("coord") or "").strip()
        if side in {"base", "current"} and coord:
            grouped[coord][side].append(dict(item))
    for item in manifest.get("business_artifacts") or ():
        side = str(item.get("side") or "")
        if side in {"base", "current"}:
            row = dict(item)
            row.setdefault("coord", "被分析系统")
            row.setdefault("version", side)
            grouped["被分析系统"][side].append(row)
    return grouped


def _contract_text(fact: ContractFact | None) -> str:
    if fact is None:
        return "-"
    parts = []
    if fact.tables:
        parts.append("表=" + ", ".join(fact.tables))
    if fact.columns:
        parts.append("列=" + ", ".join(fact.columns))
    if not parts and fact.normalized:
        parts.append(fact.normalized[:500])
    return "；".join(parts) or "已记录契约"


def compare_artifact_facts(base: ArtifactFacts | None, current: ArtifactFacts | None) -> list[dict[str, str]]:
    if base is None and current is None:
        return []
    coord = (current or base).coord
    base_facts = base.facts if base else {}
    current_facts = current.facts if current else {}
    rows = []
    for key in sorted(set(base_facts) | set(current_facts)):
        old = base_facts.get(key)
        new = current_facts.get(key)
        if old and new and old.normalized == new.normalized:
            continue
        if old is None:
            change_type = "新增当前契约"
        elif new is None:
            change_type = "移除旧契约"
        else:
            change_type = "修改契约"
        representative = new or old
        confidence = "确认"
        if representative.confidence != "确认" or (old and old.confidence != "确认"):
            confidence = "需复核"
        if change_type == "新增当前契约":
            action = "确认目标数据库结构已满足当前版本新增的数据访问契约，并执行对应场景测试。"
        elif change_type == "移除旧契约":
            action = "如存在回滚或新旧版本并行窗口，确认数据库结构仍满足旧版本契约。"
        else:
            action = "确认目标数据库结构与修改后的数据访问契约一致，并执行对应场景测试。"
        rows.append({
            "依赖包": coord,
            "旧版本": base.version if base else "-",
            "新版本": current.version if current else "-",
            "变化类型": change_type,
            "契约类型": representative.kind,
            "可信度": confidence,
            "表": ", ".join(new.tables if new else old.tables),
            "列": ", ".join(new.columns if new else old.columns),
            "契约位置": representative.location,
            "语句或字段": representative.member,
            "旧契约": _contract_text(old),
            "新契约": _contract_text(new),
            "证据": (new or old).evidence,
            "人工复核建议": action,
        })
    return rows


def _scan_side_rows(
    coord: str, side: str, rows: list[dict[str, Any]], gaps: list[str]
) -> ArtifactFacts | None:
    if not rows:
        return None
    if len(rows) != 1:
        gaps.append(f"artifact_pairing_ambiguous:{side}:{coord}:{len(rows)}")
        return None
    row = rows[0]
    path = Path(str(row.get("retained_path") or ""))
    if not path.is_file():
        gaps.append(f"artifact_missing:{side}:{coord}:{path}")
        return None
    expected = str(row.get("nested_jar_sha256") or row.get("sha256") or "").lower()
    if expected:
        try:
            digest_value = hashlib.sha256()
            with path.open('rb') as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b''):
                    digest_value.update(block)
            digest = digest_value.hexdigest()
        except OSError as error:
            gaps.append(f"artifact_digest_unreadable:{side}:{coord}:{type(error).__name__}")
            return None
        if digest != expected:
            gaps.append(f"artifact_digest_mismatch:{side}:{coord}")
            return None
    result = scan_artifact(coord, str(row.get("version") or side), side, path)
    gaps.extend(f"{side}:{coord}:{gap}" for gap in result.gaps)
    return result


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _write_outputs(output_dir: Path, rows: list[dict[str, str]], summary: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    with open_csv_write(output_dir / CSV_NAME) as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    (output_dir / SUMMARY_NAME).write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# 数据库契约变化明细",
        "",
        "> 本文件比较升级前后制品中的数据访问契约，不扫描 DDL/迁移文件，",
        "> 因而不表示对应表结构变更已经存在或已在目标环境执行。",
        "> MyBatis-Plus 约定式无注解实体通过同一制品内的 `BaseMapper<Entity>` 绑定识别；",
        "> 实体无法在该制品内绑定时会记录覆盖缺口，不推断跨制品关系。",
        "",
        f"- 覆盖状态：{summary['coverage_status']}",
        f"- 变化条目：{len(rows)}",
        f"- 涉及依赖包：{summary['changed_dependency_count']}",
        "",
    ]
    if summary["coverage_gaps"]:
        lines.extend(["## 证据缺口", ""])
        lines.extend(f"- `{gap}`" for gap in summary["coverage_gaps"])
        lines.append("")
    if rows:
        lines.extend([
            "## 全部变化", "",
            "| 依赖包 | 变化 | 契约类型 | 可信度 | 表 | 列 | 契约位置 | 人工复核建议 |",
            "|---|---|---|---|---|---|---|---|",
        ])
        for row in rows:
            cells = [
                row["依赖包"], row["变化类型"], row["契约类型"], row["可信度"],
                row["表"] or "-", row["列"] or "-",
                f"{row['契约位置']}#{row['语句或字段']}", row["人工复核建议"],
            ]
            cells = [str(value).replace("|", "\\|").replace("\n", " ") for value in cells]
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")
    else:
        result_text = (
            "本次未识别到升级前后数据访问契约变化。"
            if summary['coverage_status'] == 'complete'
            else "现有证据中未识别到数据访问契约变化；因存在证据缺口，不能解释为确认没有变化。"
        )
        lines.extend(["## 结果", "", result_text, ""])
    (output_dir / REVIEW_NAME).write_text("\n".join(lines), encoding="utf-8")


def scan_database_contracts(report_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
    report_root = Path(report_dir)
    output_root = Path(output_dir)
    manifest_path = report_root / "evidence" / "dependencies" / "dependency_jars.json"
    gaps = []
    rows: list[dict[str, str]] = []
    manifest: dict[str, Any] = {}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or manifest.get("schema") != "java-upgrade-analyzer.step1-dependency-jars.v3":
            raise ValueError("unsupported dependency_jars schema")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        gaps.append(f"dependency_jars_manifest_unavailable:{type(error).__name__}")

    if manifest:
        for side in ("base", "current"):
            closure = dict((manifest.get("runtime_closure") or {}).get(side) or {})
            if str(closure.get("coverage_status") or "") != "complete":
                gaps.append(f"runtime_closure_incomplete:{side}")
        for coord, sides in sorted(_artifact_rows(manifest).items()):
            if len(sides['base']) == len(sides['current']) == 1:
                base_hash = str(
                    sides['base'][0].get('nested_jar_sha256')
                    or sides['base'][0].get('sha256') or ''
                ).lower()
                current_hash = str(
                    sides['current'][0].get('nested_jar_sha256')
                    or sides['current'][0].get('sha256') or ''
                ).lower()
                if base_hash and base_hash == current_hash:
                    base_path = Path(str(sides['base'][0].get('retained_path') or ''))
                    current_path = Path(str(sides['current'][0].get('retained_path') or ''))
                    try:
                        if (
                            base_path.is_file()
                            and current_path.is_file()
                            and _sha256_path(base_path) == base_hash
                            and _sha256_path(current_path) == current_hash
                        ):
                            continue
                    except OSError:
                        # Side scanning below records the concrete integrity gap.
                        pass
            base = _scan_side_rows(coord, "base", sides["base"], gaps)
            current = _scan_side_rows(coord, "current", sides["current"], gaps)
            rows.extend(compare_artifact_facts(base, current))

    rows.sort(key=lambda row: (
        0 if row["变化类型"] != "移除旧契约" else 1,
        row["依赖包"], row["契约位置"], row["语句或字段"], row["契约类型"],
    ))
    coverage_status = "complete" if not gaps else ("partial" if manifest else "insufficient")
    summary = {
        "schema": SCHEMA,
        "coverage_status": coverage_status,
        "coverage_gaps": sorted(set(gaps)),
        "change_count": len(rows),
        "confirmed_count": sum(row["可信度"] == "确认" for row in rows),
        "review_count": sum(row["可信度"] != "确认" for row in rows),
        "changed_dependency_count": len({row["依赖包"] for row in rows}),
        "outputs": {
            "csv": CSV_NAME,
            "human_review": REVIEW_NAME,
        },
        "boundary": (
            "未扫描 DDL/迁移文件；结果仅表示数据访问契约变化。"
            "MyBatis-Plus 约定式无注解实体仅解析同一制品内的 BaseMapper 泛型绑定。"
        ),
    }
    _write_outputs(output_root, rows, summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="升级前后数据库访问契约对比")
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    summary = scan_database_contracts(args.report_dir, args.output_dir)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
