import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import database_contract_scan as scan  # noqa: E402
from binary_asm_helper import BinaryAsmError  # noqa: E402
from database_contract_scan import (  # noqa: E402
    ArtifactFacts,
    ContractFact,
    _annotation_values,
    _annotations_by_descriptor,
    _archive_class_inputs,
    _artifact_rows,
    _bean_property_name,
    _clean_identifier,
    _contract_text,
    _first_annotation_value,
    _local_name,
    _normalize_sql,
    _scan_side_rows,
    _simple_column,
    _sql_contract_fingerprint,
    _sql_from_annotation,
    _write_outputs,
    compare_artifact_facts,
    extract_sql_fragment_references,
    extract_sql_references,
    facts_from_class_record,
    facts_from_mapper_xml,
    facts_from_orm_xml,
    scan_artifact,
    scan_database_contracts,
)


def _annotation(descriptor, *values):
    return {"descriptor": descriptor, "values": list(values)}


def _fact(
    key="key",
    *,
    normalized="normalized",
    confidence="确认",
    tables=(),
    columns=(),
    evidence="entry#member",
):
    return ContractFact(
        key=key,
        kind="fixture-kind",
        location="fixture.Location",
        member="member",
        normalized=normalized,
        confidence=confidence,
        tables=tuple(tables),
        columns=tuple(columns),
        evidence=evidence,
    )


class DatabaseContractScanBoundaryTest(unittest.TestCase):
    def test_identifier_and_sql_normalization_partitions_empty_qualified_and_comments(self):
        self.assertEqual(_local_name(None), "")
        self.assertEqual(_local_name("{urn:test}mapper"), "mapper")
        self.assertEqual(_clean_identifier(None), "")
        self.assertEqual(
            _clean_identifier(' [catalog] . `schema` . "orders" . '),
            "catalog.schema.orders",
        )
        self.assertEqual(_simple_column(""), "")
        self.assertEqual(_simple_column("schema.orders.order_id"), "order_id")
        self.assertEqual(
            _normalize_sql(None), ""
        )
        self.assertEqual(
            _normalize_sql("select /* block\ncomment */ id -- line\n from orders;"),
            "select id from orders",
        )
        exact = json.loads(
            _sql_contract_fingerprint(
                "SELECT", ("orders",), ("id",), "ignored", False
            )
        )
        ambiguous = json.loads(
            _sql_contract_fingerprint(
                "SELECT", (), (), " select ${column} ", True
            )
        )
        self.assertNotIn("ambiguous_sql", exact)
        self.assertEqual(ambiguous["ambiguous_sql"], "select ${column}")

    def test_sql_reference_extraction_covers_all_supported_statement_shapes(self):
        cases = (
            (
                "select o.id as order_id, o.state from sales.orders o "
                "join tenants t on t.id=o.tenant_id where o.state like #{state}",
                ("sales.orders", "tenants"),
                ("id", "state", "tenant_id"),
                False,
            ),
            (
                "insert into orders (id, state) values (#{id}, #{state})",
                ("orders",),
                ("id", "state"),
                False,
            ),
            (
                "update orders set state = #{state}, updated_at=#{time} "
                "where id between #{low} and #{high}",
                ("orders",),
                ("id", "state", "updated_at"),
                False,
            ),
            (
                "delete from orders where id in (#{ids})",
                ("orders",),
                ("id",),
                False,
            ),
            ("select ${column} from ${table}", (), (), True),
            ("call dynamic_procedure()", (), (), True),
        )
        for sql, tables, columns, ambiguous in cases:
            with self.subTest(sql=sql):
                self.assertEqual(
                    extract_sql_references(sql), (tables, columns, ambiguous)
                )

        tables, columns, ambiguous = extract_sql_references(
            "select *, invalid(expression), valid_name from orders"
        )
        self.assertEqual(tables, ("orders",))
        self.assertEqual(columns, ("valid_name",))
        self.assertFalse(ambiguous)
        self.assertEqual(
            extract_sql_references("select id from orders where null = id"),
            (("orders",), ("id",), False),
        )

    def test_sql_fragment_extraction_distinguishes_projection_and_ambiguous_text(self):
        self.assertEqual(
            extract_sql_fragment_references("orders.id, `state`, created_at"),
            ((), ("created_at", "id", "state"), False),
        )
        self.assertEqual(
            extract_sql_fragment_references("id, from"),
            ((), (), True),
        )
        self.assertEqual(
            extract_sql_fragment_references(""),
            ((), (), True),
        )
        self.assertEqual(
            extract_sql_fragment_references("select id from orders"),
            (("orders",), ("id",), False),
        )

    def test_annotation_helpers_reject_malformed_values_and_preserve_supported_shapes(self):
        annotation = {
            "values": [
                None,
                ["short"],
                [None, "empty-name"],
                ["scalar", "value"],
                ["extended-scalar", "value", "ignored"],
                ["array", "array", ["one", 2]],
                ["bad-array", "array", "not-a-list"],
            ]
        }
        self.assertEqual(
            _annotation_values(annotation),
            {
                "": "empty-name",
                "scalar": "value",
                "extended-scalar": "value",
                "array": ["one", 2],
                "bad-array": [],
            },
        )
        self.assertEqual(_annotation_values({}), {})
        descriptors = _annotations_by_descriptor(
            [
                None,
                {},
                {"descriptor": ""},
                {"descriptor": "Lone;@visible", "values": []},
                {"descriptor": "Ltwo;", "values": []},
            ]
        )
        self.assertEqual(set(descriptors), {"Lone;", "Ltwo;"})
        self.assertEqual(_annotations_by_descriptor(None), {})

        annotations = {
            "Lfirst;": _annotation("Lfirst;", ["name", 1]),
            "Lsecond;": _annotation(
                "Lsecond;", ["name", "  "], ["value", " chosen "]
            ),
        }
        self.assertEqual(
            _first_annotation_value(
                annotations, {"Lmissing;", "Lfirst;", "Lsecond;"}, "name", "value"
            ),
            "chosen",
        )
        self.assertEqual(
            _first_annotation_value(annotations, {"Lmissing;"}, "name"), ""
        )
        self.assertEqual(
            _first_annotation_value(annotations, {"Lfirst;"}, "name"), ""
        )
        self.assertEqual(
            _sql_from_annotation(
                _annotation("Lsql;", ["value", "array", ["select", 1, "id"]])
            ),
            "select id",
        )
        self.assertEqual(
            _sql_from_annotation(_annotation("Lsql;", ["value", "select 1"])),
            "select 1",
        )
        self.assertEqual(_sql_from_annotation({}), "")
        self.assertEqual(_bean_property_name("getX", 3), "x")

    def test_class_annotation_sql_provider_and_fallback_member_are_retained(self):
        methods = []
        for index, descriptor in enumerate(scan.SQL_ANNOTATIONS):
            methods.append(
                {
                    "contract": {
                        "annotations": [
                            _annotation(
                                descriptor,
                                [
                                    "value",
                                    "array",
                                    [
                                        "select ${column} from ${table}"
                                        if index == 0
                                        else "select id from orders"
                                    ],
                                ],
                            )
                        ]
                    }
                }
            )
        methods.append(
            {
                "contract": {
                    "name": "provided",
                    "descriptor": "()V",
                    "annotations": [
                        _annotation(
                            next(iter(scan.SQL_PROVIDER_ANNOTATIONS)),
                            ["type", "Lfixture/Provider;"],
                        ),
                        _annotation("Lfixture/Unrelated;"),
                    ],
                }
            }
        )
        facts = facts_from_class_record(
            {"annotations": [], "fields": [], "methods": methods},
            "fixture/Fallback.class",
        )
        self.assertEqual(len(facts), len(scan.SQL_ANNOTATIONS) + 1)
        self.assertTrue(any(fact.kind == "MyBatis SQL Provider" for fact in facts))
        self.assertTrue(any(fact.location == "fixture.Fallback" for fact in facts))
        self.assertTrue(any(fact.member == "?" for fact in facts))
        self.assertTrue(any(fact.confidence == "需复核" for fact in facts))

    def test_entity_field_filtering_and_confidence_matrix_is_explicit(self):
        table = _annotation(
            "Ljakarta/persistence/Table;", ["name", "orders"]
        )
        record = {
            "class_name": "fixture/Order",
            "annotations": [
                _annotation("Ljakarta/persistence/Entity;"),
                table,
            ],
            "methods": [],
            "fields": [
                {"name": "staticValue", "access": 0x0008},
                {"name": "javaTransient", "access": 0x0080},
                {
                    "name": "jpaTransient",
                    "annotations": [_annotation("Ljakarta/persistence/Transient;")],
                },
                {
                    "name": "notExisting",
                    "annotations": [
                        _annotation(
                            "Lcom/baomidou/mybatisplus/annotation/TableField;",
                            ["exist", False],
                        )
                    ],
                },
                {"name": "", "annotations": []},
                {
                    "name": "explicit",
                    "descriptor": "Ljava/lang/String;",
                    "annotations": [
                        _annotation(
                            "Ljakarta/persistence/Column;",
                            ["name", "explicit_column"],
                        ),
                        _annotation("Ljakarta/persistence/Id;"),
                    ],
                },
                {"name": "implicit", "descriptor": "J", "annotations": []},
                {"name": "noDescriptor", "annotations": []},
            ],
        }
        facts = facts_from_class_record(record, "fixture/Order.class")
        members = {fact.member: fact for fact in facts}
        self.assertEqual(
            set(members), {"<class>", "explicit", "implicit", "noDescriptor"}
        )
        self.assertEqual(members["explicit"].confidence, "确认")
        self.assertEqual(members["implicit"].confidence, "需复核")
        self.assertEqual(members["implicit"].columns, ("implicit",))

        forced = facts_from_class_record(
            {
                "class_name": "fixture/ConventionDto",
                "annotations": [],
                "methods": [],
                "fields": [{"name": "value", "descriptor": "I"}],
            },
            "fixture/ConventionDto.class",
            force_mybatis_plus_entity=True,
        )
        self.assertTrue(any(fact.member == "value" for fact in forced))

    def test_jpa_property_access_covers_getter_boolean_explicit_and_filtered_methods(self):
        record = {
            "class_name": "fixture/PropertyEntity",
            "annotations": [_annotation("Ljakarta/persistence/Entity;")],
            "fields": [{"name": "backing", "descriptor": "J"}],
            "methods": [
                {},
                {
                    "contract": {
                        "name": "getId",
                        "descriptor": "()J",
                        "annotations": [_annotation("Ljakarta/persistence/Id;")],
                    }
                },
                {"contract": {"name": "getName", "descriptor": "()Ljava/lang/String;"}},
                {"contract": {"name": "isActive", "descriptor": "()Z"}},
                {"contract": {"name": "getURL", "descriptor": "()Ljava/lang/String;"}},
                {"contract": {"name": "get", "descriptor": "()I"}},
                {"contract": {"name": "is", "descriptor": "()Z"}},
                {"contract": {"name": "getArg", "descriptor": "(I)I"}},
                {"contract": {"name": "staticGetter", "descriptor": "()I", "access": 8}},
                {
                    "contract": {
                        "name": "getTransient",
                        "descriptor": "()I",
                        "annotations": [_annotation("Ljakarta/persistence/Transient;")],
                    }
                },
                {
                    "contract": {
                        "name": "custom",
                        "descriptor": "()I",
                        "annotations": [
                            _annotation(
                                "Ljakarta/persistence/Column;", ["name", "custom_col"]
                            )
                        ],
                    }
                },
            ],
        }
        facts = facts_from_class_record(record, "fixture/PropertyEntity.class")
        properties = {
            fact.member: fact for fact in facts if fact.kind == "ORM 持久化属性"
        }
        self.assertEqual(
            set(properties), {"id", "name", "active", "URL", "custom"}
        )
        self.assertEqual(properties["custom"].columns, ("custom_col",))
        self.assertEqual(properties["name"].confidence, "需复核")

        mixed = copy.deepcopy(record)
        mixed["annotations"].append(
            _annotation("Ljakarta/persistence/Table;", ["name", "entities"])
        )
        mixed["fields"][0]["annotations"] = [
            _annotation("Ljakarta/persistence/Id;")
        ]
        mixed_properties = {
            fact.member: fact
            for fact in facts_from_class_record(mixed, "fixture/PropertyEntity.class")
            if fact.kind == "ORM 持久化属性"
        }
        self.assertEqual(mixed_properties["custom"].confidence, "需复核")

        field_access = {
            "class_name": "fixture/FieldAccess",
            "annotations": [
                _annotation("Ljakarta/persistence/Entity;"),
                _annotation("Ljakarta/persistence/Table;", ["name", "entities"]),
            ],
            "fields": [
                {
                    "name": "id",
                    "annotations": [_annotation("Ljakarta/persistence/Id;")],
                }
            ],
            "methods": [
                {
                    "contract": {
                        "name": "custom",
                        "descriptor": "()I",
                        "annotations": [
                            _annotation(
                                "Ljakarta/persistence/Column;", ["name", "custom_col"]
                            )
                        ],
                    }
                }
            ],
        }
        custom = next(
            fact
            for fact in facts_from_class_record(field_access, "fixture/FieldAccess.class")
            if fact.member == "custom"
        )
        self.assertEqual(custom.confidence, "需复核")

    def test_mapper_xml_covers_root_size_statement_fragment_and_result_map_boundaries(self):
        with self.assertRaises(ValueError):
            facts_from_mapper_xml(b"x" * (scan.MAX_XML_BYTES + 1), "large.xml")
        self.assertEqual(facts_from_mapper_xml(b"<root/>", "root.xml"), [])
        content = b"""<mapper>
          <select>select id from orders</select>
          <insert id="add">insert into orders(id) values (1)</insert>
          <update id="change"><if test="x">update orders set state='x'</if></update>
          <delete id="remove">delete from orders where id=1</delete>
          <sql>id, state</sql>
          <resultMap>
            <constructor/>
            <id property="id" column="orders.id"/>
            <result property="" column="ignored"/>
            <result property="name" column=""/>
          </resultMap>
        </mapper>"""
        facts = facts_from_mapper_xml(content, "mapper.xml")
        self.assertEqual(sum(f.kind.startswith("MyBatis XML") for f in facts), 4)
        self.assertTrue(any(f.member == "<anonymous>" for f in facts))
        self.assertTrue(any(f.kind == "MyBatis SQL 片段" for f in facts))
        mapping = next(f for f in facts if f.kind == "MyBatis ResultMap 映射")
        self.assertEqual(mapping.member, "<anonymous>.id")
        update = next(f for f in facts if f.kind == "MyBatis XML UPDATE")
        self.assertEqual(update.confidence, "需复核")

    def test_orm_xml_covers_root_size_table_column_and_fallback_boundaries(self):
        with self.assertRaises(ValueError):
            facts_from_orm_xml(b"x" * (scan.MAX_XML_BYTES + 1), "large.xml")
        self.assertEqual(facts_from_orm_xml(b"<root/>", "root.xml"), [])
        jpa = facts_from_orm_xml(
            b"""<entity-mappings>
              <entity><other/><table/><attributes>
                <id name="id"><other/><column name="id_col"/></id>
                <basic name="emptyColumn"><column/></basic>
                <basic/>
                <many-to-one name="owner" column="owner_id"/>
                <version name="version"/>
                <ignored name="ignored"/>
              </attributes></entity>
            </entity-mappings>""",
            "orm.xml",
        )
        self.assertTrue(any(f.location == "<anonymous>" for f in jpa))
        self.assertTrue(any(f.member == "id" and f.columns == ("id_col",) for f in jpa))
        self.assertTrue(any(f.member == "version" and f.confidence == "需复核" for f in jpa))
        no_table = facts_from_orm_xml(
            b'<entity-mappings><entity class="fixture.NoTable">'
            b'<attributes><basic name="value"/></attributes>'
            b'</entity></entity-mappings>',
            "orm.xml",
        )
        self.assertTrue(all(f.confidence == "需复核" for f in no_table))
        hibernate = facts_from_orm_xml(
            b'<hibernate-mapping><class name="fixture.Order" table="orders">'
            b'<property name="state" column="state_col"/>'
            b'<property name="implicit"/>'
            b'</class></hibernate-mapping>',
            "Order.hbm.xml",
        )
        self.assertEqual(
            next(f for f in hibernate if f.member == "state").confidence,
            "确认",
        )
        self.assertEqual(
            next(f for f in hibernate if f.member == "implicit").confidence,
            "需复核",
        )

    def test_archive_class_candidates_cover_directory_extension_marker_size_and_gap_sink(self):
        class FakeArchive:
            def __init__(self):
                self.rows = [
                    SimpleNamespace(filename="dir/", file_size=0, is_dir=lambda: True),
                    SimpleNamespace(filename="note.txt", file_size=1, is_dir=lambda: False),
                    SimpleNamespace(filename="Huge.class", file_size=scan.MAX_CLASS_BYTES + 1, is_dir=lambda: False),
                    SimpleNamespace(filename="Plain.class", file_size=5, is_dir=lambda: False),
                    SimpleNamespace(filename="Entity.class", file_size=100, is_dir=lambda: False),
                ]

            def infolist(self):
                return self.rows

            def read(self, info):
                if info.filename == "Entity.class":
                    return b"Ljakarta/persistence/Entity;"
                return b"plain"

        gaps = []
        values = list(_archive_class_inputs(FakeArchive(), "identity", gaps))
        self.assertEqual([item.class_entry for item in values], ["Entity.class"])
        self.assertEqual(gaps, ["class_size_limit_exceeded:Huge.class"])
        self.assertEqual(
            [item.class_entry for item in _archive_class_inputs(FakeArchive(), "identity")],
            ["Entity.class"],
        )

    def test_artifact_rows_filters_purpose_side_and_applies_business_defaults(self):
        grouped = _artifact_rows(
            {
                "items": [
                    {"side": "base", "coord": "g:a", "purposes": ["binary_runtime"]},
                    {"side": "current", "coord": "g:a"},
                    {"side": "base", "coord": "ignored", "purposes": ["source"]},
                    {"side": "future", "coord": "ignored"},
                    {"side": "base", "coord": "   "},
                    {"coord": "missing-side"},
                    {"side": "base"},
                ],
                "business_artifacts": [
                    {"side": "base"},
                    {"side": "current", "coord": "custom", "version": "2"},
                    {"side": "future"},
                    {},
                ],
            }
        )
        self.assertEqual(len(grouped["g:a"]["base"]), 1)
        self.assertEqual(len(grouped["g:a"]["current"]), 1)
        self.assertEqual(grouped["被分析系统"]["base"][0]["version"], "base")
        self.assertEqual(grouped["被分析系统"]["current"][0]["coord"], "custom")
        self.assertEqual(_artifact_rows({}), {})

    def test_contract_rendering_and_change_rows_cover_all_change_types_and_confidence(self):
        self.assertEqual(_contract_text(None), "-")
        self.assertEqual(_contract_text(_fact(tables=("orders",), columns=("id",))), "表=orders；列=id")
        self.assertEqual(_contract_text(_fact(normalized="x" * 600)), "x" * 500)
        self.assertEqual(_contract_text(_fact(normalized="")), "已记录契约")
        self.assertEqual(compare_artifact_facts(None, None), [])

        base = ArtifactFacts("g:a", "1", "base", Path("base.jar"))
        current = ArtifactFacts("g:a", "2", "current", Path("current.jar"))
        base.facts = {
            "same": _fact("same", normalized="same"),
            "removed": _fact("removed", confidence="需复核", columns=("old",)),
            "changed": _fact("changed", normalized="old", tables=("old_table",)),
        }
        current.facts = {
            "same": _fact("same", normalized="same"),
            "added": _fact("added", columns=("new",)),
            "changed": _fact("changed", normalized="new", tables=("new_table",)),
            "changed-review": _fact("changed-review", normalized="new"),
        }
        base.facts["changed-review"] = _fact(
            "changed-review", normalized="old", confidence="需复核"
        )
        rows = compare_artifact_facts(base, current)
        self.assertEqual(
            {row["变化类型"] for row in rows},
            {"新增当前契约", "移除旧契约", "修改契约"},
        )
        self.assertEqual(next(r for r in rows if r["变化类型"] == "移除旧契约")["可信度"], "需复核")
        self.assertIn("回滚", next(r for r in rows if r["变化类型"] == "移除旧契约")["人工复核建议"])
        self.assertEqual(compare_artifact_facts(None, current)[0]["旧版本"], "-")
        self.assertEqual(compare_artifact_facts(base, None)[0]["新版本"], "-")

    def test_scan_side_rows_partitions_cardinality_path_digest_and_scan_gaps(self):
        gaps = []
        self.assertIsNone(_scan_side_rows("g:a", "base", [], gaps))
        self.assertIsNone(_scan_side_rows("g:a", "base", [{}, {}], gaps))
        self.assertIn("artifact_pairing_ambiguous:base:g:a:2", gaps)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = {"retained_path": str(root / "missing.jar")}
            self.assertIsNone(_scan_side_rows("g:a", "base", [missing], gaps))
            self.assertIsNone(_scan_side_rows("g:a", "base", [{}], gaps))
            artifact = root / "artifact.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("payload", b"value")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self.assertIsNone(
                _scan_side_rows(
                    "g:a",
                    "base",
                    [{"retained_path": str(artifact)}],
                    gaps,
                )
            )
            self.assertIn("artifact_identity_invalid:base:g:a", gaps)
            self.assertIsNone(
                _scan_side_rows(
                    "g:a",
                    "base",
                    [{"retained_path": str(artifact), "nested_jar_sha256": "0" * 64}],
                    gaps,
                )
            )
            with mock.patch.object(
                scan,
                "scan_artifact",
                return_value=ArtifactFacts(
                    "g:a", "fallback", "base", artifact, gaps=["inner-gap"]
                ),
            ) as called:
                result = _scan_side_rows(
                    "g:a",
                    "base",
                    [{"retained_path": str(artifact), "sha256": digest}],
                    gaps,
                    jdk_home="/selected/jdk",
                )
            self.assertIsNotNone(result)
            self.assertEqual(called.call_args.args[1], "base")
            self.assertEqual(called.call_args.kwargs["jdk_home"], "/selected/jdk")
            self.assertIn("base:g:a:inner-gap", gaps)

    def test_output_rendering_covers_rows_gaps_escaping_and_empty_statuses(self):
        row = {
            field: "value" for field in scan.CSV_FIELDS
        }
        row.update(
            {
                "依赖包": "g|a",
                "变化类型": "新增当前契约",
                "契约类型": "kind",
                "可信度": "确认",
                "表": "",
                "列": "",
                "契约位置": "line\nbreak",
                "语句或字段": "member",
                "人工复核建议": "review",
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = {
                "coverage_status": "partial",
                "coverage_gaps": ["gap"],
                "changed_dependency_count": 1,
            }
            _write_outputs(root / "rows", [row], summary)
            review = (root / "rows" / scan.REVIEW_NAME).read_text(encoding="utf-8")
            self.assertIn("g\\|a", review)
            self.assertIn("line break#member", review)
            self.assertIn("## 证据缺口", review)

            for status, expected in (
                ("complete", "本次未识别到升级前后数据访问契约变化。"),
                ("partial", "不能解释为确认没有变化"),
            ):
                output = root / status
                _write_outputs(
                    output,
                    [],
                    {
                        "coverage_status": status,
                        "coverage_gaps": [],
                        "changed_dependency_count": 0,
                    },
                )
                self.assertIn(
                    expected,
                    (output / scan.REVIEW_NAME).read_text(encoding="utf-8"),
                )

    def test_scan_artifact_reports_unreadable_and_xml_boundaries_without_overstating(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = root / "bad.jar"
            bad.write_bytes(b"bad")
            result = scan_artifact("g:a", "1", "base", bad)
            self.assertEqual(result.gaps, ["artifact_unreadable:BadZipFile"])

            artifact = root / "xml.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("dir/", b"")
                archive.writestr("not-xml.txt", b"ignored")
                archive.writestr("broken-mapper.xml", b"<mapper>")
                archive.writestr("broken-other.xml", b"<other>")
                archive.writestr("valid.xml", b"<mapper><select id='x'>select id from t</select></mapper>")
            result = scan_artifact("g:a", "1", "current", artifact)
            self.assertIn("mapper_xml_unreadable:broken-mapper.xml", result.gaps)
            self.assertFalse(any("broken-other" in gap for gap in result.gaps))
            self.assertTrue(any(fact.tables == ("t",) for fact in result.facts.values()))

            formats = root / "formats.jar"
            with zipfile.ZipFile(formats, "w") as archive:
                archive.writestr(
                    "hibernate.xml",
                    b'<hibernate-mapping><class name="E" table="entities"/></hibernate-mapping>',
                )
                archive.writestr("other.xml", b"<other/>")
            result = scan_artifact("g:a", "1", "current", formats)
            self.assertTrue(any(fact.tables == ("entities",) for fact in result.facts.values()))

            large = root / "large-xml.jar"
            with zipfile.ZipFile(large, "w") as archive:
                archive.writestr("mapper.xml", b"<mapper" + b"x" * 20)
                archive.writestr("jpa.xml", b"<entity-mappings" + b"x" * 20)
                archive.writestr("hibernate.xml", b"<hibernate-mapping" + b"x" * 20)
                archive.writestr("unrelated.xml", b"<unrelated" + b"x" * 20)
            with mock.patch.object(scan, "MAX_XML_BYTES", 8):
                result = scan_artifact("g:a", "1", "current", large)
            self.assertEqual(
                set(result.gaps),
                {
                    "xml_size_limit_exceeded:mapper.xml",
                    "xml_size_limit_exceeded:jpa.xml",
                    "xml_size_limit_exceeded:hibernate.xml",
                },
            )

    def test_scan_artifact_reports_class_candidate_read_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "artifact.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("payload", b"value")
            for failure in (OSError("read"), RuntimeError("read")):
                with self.subTest(failure=type(failure).__name__), mock.patch.object(
                    scan, "_archive_class_inputs", side_effect=failure
                ):
                    result = scan_artifact("g:a", "1", "base", artifact)
                self.assertEqual(
                    result.gaps,
                    [f"class_candidate_read_failed:{type(failure).__name__}"],
                )

    def test_scan_artifact_resolves_forced_entities_by_exact_and_nested_entry(self):
        for target_entry in (
            "fixture/Entity.class",
            "BOOT-INF/classes/fixture/Entity.class",
        ):
            with self.subTest(target_entry=target_entry), tempfile.TemporaryDirectory() as tmp:
                artifact = Path(tmp) / "artifact.jar"
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr("dir/", b"")
                    archive.writestr(
                        "fixture/Mapper.class",
                        b"com/baomidou/mybatisplus/core/mapper/BaseMapper",
                    )
                    archive.writestr(target_entry, b"plain-entity-bytes")
                first = SimpleNamespace(
                    records=[
                        {"frame_type": "diagnostic"},
                        {
                            "frame_type": "class_fact",
                            "class_name": "fixture/Mapper",
                            "class_entry": "fixture/Mapper.class",
                            "class_signature": (
                                "Lcom/baomidou/mybatisplus/core/mapper/"
                                "BaseMapper<Lfixture/Entity;>;"
                            ),
                            "annotations": [],
                            "fields": [],
                            "methods": [],
                        },
                    ],
                    coverage_status="complete",
                )
                second = SimpleNamespace(
                    records=[
                        {"frame_type": "diagnostic"},
                        {
                            "frame_type": "class_fact",
                            "class_name": "fixture/Entity",
                            "class_entry": target_entry,
                            "annotations": [],
                            "fields": [{"name": "value"}],
                            "methods": [],
                        },
                        {
                            "frame_type": "class_fact",
                            "class_name": "",
                            "annotations": [],
                            "fields": [],
                            "methods": [],
                        },
                    ],
                    coverage_status="partial",
                )
                with mock.patch.object(
                    scan, "extract_class_facts", side_effect=[first, second]
                ):
                    result = scan_artifact("g:a", "1", "base", artifact)
                self.assertIn("mybatis_plus_entity_fact_coverage:partial", result.gaps)
                self.assertTrue(any(fact.member == "value" for fact in result.facts.values()))

    def test_scan_artifact_forced_entity_resolution_gaps_are_explicit(self):
        cases = (
            ([], 0, None),
            (
                ["fixture/Entity.class", "nested/fixture/Entity.class"],
                2,
                None,
            ),
            (["fixture/Entity.class"], 1, "oversized"),
            (["fixture/Entity.class"], 1, "failure"),
        )
        for entries, count, mode in cases:
            with self.subTest(entries=entries, mode=mode), tempfile.TemporaryDirectory() as tmp:
                artifact = Path(tmp) / "artifact.jar"
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr(
                        "fixture/Mapper.class",
                        b"com/baomidou/mybatisplus/core/mapper/BaseMapper",
                    )
                    for entry in entries:
                        archive.writestr(entry, b"x" * (128 if mode == "oversized" else 8))
                first = SimpleNamespace(
                    records=[
                        {
                            "frame_type": "class_fact",
                            "class_name": "fixture/Mapper",
                            "class_entry": "",
                            "class_signature": (
                                "Lcom/baomidou/mybatisplus/core/mapper/"
                                "BaseMapper<Lfixture/Entity;>;"
                            ),
                            "annotations": [],
                            "fields": [],
                            "methods": [],
                        }
                    ],
                    coverage_status="complete",
                )
                side_effect = [first]
                if mode == "failure":
                    side_effect.append(BinaryAsmError("FIXTURE", "failure"))
                with mock.patch.object(
                    scan,
                    "MAX_CLASS_BYTES",
                    64 if mode == "oversized" else scan.MAX_CLASS_BYTES,
                ), mock.patch.object(
                    scan, "extract_class_facts", side_effect=side_effect
                ):
                    result = scan_artifact("g:a", "1", "base", artifact)
                if mode == "oversized":
                    self.assertIn("class_size_limit_exceeded:fixture/Entity.class", result.gaps)
                elif mode == "failure":
                    self.assertIn(
                        "mybatis_plus_entity_extraction_failed:BinaryAsmError",
                        result.gaps,
                    )
                else:
                    self.assertIn(
                        f"mybatis_plus_entity_resolution:fixture/Entity:{count}",
                        result.gaps,
                    )

    def test_scan_artifact_class_extraction_failure_and_coverage_are_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "class.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("Entity.class", b"Ljakarta/persistence/Entity;")
            for failure in (
                BinaryAsmError("FIXTURE", "fixture"),
                OSError("fixture"),
                RuntimeError("fixture"),
            ):
                with self.subTest(failure=type(failure).__name__), mock.patch.object(
                    scan, "extract_class_facts", side_effect=failure
                ):
                    result = scan_artifact("g:a", "1", "base", artifact)
                    self.assertEqual(
                        result.gaps,
                        [f"class_fact_extraction_failed:{type(failure).__name__}"],
                    )
            with mock.patch.object(
                scan,
                "extract_class_facts",
                return_value=SimpleNamespace(
                    records=[
                        {"frame_type": "diagnostic"},
                        {
                            "frame_type": "class_fact",
                            "class_name": "fixture/Entity",
                            "class_entry": "Entity.class",
                            "annotations": [_annotation("Ljakarta/persistence/Entity;")],
                            "fields": [],
                            "methods": [],
                        },
                    ],
                    coverage_status="partial",
                ),
            ):
                result = scan_artifact("g:a", "1", "base", artifact)
            self.assertIn("class_fact_coverage:partial", result.gaps)
            self.assertTrue(result.facts)

            with mock.patch.object(
                scan,
                "extract_class_facts",
                return_value=SimpleNamespace(
                    records=[{"frame_type": "diagnostic"}],
                    coverage_status="complete",
                ),
            ):
                empty = scan_artifact("g:a", "1", "base", artifact)
            self.assertEqual(empty.facts, {})

    def test_scan_database_contracts_handles_invalid_manifests_closure_and_sorting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence" / "dependencies"
            evidence.mkdir(parents=True)
            output = root / "output"
            for raw in ("{", "[]", "null", '{"schema":"future"}'):
                (evidence / "dependency_jars.json").write_text(raw, encoding="utf-8")
                summary = scan_database_contracts(root, output / hashlib.sha256(raw.encode()).hexdigest())
                self.assertEqual(summary["coverage_status"], "insufficient")

            manifest = {
                "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
                "items": [],
                "business_artifacts": [],
                "runtime_closure": {
                    "base": {"coverage_status": "partial"},
                    "current": {},
                },
            }
            (evidence / "dependency_jars.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            summary = scan_database_contracts(root, output / "closure")
            self.assertEqual(summary["coverage_status"], "partial")
            self.assertEqual(
                summary["coverage_gaps"],
                ["runtime_closure_incomplete:base", "runtime_closure_incomplete:current"],
            )

    def test_scan_database_fast_path_boolean_boundaries_and_hash_fallbacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence" / "dependencies"
            evidence.mkdir(parents=True)
            base = root / "base.jar"
            current = root / "current.jar"
            base.write_bytes(b"same")
            current.write_bytes(b"same")
            digest = hashlib.sha256(b"same").hexdigest()

            def run(items, *, runtime_closure=None, sha_side_effect=None):
                manifest = {
                    "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
                    "items": items,
                    "business_artifacts": [],
                }
                if runtime_closure is not None:
                    manifest["runtime_closure"] = runtime_closure
                (evidence / "dependency_jars.json").write_text(
                    json.dumps(manifest), encoding="utf-8"
                )
                patches = [
                    mock.patch.object(scan, "_scan_side_rows", return_value=None),
                    mock.patch.object(scan, "_write_outputs"),
                ]
                if sha_side_effect is not None:
                    patches.append(
                        mock.patch.object(
                            scan, "_sha256_path", side_effect=sha_side_effect
                        )
                    )
                entered = [patcher.start() for patcher in patches]
                try:
                    return scan_database_contracts(root, root / "output"), entered
                finally:
                    for patcher in reversed(patches):
                        patcher.stop()

            closure = {
                side: {"coverage_status": "complete"}
                for side in ("base", "current")
            }
            one_side = [
                {
                    "side": "base",
                    "coord": "g:a",
                    "retained_path": str(base),
                    "nested_jar_sha256": digest,
                }
            ]
            run(one_side, runtime_closure=closure)

            pair = [
                {
                    "side": side,
                    "coord": "g:a",
                    "retained_path": str(path),
                    "sha256": value,
                }
                for side, path, value in (
                    ("base", base, digest),
                    ("current", current, "0" * 64),
                )
            ]
            run(pair, runtime_closure=closure)

            invalid = copy.deepcopy(pair)
            invalid[0]["sha256"] = "invalid"
            invalid[1]["sha256"] = "invalid"
            run(invalid, runtime_closure=closure)

            empty_paths = copy.deepcopy(pair)
            for row in empty_paths:
                row["sha256"] = digest
                row["retained_path"] = ""
            run(empty_paths, runtime_closure=closure)

            second_missing = copy.deepcopy(empty_paths)
            second_missing[0]["retained_path"] = str(base)
            run(second_missing, runtime_closure=closure)

            mismatched_base = copy.deepcopy(pair)
            for row in mismatched_base:
                row["sha256"] = "1" * 64
            run(mismatched_base, runtime_closure=closure)

            current.write_bytes(b"different")
            mismatched_current = copy.deepcopy(pair)
            for row in mismatched_current:
                row["sha256"] = digest
            run(mismatched_current, runtime_closure=closure)
            current.write_bytes(b"same")

            _, entered = run(pair := [
                {
                    "side": side,
                    "coord": "g:a",
                    "retained_path": str(path),
                    "sha256": digest,
                }
                for side, path in (("base", base), ("current", current))
            ], runtime_closure=closure)
            self.assertEqual(entered[0].call_count, 0)

            _, entered = run(
                pair,
                runtime_closure=closure,
                sha_side_effect=OSError("unreadable"),
            )
            self.assertGreater(entered[0].call_count, 0)

            summary, _ = run([], runtime_closure=None)
            self.assertEqual(summary["coverage_status"], "partial")

    def test_scan_database_sort_places_removed_contracts_after_other_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence" / "dependencies"
            evidence.mkdir(parents=True)
            manifest = {
                "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
                "items": [
                    {"side": "base", "coord": "g:a"},
                    {"side": "current", "coord": "g:a"},
                ],
                "business_artifacts": [],
                "runtime_closure": {
                    side: {"coverage_status": "complete"}
                    for side in ("base", "current")
                },
            }
            (evidence / "dependency_jars.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            rows = []
            for change_type, location in (
                ("移除旧契约", "z"),
                ("新增当前契约", "b"),
                ("修改契约", "a"),
            ):
                row = {field: "" for field in scan.CSV_FIELDS}
                row.update(
                    {
                        "依赖包": "g:a",
                        "变化类型": change_type,
                        "契约位置": location,
                        "语句或字段": "member",
                        "契约类型": "kind",
                        "可信度": "确认",
                    }
                )
                rows.append(row)
            captured = {}

            def capture(_output, sorted_rows, _summary):
                captured["rows"] = list(sorted_rows)

            with mock.patch.object(scan, "_scan_side_rows", return_value=None), mock.patch.object(
                scan, "compare_artifact_facts", return_value=rows
            ), mock.patch.object(scan, "_write_outputs", side_effect=capture):
                summary = scan_database_contracts(root, root / "output")
            self.assertEqual(
                [row["变化类型"] for row in captured["rows"]],
                ["修改契约", "新增当前契约", "移除旧契约"],
            )
            self.assertEqual(summary["confirmed_count"], 3)

    def test_main_forwards_empty_and_explicit_jdk_arguments(self):
        for jdk_argument, expected in (("", None), ("/jdk", "/jdk")):
            with self.subTest(jdk=jdk_argument), mock.patch.object(
                sys,
                "argv",
                [
                    "database_contract_scan.py",
                    "--report-dir",
                    "/report",
                    "--output-dir",
                    "/output",
                    "--jdk-home",
                    jdk_argument,
                ],
            ), mock.patch.object(
                scan,
                "scan_database_contracts",
                return_value={"coverage_status": "complete"},
            ) as called, mock.patch("builtins.print"):
                scan.main()
            self.assertEqual(called.call_args.kwargs["jdk_home"], expected)


if __name__ == "__main__":
    unittest.main()
