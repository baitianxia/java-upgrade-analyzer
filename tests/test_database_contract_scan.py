import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import database_contract_scan  # noqa: E402
from database_contract_scan import (  # noqa: E402
    ArtifactFacts,
    CSV_NAME,
    REVIEW_NAME,
    SUMMARY_NAME,
    compare_artifact_facts,
    facts_from_class_record,
    facts_from_mapper_xml,
    facts_from_orm_xml,
    scan_database_contracts,
    scan_artifact,
)


def annotation(descriptor, **values):
    return {
        "descriptor": descriptor,
        "visible": True,
        "values": [[name, value] for name, value in values.items()],
    }


class DatabaseContractScanTest(unittest.TestCase):
    def test_artifact_parser_uses_the_step0_selected_jdk_not_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "contract.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr(
                    "demo/Entity.class",
                    b"fixture-Ljakarta/persistence/Entity;-bytes",
                )
            with patch.object(
                database_contract_scan,
                "extract_class_facts",
                return_value=SimpleNamespace(
                    records=(), coverage_status="complete",
                ),
            ) as extract:
                scan_artifact(
                    "com.acme:data",
                    "1",
                    "current",
                    jar_path,
                    jdk_home="/selected/jdk",
                )

        self.assertEqual(extract.call_args.kwargs["jdk_home"], "/selected/jdk")

    def _write_jar(self, path, mapper_xml):
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("mapper/OrderMapper.xml", mapper_xml)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_compares_two_sided_mapper_contract_and_keeps_dependency_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dependencies = root / "evidence" / "dependencies"
            output = root / "evidence" / "static_scan"
            base_jar = dependencies / "base.jar"
            current_jar = dependencies / "current.jar"
            base_sha = self._write_jar(
                base_jar,
                """<mapper namespace="com.acme.OrderMapper">
                <select id="find">select id from orders where tenant_id = #{tenantId}</select>
                </mapper>""",
            )
            current_sha = self._write_jar(
                current_jar,
                """<mapper namespace="com.acme.OrderMapper">
                <select id="find">select id, new_column from orders where tenant_id = #{tenantId}</select>
                </mapper>""",
            )
            dependencies.mkdir(parents=True, exist_ok=True)
            manifest = {
                "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
                "items": [
                    {
                        "side": "base", "coord": "com.acme:data-access", "version": "1.0",
                        "retained_path": str(base_jar), "nested_jar_sha256": base_sha,
                        "purposes": ["binary_runtime"],
                    },
                    {
                        "side": "current", "coord": "com.acme:data-access", "version": "2.0",
                        "retained_path": str(current_jar), "nested_jar_sha256": current_sha,
                        "purposes": ["binary_runtime"],
                    },
                ],
                "business_artifacts": [],
                "runtime_closure": {
                    "base": {"coverage_status": "complete"},
                    "current": {"coverage_status": "complete"},
                },
            }
            (dependencies / "dependency_jars.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )

            summary = scan_database_contracts(root, output)

            self.assertEqual(summary["coverage_status"], "complete")
            self.assertEqual(summary["change_count"], 1)
            csv_text = (output / CSV_NAME).read_text(encoding="utf-8-sig")
            self.assertIn("com.acme:data-access", csv_text)
            self.assertIn("new_column", csv_text)
            self.assertIn("orders", csv_text)
            review = (output / REVIEW_NAME).read_text(encoding="utf-8")
            self.assertIn("不扫描 DDL/迁移文件", review)

    def test_orm_entity_field_is_contract_but_plain_dto_field_is_not(self):
        base_record = {
            "class_name": "com/acme/OrderEntity",
            "annotations": [
                annotation("Ljakarta/persistence/Entity;"),
                annotation("Ljakarta/persistence/Table;", name="orders"),
            ],
            "methods": [],
            "fields": [
                {
                    "name": "id", "descriptor": "J", "access": 2,
                    "annotations": [
                        annotation("Ljakarta/persistence/Id;"),
                        annotation("Ljakarta/persistence/Column;", name="id"),
                    ],
                }
            ],
        }
        current_record = json.loads(json.dumps(base_record))
        current_record["fields"].append({
            "name": "newCode", "descriptor": "Ljava/lang/String;", "access": 2,
            "annotations": [annotation("Ljakarta/persistence/Column;", name="new_code")],
        })
        base = ArtifactFacts("com.acme:model", "1", "base", Path("base.jar"))
        current = ArtifactFacts("com.acme:model", "2", "current", Path("current.jar"))
        base.facts = {fact.key: fact for fact in facts_from_class_record(base_record, "OrderEntity.class")}
        current.facts = {fact.key: fact for fact in facts_from_class_record(current_record, "OrderEntity.class")}

        rows = compare_artifact_facts(base, current)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["列"], "new_code")
        self.assertEqual(rows[0]["可信度"], "确认")

        dto = {
            "class_name": "com/acme/OrderDto",
            "annotations": [],
            "methods": [],
            "fields": [{"name": "newCode", "descriptor": "Ljava/lang/String;", "access": 2}],
        }
        self.assertEqual(facts_from_class_record(dto, "OrderDto.class"), [])

    def test_mybatis_annotation_sql_is_included(self):
        record = {
            "class_name": "com/acme/OrderMapper",
            "annotations": [],
            "fields": [],
            "methods": [{
                "contract": {
                    "name": "find", "descriptor": "(J)Lcom/acme/Order;",
                    "annotations": [annotation(
                        "Lorg/apache/ibatis/annotations/Select;",
                        value=["select id, state from orders where id = #{id}"],
                    )],
                }
            }],
        }

        facts = facts_from_class_record(record, "OrderMapper.class")

        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].tables, ("orders",))
        self.assertIn("state", facts[0].columns)
        self.assertEqual(facts[0].confidence, "确认")

    def test_dynamic_mapper_result_is_not_overstated(self):
        facts = facts_from_mapper_xml(
            b"""<mapper namespace="sample.Mapper"><select id="find">
            select * from ${tableName} where id = #{id}
            </select></mapper>""",
            "sample.xml",
        )

        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].confidence, "需复核")

    def test_sql_value_change_without_table_or_column_change_is_not_schema_contract_change(self):
        base_fact = facts_from_mapper_xml(
            b'<mapper namespace="sample.Mapper"><select id="find">'
            b"select id from orders where state = 'OPEN'"
            b'</select></mapper>',
            "sample.xml",
        )[0]
        current_fact = facts_from_mapper_xml(
            b'<mapper namespace="sample.Mapper"><select id="find">'
            b"select id from orders where state = 'READY'"
            b'</select></mapper>',
            "sample.xml",
        )[0]
        base = ArtifactFacts("com.acme:data", "1", "base", Path("base.jar"))
        current = ArtifactFacts("com.acme:data", "2", "current", Path("current.jar"))
        base.facts = {base_fact.key: base_fact}
        current.facts = {current_fact.key: current_fact}

        self.assertEqual(compare_artifact_facts(base, current), [])

    def test_mybatis_sql_fragment_column_change_is_visible_but_requires_review(self):
        facts = facts_from_mapper_xml(
            b'<mapper namespace="sample.Mapper">'
            b'<sql id="columns">id, new_column</sql>'
            b'<select id="find">select <include refid="columns"/> from orders</select>'
            b'</mapper>',
            "sample.xml",
        )

        fragment = next(fact for fact in facts if fact.kind == "MyBatis SQL 片段")
        statement = next(fact for fact in facts if fact.kind == "MyBatis XML SELECT")
        self.assertEqual(fragment.columns, ("id", "new_column"))
        self.assertEqual(fragment.confidence, "需复核")
        self.assertEqual(statement.confidence, "需复核")

    def test_jpa_and_hibernate_xml_mappings_are_database_contracts(self):
        jpa = facts_from_orm_xml(
            b'''<entity-mappings xmlns="https://jakarta.ee/xml/ns/persistence/orm">
              <entity class="com.acme.Order"><table name="orders"/><attributes>
                <basic name="newCode"><column name="new_code"/></basic>
              </attributes></entity></entity-mappings>''',
            "META-INF/orm.xml",
        )
        hibernate = facts_from_orm_xml(
            b'''<hibernate-mapping><class name="com.acme.Order" table="orders">
              <property name="newCode" column="new_code"/>
            </class></hibernate-mapping>''',
            "Order.hbm.xml",
        )

        self.assertTrue(any(fact.columns == ("new_code",) for fact in jpa))
        self.assertTrue(any(fact.columns == ("new_code",) for fact in hibernate))
        self.assertTrue(all(fact.confidence == "确认" for fact in jpa + hibernate))

    def test_jpa_property_access_does_not_treat_backing_fields_as_persistent_contract(self):
        record = {
            "class_name": "com/acme/OrderEntity",
            "annotations": [
                annotation("Ljakarta/persistence/Entity;"),
                annotation("Ljakarta/persistence/Table;", name="orders"),
            ],
            "fields": [{"name": "internalCache", "descriptor": "Ljava/lang/String;", "access": 2}],
            "methods": [{
                "contract": {
                    "name": "getId", "descriptor": "()J", "access": 1,
                    "annotations": [
                        annotation("Ljakarta/persistence/Id;"),
                        annotation("Ljakarta/persistence/Column;", name="id"),
                    ],
                }
            }, {
                "contract": {
                    "name": "getNewCode", "descriptor": "()Ljava/lang/String;", "access": 1,
                    "annotations": [annotation("Ljakarta/persistence/Column;", name="new_code")],
                }
            }],
        }

        facts = facts_from_class_record(record, "OrderEntity.class")

        self.assertFalse(any(fact.member == "internalCache" for fact in facts))
        self.assertTrue(any(fact.member == "newCode" and fact.columns == ("new_code",) for fact in facts))

    def test_generated_style_mybatis_plus_dto_keeps_persistent_field_contract(self):
        record = {
            "class_name": "com/acme/generated/OrderDto",
            "annotations": [
                annotation(
                    "Lcom/baomidou/mybatisplus/annotation/TableName;",
                    value="orders",
                )
            ],
            "methods": [],
            "fields": [{
                "name": "newCode", "descriptor": "Ljava/lang/String;", "access": 2,
                "annotations": [annotation(
                    "Lcom/baomidou/mybatisplus/annotation/TableField;",
                    value="new_code",
                )],
            }],
        }

        facts = facts_from_class_record(record, "com/acme/generated/OrderDto.class")

        persistent = next(fact for fact in facts if fact.kind == "ORM 持久化字段")
        self.assertEqual(persistent.tables, ("orders",))
        self.assertEqual(persistent.columns, ("new_code",))
        self.assertEqual(persistent.confidence, "确认")

    def test_missing_two_sided_manifest_writes_visible_incomplete_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "evidence" / "static_scan"

            summary = scan_database_contracts(root, output)

            self.assertEqual(summary["coverage_status"], "insufficient")
            self.assertTrue(summary["coverage_gaps"])
            self.assertTrue((output / CSV_NAME).is_file())
            self.assertTrue((output / SUMMARY_NAME).is_file())
            self.assertTrue((output / REVIEW_NAME).is_file())
            self.assertNotIn(
                "本次未识别到升级前后数据访问契约变化。",
                (output / REVIEW_NAME).read_text(encoding="utf-8"),
            )

    def test_identical_manifest_hash_does_not_hide_missing_retained_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dependencies = root / "evidence" / "dependencies"
            dependencies.mkdir(parents=True)
            missing_hash = "0" * 64
            manifest = {
                "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
                "items": [
                    {
                        "side": side, "coord": "com.acme:data", "version": "1",
                        "retained_path": str(root / f"{side}.jar"),
                        "nested_jar_sha256": missing_hash,
                        "purposes": ["binary_runtime"],
                    }
                    for side in ("base", "current")
                ],
                "business_artifacts": [],
                "runtime_closure": {
                    "base": {"coverage_status": "complete"},
                    "current": {"coverage_status": "complete"},
                },
            }
            (dependencies / "dependency_jars.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )

            summary = scan_database_contracts(root, root / "evidence" / "static_scan")

            self.assertEqual(summary["coverage_status"], "partial")
            self.assertTrue(any("artifact_missing:base" in gap for gap in summary["coverage_gaps"]))
            self.assertTrue(any("artifact_missing:current" in gap for gap in summary["coverage_gaps"]))

    @unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
    def test_compiled_orm_and_mapper_annotations_are_extracted_from_jar(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = root / "src"
            classes = root / "classes"
            source_files = {
                "jakarta/persistence/Entity.java": """
                    package jakarta.persistence;
                    import java.lang.annotation.*;
                    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                    public @interface Entity {}
                """,
                "jakarta/persistence/Table.java": """
                    package jakarta.persistence;
                    import java.lang.annotation.*;
                    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                    public @interface Table { String name() default ""; }
                """,
                "jakarta/persistence/Column.java": """
                    package jakarta.persistence;
                    import java.lang.annotation.*;
                    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.FIELD)
                    public @interface Column { String name() default ""; }
                """,
                "jakarta/persistence/Id.java": """
                    package jakarta.persistence;
                    import java.lang.annotation.*;
                    @Retention(RetentionPolicy.RUNTIME) @Target({ElementType.FIELD, ElementType.METHOD})
                    public @interface Id {}
                """,
                "org/apache/ibatis/annotations/Select.java": """
                    package org.apache.ibatis.annotations;
                    import java.lang.annotation.*;
                    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                    public @interface Select { String[] value(); }
                """,
                "com/baomidou/mybatisplus/core/mapper/BaseMapper.java": """
                    package com.baomidou.mybatisplus.core.mapper;
                    public interface BaseMapper<T> {}
                """,
                "com/acme/OrderEntity.java": """
                    package com.acme;
                    @jakarta.persistence.Entity
                    @jakarta.persistence.Table(name="orders")
                    public class OrderEntity {
                        @jakarta.persistence.Id
                        @jakarta.persistence.Column(name="id")
                        private long id;
                        @jakarta.persistence.Column(name="new_code")
                        private String newCode;
                    }
                """,
                "com/acme/OrderMapper.java": """
                    package com.acme;
                    public interface OrderMapper {
                        @org.apache.ibatis.annotations.Select(
                            "select id, new_code from orders where id = #{id}")
                        OrderEntity find(long id);
                    }
                """,
                "com/acme/GeneratedOrderDto.java": """
                    package com.acme;
                    public class GeneratedOrderDto {
                        private String conventionColumn;
                    }
                """,
                "com/acme/GeneratedOrderMapper.java": """
                    package com.acme;
                    public interface GeneratedOrderMapper extends
                        com.baomidou.mybatisplus.core.mapper.BaseMapper<GeneratedOrderDto> {}
                """,
            }
            java_paths = []
            for relative, content in source_files.items():
                path = sources / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                java_paths.append(str(path))
            classes.mkdir()
            completed = subprocess.run(
                [shutil.which("javac"), "-encoding", "UTF-8", "-d", str(classes), *java_paths],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            jar_path = root / "compiled.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                for class_file in classes.rglob("*.class"):
                    archive.write(class_file, class_file.relative_to(classes).as_posix())

            facts = scan_artifact(
                "com.acme:data-access", "2.0", "current", jar_path
            )

            self.assertEqual(facts.gaps, [])
            kinds = {fact.kind for fact in facts.facts.values()}
            self.assertIn("ORM 实体表映射", kinds)
            self.assertIn("ORM 持久化字段", kinds)
            self.assertIn("MyBatis 注解 SELECT", kinds)
            self.assertTrue(any(fact.columns == ("new_code",) for fact in facts.facts.values()))
            convention_fact = next(
                fact for fact in facts.facts.values()
                if fact.location == "com.acme.GeneratedOrderDto"
                and fact.member == "conventionColumn"
            )
            self.assertEqual(convention_fact.columns, ("conventionColumn",))
            self.assertEqual(convention_fact.confidence, "需复核")

            external_entity_jar = root / "mapper-with-external-entity.jar"
            with zipfile.ZipFile(external_entity_jar, "w") as archive:
                for class_file in classes.rglob("*.class"):
                    relative = class_file.relative_to(classes).as_posix()
                    if relative == "com/acme/GeneratedOrderDto.class":
                        continue
                    archive.write(class_file, relative)
            external = scan_artifact(
                "com.acme:mapper-only", "2.0", "current", external_entity_jar
            )
            self.assertTrue(any(
                gap.startswith("mybatis_plus_entity_resolution:com/acme/GeneratedOrderDto:0")
                for gap in external.gaps
            ))


if __name__ == "__main__":
    unittest.main()
