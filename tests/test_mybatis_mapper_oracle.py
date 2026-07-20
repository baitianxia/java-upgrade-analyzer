import hashlib
import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import mybatis_mapper_oracle as oracle  # noqa: E402


MAPPER_JAVAP = """\
public interface sample.mybatis.xml.mapper.HotelMapper
  minor version: 0
  major version: 61
{
  public abstract sample.mybatis.xml.domain.Hotel selectByCityId(int);
    descriptor: (I)Lsample/mybatis/xml/domain/Hotel;
    RuntimeVisibleAnnotations:
      0: #10()
        org.apache.ibatis.annotations.Select(
          value=[\"select city from hotel where city = #{id}\"]
        )
}
RuntimeVisibleAnnotations:
  0: #17()
    org.apache.ibatis.annotations.Mapper
"""

XML_MAPPER_JAVAP = """\
public interface sample.mybatis.xml.mapper.HotelMapper
  minor version: 0
  major version: 61
{
  public abstract sample.mybatis.xml.domain.Hotel selectByCityId(int);
    descriptor: (I)Lsample/mybatis/xml/domain/Hotel;
}
RuntimeVisibleAnnotations:
  0: #17()
    org.apache.ibatis.annotations.Mapper
"""

UNREGISTERED_XML_MAPPER_JAVAP = """\
public interface sample.mybatis.xml.mapper.HotelMapper
{
  public abstract sample.mybatis.xml.domain.Hotel selectByCityId(int);
    descriptor: (I)Lsample/mybatis/xml/domain/Hotel;
}
"""


def nested_jar_bytes(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def write_fake_fat_jar(
    path,
    *,
    mapper_xml=(
        b"<mapper namespace=\"sample.mybatis.xml.mapper.HotelMapper\">"
        b"<select id=\"selectByCityId\" resultType=\"Hotel\">select 1</select>"
        b"</mapper>"
    ),
):
    framework = nested_jar_bytes({
        "org/apache/ibatis/binding/MapperProxy.class": b"proxy",
        "org/apache/ibatis/binding/MapperProxy$PlainMethodInvoker.class": b"invoker",
        "org/apache/ibatis/binding/MapperMethod.class": b"method",
    })
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "BOOT-INF/classes/sample/mybatis/xml/mapper/HotelMapper.class",
            b"Lorg/apache/ibatis/annotations/Mapper;selectByCityId",
        )
        archive.writestr(
            "BOOT-INF/classes/mybatis-config.xml",
            b"""<configuration><mappers><mapper resource=\"sample/mybatis/xml/mapper/HotelMapper.xml\"/></mappers></configuration>""",
        )
        if mapper_xml is not None:
            archive.writestr(
                "BOOT-INF/classes/sample/mybatis/xml/mapper/HotelMapper.xml",
                mapper_xml,
            )
        archive.writestr("BOOT-INF/lib/mybatis-3.5.19.jar", framework)


def complete_scan_edges():
    return [
        {
            "caller_owner": "sample.mybatis.xml.SampleXmlApplication",
            "caller_member": "run",
            "caller_descriptor": "([Ljava/lang/String;)V",
            "callee_owner": "sample.mybatis.xml.mapper.HotelMapper",
            "callee_member": "selectByCityId",
            "callee_descriptor": "(I)Lsample/mybatis/xml/domain/Hotel;",
            "opcode_family": "invokeinterface",
        },
        {
            "caller_owner": "org.apache.ibatis.binding.MapperProxy",
            "caller_member": "invoke",
            "caller_descriptor": "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;",
            "callee_owner": "org.apache.ibatis.binding.MapperProxy$MapperMethodInvoker",
            "callee_member": "invoke",
            "callee_descriptor": "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;Lorg/apache/ibatis/session/SqlSession;)Ljava/lang/Object;",
            "opcode_family": "invokeinterface",
        },
        {
            "caller_owner": "org.apache.ibatis.binding.MapperProxy$PlainMethodInvoker",
            "caller_member": "invoke",
            "caller_descriptor": "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;Lorg/apache/ibatis/session/SqlSession;)Ljava/lang/Object;",
            "callee_owner": "org.apache.ibatis.binding.MapperMethod",
            "callee_member": "execute",
            "callee_descriptor": "(Lorg/apache/ibatis/session/SqlSession;[Ljava/lang/Object;)Ljava/lang/Object;",
            "opcode_family": "invokevirtual",
        },
        {
            "caller_owner": "org.apache.ibatis.binding.MapperMethod",
            "caller_member": "execute",
            "caller_descriptor": "(Lorg/apache/ibatis/session/SqlSession;[Ljava/lang/Object;)Ljava/lang/Object;",
            "callee_owner": "org.apache.ibatis.session.SqlSession",
            "callee_member": "selectOne",
            "callee_descriptor": "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;",
            "opcode_family": "invokeinterface",
        },
    ]


def complete_scan_result(edges=None):
    return {
        "complete": True,
        "failures": [],
        "edges": complete_scan_edges() if edges is None else edges,
        "class_count": 4,
        "inventory_class_count": 20,
        "parsed_class_count": 4,
    }


class MybatisMapperOracleTest(unittest.TestCase):
    @patch("mybatis_mapper_oracle.scan_final_artifact")
    @patch("mybatis_mapper_oracle._run_javap", return_value=XML_MAPPER_JAVAP)
    def test_mapper_evidence_records_bind_to_raw_final_artifact_sha(
        self, _run_javap, scan_final_artifact
    ):
        scan_final_artifact.return_value = complete_scan_result()
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "sample.jar"
            write_fake_fat_jar(artifact)
            expected_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()

            result = oracle.inspect_mybatis_artifact(
                artifact, timeout_seconds=5.0
            )

        evidence_records = [
            *result["mapper_contracts"],
            *result["statement_bindings"],
        ]
        self.assertTrue(evidence_records)
        self.assertEqual(
            {item.get("artifact_sha256") for item in evidence_records},
            {expected_sha256},
        )

    @patch("mybatis_mapper_oracle.subprocess.run")
    def test_runtime_activation_refuses_empty_review_expectation(self, run):
        result = oracle.verify_runtime_activation(Path("sample.jar"), [])

        self.assertFalse(result["active"])
        self.assertEqual(
            result["failures"], ["MYBATIS_RUNTIME_EXPECTATION_MISSING"]
        )
        run.assert_not_called()

    @patch("mybatis_mapper_oracle.subprocess.run")
    def test_runtime_activation_requires_exit_zero_and_every_expected_output(
        self, run
    ):
        run.return_value = subprocess.CompletedProcess(
            ["java", "-jar", "sample.jar"],
            0,
            stdout="CityMapper.findByState\n1,San Francisco,CA,US\n",
            stderr="",
        )

        result = oracle.verify_runtime_activation(
            Path("sample.jar"),
            ["CityMapper.findByState", "1,San Francisco,CA,US"],
            timeout_seconds=5.0,
        )

        self.assertTrue(result["active"])
        self.assertEqual(result["failures"], [])
        self.assertRegex(result["output_sha256"], r"^[0-9a-f]{64}$")
        run.assert_called_once_with(
            ["java", "-jar", "sample.jar"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5.0,
            check=False,
        )

    def test_parse_mapper_javap_reads_exact_contract_and_annotations(self):
        parsed = oracle.parse_mapper_javap(
            MAPPER_JAVAP,
            "BOOT-INF/classes/sample/mybatis/xml/mapper/HotelMapper.class",
        )

        self.assertEqual(parsed["owner"], "sample.mybatis.xml.mapper.HotelMapper")
        self.assertTrue(parsed["mapper_registered"])
        self.assertEqual(parsed["methods"], [{
            "owner": "sample.mybatis.xml.mapper.HotelMapper",
            "member": "selectByCityId",
            "descriptor": "(I)Lsample/mybatis/xml/domain/Hotel;",
            "annotation_bindings": ["org.apache.ibatis.annotations.Select"],
            "artifact_entry": "BOOT-INF/classes/sample/mybatis/xml/mapper/HotelMapper.class",
        }])

    def test_parse_mapper_xml_reads_namespace_and_statement_ids(self):
        parsed = oracle.parse_mapper_xml(
            b"""<mapper namespace=\"sample.Mapper\"><select id=\"find\">select 1</select><insert id=\"save\">insert</insert></mapper>""",
            "BOOT-INF/classes/sample/Mapper.xml",
        )

        self.assertEqual(parsed["namespace"], "sample.Mapper")
        self.assertEqual(parsed["statements"], ["find", "save"])
        self.assertEqual(parsed["artifact_entry"], "BOOT-INF/classes/sample/Mapper.xml")

    @patch("mybatis_mapper_oracle.scan_final_artifact")
    @patch("mybatis_mapper_oracle._run_javap")
    def test_inspect_requires_packaged_registration_binding_and_dispatch(
        self, run_javap, scan_final_artifact
    ):
        run_javap.return_value = XML_MAPPER_JAVAP
        scan_final_artifact.return_value = complete_scan_result()
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "sample.jar"
            write_fake_fat_jar(artifact)

            result = oracle.inspect_mybatis_artifact(artifact, timeout_seconds=5.0)

        self.assertTrue(result["complete"])
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["mapper_contracts"], [{
            "owner": "sample.mybatis.xml.mapper.HotelMapper",
            "member": "selectByCityId",
            "descriptor": "(I)Lsample/mybatis/xml/domain/Hotel;",
            "registration": "mapper_annotation",
            "binding": "mapper_xml",
            "artifact_entry": "BOOT-INF/classes/sample/mybatis/xml/mapper/HotelMapper.class",
            "binding_entry": "BOOT-INF/classes/sample/mybatis/xml/mapper/HotelMapper.xml",
            "artifact_sha256": result["artifact_sha256"],
        }])
        self.assertEqual(len(result["proxy_dispatch_links"]), 1)
        self.assertEqual(
            result["proxy_dispatch_links"][0]["evidence_authority"],
            "final-artifact-javap-plus-mapper-registration",
        )
        self.assertEqual(
            [edge["caller_owner"] for edge in result["proxy_dispatch_links"][0]["physical_dispatch_edges"]],
            [
                "org.apache.ibatis.binding.MapperProxy",
                "org.apache.ibatis.binding.MapperProxy$PlainMethodInvoker",
                "org.apache.ibatis.binding.MapperMethod",
            ],
        )
        self.assertEqual(result["metrics"]["mapper_classes"], 1)
        self.assertEqual(result["metrics"]["mapper_resources"], 1)

    @patch("mybatis_mapper_oracle.scan_final_artifact")
    @patch("mybatis_mapper_oracle._run_javap", return_value=XML_MAPPER_JAVAP)
    def test_inspect_requires_select_one_physical_dispatch_for_scalar_select(
        self, _run_javap, scan_final_artifact
    ):
        scan_final_artifact.return_value = complete_scan_result(
            complete_scan_edges()[:-1]
        )
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "sample.jar"
            write_fake_fat_jar(artifact)

            result = oracle.inspect_mybatis_artifact(artifact, timeout_seconds=5.0)

        self.assertFalse(result["complete"])
        self.assertIn("MYBATIS_SELECT_ONE_DISPATCH_MISSING", result["failures"])

    @patch("mybatis_mapper_oracle.scan_final_artifact")
    @patch("mybatis_mapper_oracle._run_javap", return_value=XML_MAPPER_JAVAP)
    def test_precomputed_physical_scan_prevents_duplicate_artifact_scan(
        self, _run_javap, scan_final_artifact
    ):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "sample.jar"
            write_fake_fat_jar(artifact)

            result = oracle.inspect_mybatis_artifact(
                artifact,
                timeout_seconds=5.0,
                physical_scan=complete_scan_result(),
            )

        self.assertTrue(result["complete"])
        scan_final_artifact.assert_not_called()
        self.assertEqual(result["metrics"]["duplicate_artifact_scans"], 0)

    @patch("mybatis_mapper_oracle.scan_final_artifact", return_value=complete_scan_result([]))
    @patch("mybatis_mapper_oracle._run_javap", return_value=XML_MAPPER_JAVAP)
    def test_missing_declared_mapper_resource_marks_oracle_incomplete(
        self, _run_javap, _scan_final_artifact
    ):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "sample.jar"
            write_fake_fat_jar(artifact, mapper_xml=None)

            result = oracle.inspect_mybatis_artifact(artifact, timeout_seconds=5.0)

        self.assertFalse(result["complete"])
        self.assertIn(
            "MAPPER_RESOURCE_MISSING:sample/mybatis/xml/mapper/HotelMapper.xml",
            result["failures"],
        )

    @patch("mybatis_mapper_oracle.scan_final_artifact", return_value=complete_scan_result())
    @patch("mybatis_mapper_oracle._run_javap", return_value=XML_MAPPER_JAVAP)
    def test_namespace_mismatch_is_not_reduced_to_a_static_miss(
        self, _run_javap, _scan_final_artifact
    ):
        mismatched = (
            b"<mapper namespace=\"sample.mybatis.xml.mapper.OtherMapper\">"
            b"<select id=\"selectByCityId\">select 1</select></mapper>"
        )
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "sample.jar"
            write_fake_fat_jar(artifact, mapper_xml=mismatched)

            result = oracle.inspect_mybatis_artifact(artifact, timeout_seconds=5.0)

        self.assertFalse(result["complete"])
        self.assertIn(
            "MAPPER_NAMESPACE_MISMATCH:sample.mybatis.xml.mapper.HotelMapper:sample.mybatis.xml.mapper.OtherMapper",
            result["failures"],
        )

    @patch("mybatis_mapper_oracle.scan_final_artifact", return_value=complete_scan_result())
    @patch("mybatis_mapper_oracle._run_javap", return_value=XML_MAPPER_JAVAP)
    def test_statement_id_mismatch_marks_invoked_mapper_unresolved(
        self, _run_javap, _scan_final_artifact
    ):
        changed = (
            b"<mapper namespace=\"sample.mybatis.xml.mapper.HotelMapper\">"
            b"<select id=\"renamed\">select 1</select></mapper>"
        )
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "sample.jar"
            write_fake_fat_jar(artifact, mapper_xml=changed)

            result = oracle.inspect_mybatis_artifact(artifact, timeout_seconds=5.0)

        self.assertFalse(result["complete"])
        self.assertIn(
            "MAPPER_STATEMENT_UNRESOLVED:sample.mybatis.xml.mapper.HotelMapper.selectByCityId",
            result["failures"],
        )

    @patch("mybatis_mapper_oracle.scan_final_artifact")
    @patch("mybatis_mapper_oracle._run_javap", return_value=XML_MAPPER_JAVAP)
    def test_missing_proxy_entry_edge_blocks_semantic_dispatch(
        self, _run_javap, scan_final_artifact
    ):
        scan_final_artifact.return_value = complete_scan_result(
            [edge for edge in complete_scan_edges() if edge["caller_owner"] != "org.apache.ibatis.binding.MapperProxy"]
        )
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "sample.jar"
            write_fake_fat_jar(artifact)

            result = oracle.inspect_mybatis_artifact(artifact, timeout_seconds=5.0)

        self.assertFalse(result["complete"])
        self.assertIn("MYBATIS_PROXY_ENTRY_DISPATCH_MISSING", result["failures"])
        self.assertEqual(result["proxy_dispatch_links"], [])

    @patch("mybatis_mapper_oracle.scan_final_artifact", return_value=complete_scan_result())
    @patch(
        "mybatis_mapper_oracle._run_javap",
        return_value=UNREGISTERED_XML_MAPPER_JAVAP,
    )
    def test_missing_mapper_registration_blocks_proxy_conclusion(
        self, _run_javap, _scan_final_artifact
    ):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "sample.jar"
            write_fake_fat_jar(artifact)

            result = oracle.inspect_mybatis_artifact(artifact, timeout_seconds=5.0)

        self.assertFalse(result["complete"])
        self.assertIn(
            "MAPPER_REGISTRATION_MISSING:sample.mybatis.xml.mapper.HotelMapper",
            result["failures"],
        )
        self.assertEqual(result["proxy_dispatch_links"], [])

    @patch("mybatis_mapper_oracle.scan_final_artifact", return_value=complete_scan_result([]))
    @patch("mybatis_mapper_oracle._run_javap")
    def test_javap_timeout_is_reported_as_incomplete(self, run_javap, _scan_final_artifact):
        run_javap.side_effect = subprocess.TimeoutExpired(["javap"], timeout=0.1)
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "sample.jar"
            write_fake_fat_jar(artifact)

            result = oracle.inspect_mybatis_artifact(artifact, timeout_seconds=0.1)

        self.assertFalse(result["complete"])
        self.assertTrue(any(item.startswith("ORACLE_TIMEOUT:") for item in result["failures"]))


if __name__ == "__main__":
    unittest.main()
