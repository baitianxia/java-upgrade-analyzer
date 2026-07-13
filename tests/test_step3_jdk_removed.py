import sys
import tempfile
from pathlib import Path
import unittest


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s3_scan as step3  # noqa: E402


class Step3JdkRemovedTest(unittest.TestCase):
    def test_thread_parameter_declaration_may_span_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "Worker.java"
            source.write_text(
                "class Worker { void halt(java.lang.Thread\n worker) { worker.stop(); } }\n",
                encoding="utf-8",
            )

            rows = step3.scan_thread_lifecycle_calls(tmp)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["置信度"], "CONFIRMED")

    def test_class_usage_matches_dollar_prefixed_and_inner_class_names(self):
        self.assertEqual(
            step3._class_usage_match_kind("Demo.java", "new $Proxy();", "com.acme.$Proxy", "$Proxy")[0],
            "class_reference",
        )
        self.assertEqual(
            step3._class_usage_match_kind("Demo.java", "Map.Entry.class", "java.util.Map$Entry", "Map$Entry")[0],
            "class_literal",
        )

    def test_scan_thread_lifecycle_calls_ignores_non_thread_stop_method(self):
        with tempfile.TemporaryDirectory() as tmp:
            java_file = Path(tmp) / "CallMonitoringAspect.java"
            java_file.write_text(
                """
                package demo;

                import org.springframework.util.StopWatch;

                class CallMonitoringAspect {
                    void invoke() {
                        StopWatch sw = new StopWatch();
                        sw.stop();
                    }
                }
                """,
                encoding="utf-8",
            )

            rows = step3.scan_thread_lifecycle_calls(tmp)

        self.assertEqual(rows, [])

    def test_scan_thread_lifecycle_calls_keeps_declared_thread_receiver(self):
        with tempfile.TemporaryDirectory() as tmp:
            java_file = Path(tmp) / "ThreadUsage.java"
            java_file.write_text(
                """
                package demo;

                class ThreadUsage {
                    void stopIt(Thread worker) {
                        worker.stop();
                    }
                }
                """,
                encoding="utf-8",
            )

            rows = step3.scan_thread_lifecycle_calls(tmp)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["API"], "java.lang.Thread.stop")
        self.assertEqual(rows[0]["置信度"], "CONFIRMED")


if __name__ == "__main__":
    unittest.main()
