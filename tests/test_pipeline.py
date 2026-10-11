"""端到端流水线测试：四步闭环 + 六道防线的集成行为。"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from zhigou.attestation import LocalLedgerAdapter
from zhigou.collectors import TaskParameter
from zhigou.models import AuthorityAnchor, FollowUp, Platform, Verdict, utcnow
from zhigou.pipeline import Pipeline, PipelineConfig
from zhigou.report import render_html, render_text


def make_pipeline(tmp: str) -> Pipeline:
    return Pipeline(PipelineConfig(
        collector="simulated",
        collector_kwargs={"seed": 777, "authentic_count": 40},
        ledger_path=os.path.join(tmp, "ledger.jsonl"),
    ))


TASK = TaskParameter(task_id="t-demo", product_id="X7-001")


class TestPipelineEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.pipeline = make_pipeline(self.tmp)

    def tearDown(self):
        for root, _, files in os.walk(self.tmp):
            for f in files:
                os.remove(os.path.join(root, f))
        os.rmdir(self.tmp)

    # -- 基本闭环 --------------------------------------------------

    def test_report_is_produced(self):
        r = self.pipeline.run(TASK)
        self.assertGreater(r.total_collected, 0)
        self.assertTrue(r.product.title)

    def test_all_three_pools_are_populated(self):
        """模拟语料刻意混入了四类噪声，三池都应有内容。"""
        r = self.pipeline.run(TASK)
        self.assertGreater(r.trusted, 0)
        self.assertGreater(r.doubted + r.rejected, 0)

    def test_effective_ratio_is_reported(self):
        r = self.pipeline.run(TASK)
        self.assertAlmostEqual(
            r.authenticity["effective_ratio"],
            r.trusted / r.total_collected,
            places=3,
        )

    # -- 防线一：快照 -----------------------------------------------

    def test_attestation_covers_all_snapshots(self):
        r = self.pipeline.run(TASK)
        self.assertIsNotNone(r.attestation)
        self.assertEqual(r.attestation.leaf_count, r.total_collected)

    def test_model_fingerprint_recorded(self):
        """存证必须附带模型指纹，否则「偷偷改模型改分」无法被发现。"""
        r = self.pipeline.run(TASK)
        self.assertTrue(r.attestation.model_fingerprint)

    def test_ledger_is_intact_after_run(self):
        self.pipeline.run(TASK)
        adapter = LocalLedgerAdapter(path=os.path.join(self.tmp, "ledger.jsonl"))
        self.assertTrue(adapter.audit()["ok"])

    def test_same_seed_reproduces_same_merkle_root(self):
        """复现一致性：同一证据集 + 同一模型 = 同一默克尔根。"""
        r1 = self.pipeline.run(TASK)
        r2 = self.pipeline.run(TASK)
        self.assertEqual(r1.attestation.merkle_root, r2.attestation.merkle_root)

    # -- 防线三：交叉验证 -------------------------------------------

    def test_only_corroborated_claims_reach_advice(self):
        r = self.pipeline.run(TASK)
        confirmed_ids = {id(c) for c in r.pros + r.cons if c.corroborated}
        for text in r.advice.get("suitable_for", []):
            matches = [c for c in r.pros + r.cons if c.text == text]
            self.assertTrue(matches, f"建议中出现无对应结论的项：{text}")
            self.assertIn(id(matches[0]), confirmed_ids)

    def test_single_source_claim_is_tagged_as_isolated(self):
        r = self.pipeline.run(TASK)
        isolated = [c for c in r.pros + r.cons if c.independent_source_count == 1]
        for c in isolated:
            self.assertEqual(c.tag, "孤证，待验证")

    # -- 防线五：可信度量化 -----------------------------------------

    def test_verdict_summary_is_filled(self):
        r = self.pipeline.run(TASK)
        self.assertGreater(r.summary.confidence, 0.0)
        self.assertIn(r.summary.level, ("高", "中", "低", "信息有限"))

    def test_tiny_sample_degrades_to_insufficient(self):
        """样本不足时必须主动降级，而不是硬给一个高分。"""
        p = Pipeline(PipelineConfig(
            collector="simulated",
            collector_kwargs={"seed": 1, "authentic_count": 1},
            ledger_path=os.path.join(self.tmp, "l2.jsonl"),
        ))
        r = p.run(TASK)
        self.assertEqual(r.summary.level, "信息有限")
        self.assertIn("样本不足", r.summary.reason)

    # -- 防线六：回访与监控 -----------------------------------------

    def test_followup_disputes_downweight_claims(self):
        before = self.pipeline.run(TASK)
        target = before.pros[0].text if before.pros else "续航"
        after = self.pipeline.run(TASK, followups=[
            FollowUp("f1", False, f"{target} 实际体验很差", utcnow())
        ])
        disputed = [c for c in after.pros + after.cons if "回访反馈偏离" in c.tag]
        self.assertTrue(disputed, "回访否认的结论应被标记降权")

    def test_reputation_anomaly_is_detected(self):
        # 构造批次序列：连续三批正常 + 一批好评暴增
        from zhigou.collectors import freeze
        from zhigou.models import Review

        def mk(i, positive, n):
            return [
                Review(
                    review_id=f"h{i}-{j}", platform=Platform.TAOBAO, author_id=f"u{i}-{j}",
                    content="好评" if positive else "差评",
                    rating=5.0 if positive else 1.0,
                    posted_at=utcnow(), snapshot=freeze("x", collector="t"),
                ) for j in range(n)
            ]

        history = [mk(0, True, 3), mk(1, True, 3), mk(2, True, 3), mk(3, True, 20)]
        r = self.pipeline.run(TASK, history=history)
        self.assertTrue(r.reputation_events)
        self.assertEqual(r.reputation_events[0].kind, "好评涌入")
        self.assertTrue(any("异动" in w for w in r.warnings))

    # -- 渲染 ------------------------------------------------------

    def test_text_report_renders(self):
        text = render_text(self.pipeline.run(TASK))
        self.assertIn("真实性看板", text)
        self.assertIn("购买建议", text)
        self.assertIn("存证编号", text)

    def test_html_report_is_self_contained(self):
        html = render_html(self.pipeline.run(TASK))
        self.assertIn("<!DOCTYPE html>", html)
        self.assertNotIn("<script", html.lower(), "报告页不应包含脚本")
        self.assertNotIn("http://", html, "不应有外部资源引用")

    def test_json_roundtrip(self):
        import json
        r = self.pipeline.run(TASK)
        payload = json.dumps(r.to_dict(), ensure_ascii=False)
        back = json.loads(payload)
        self.assertIn("authenticity", back)
        self.assertIn("conclusions", back)


if __name__ == "__main__":
    unittest.main()