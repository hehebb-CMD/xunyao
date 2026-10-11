"""防线一 & 防线四：快照固化与存证验证。"""

import os
import sys
import tempfile
import unittest
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from zhigou.attestation import (
    Attestor, LocalLedgerAdapter, merkle_proof, merkle_root, verify_merkle_proof,
)
from zhigou.collectors import freeze
from zhigou.models import sha256_hex, utcnow


class TestSnapshotFreeze(unittest.TestCase):
    """防线一：采集即快照。"""

    def test_digest_is_deterministic(self):
        a = freeze("同样内容", collector="t")
        b = freeze("同样内容", collector="t")
        self.assertEqual(a.digest, b.digest)

    def test_digest_changes_with_content(self):
        a = freeze("内容A", collector="t")
        b = freeze("内容B", collector="t")
        self.assertNotEqual(a.digest, b.digest)

    def test_verify_detects_tampering(self):
        snap = freeze("原始评价内容", collector="t")
        self.assertTrue(snap.verify())
        snap.content = "被篡改的内容"
        self.assertFalse(snap.verify())

    def test_collector_name_does_not_affect_digest(self):
        """内容哈希不应随采集来源变化，否则同一条评价跨平台采集会得到不同摘要。"""
        self.assertEqual(
            freeze("x", collector="taobao").digest,
            freeze("x", collector="jd").digest,
        )


class TestMerkle(unittest.TestCase):
    def test_single_leaf_root(self):
        leaf = sha256_hex("a")
        self.assertEqual(merkle_root([leaf]), leaf)

    def test_empty_tree_has_stable_root(self):
        self.assertEqual(merkle_root([]), merkle_root([]))

    def test_root_is_order_independent_after_sort(self):
        """anchor() 内部会先排序，因此集合相同的证据必得同一根。"""
        leaves = [sha256_hex(x) for x in "abcde"]
        self.assertEqual(merkle_root(sorted(leaves)), merkle_root(sorted(reversed(leaves))))

    def test_proof_verifies(self):
        leaves = [sha256_hex(str(i)) for i in range(7)]
        root = merkle_root(leaves)
        for i in range(len(leaves)):
            proof = merkle_proof(leaves, i)
            self.assertTrue(verify_merkle_proof(leaves[i], proof, i, root))

    def test_proof_rejects_wrong_leaf(self):
        leaves = [sha256_hex(str(i)) for i in range(5)]
        root = merkle_root(leaves)
        proof = merkle_proof(leaves, 2)
        self.assertFalse(verify_merkle_proof(sha256_hex("forged"), proof, 2, root))

    def test_proof_rejects_out_of_range_index(self):
        leaves = [sha256_hex(str(i)) for i in range(3)]
        self.assertEqual(merkle_proof(leaves, 99), [])


class TestLedger(unittest.TestCase):
    """防线四：哈希链账本。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "ledger.jsonl")
        self.adapter = LocalLedgerAdapter(path=self.path)

    def tearDown(self):
        for f in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, f))
        os.rmdir(self.tmp)

    def test_first_record_links_to_genesis(self):
        res = self.adapter.anchor({"x": 1})
        rec = self.adapter.get(0)
        self.assertEqual(rec["prev_hash"], "GENESIS")
        self.assertEqual(res["index"], 0)

    def test_audit_passes_on_intact_chain(self):
        for i in range(5):
            self.adapter.anchor({"i": i})
        self.assertTrue(self.adapter.audit()["ok"])

    def test_audit_detects_tampered_payload(self):
        for i in range(3):
            self.adapter.anchor({"i": i})
        # 直接改写中间某条的 payload —— self_hash 不再匹配
        records = self.adapter._read_all()
        records[1]["payload"]["i"] = 999
        with open(self.path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(__import__("json").dumps(r, ensure_ascii=False) + "\n")

        result = self.adapter.audit()
        self.assertFalse(result["ok"])
        self.assertTrue(any("payload" in p or "self_hash" in p for p in result["problems"]))

    def test_audit_detects_deleted_record(self):
        for i in range(4):
            self.adapter.anchor({"i": i})
        records = self.adapter._read_all()
        del records[2]
        with open(self.path, "w", encoding="utf-8") as f:
            import json
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        result = self.adapter.audit()
        self.assertFalse(result["ok"])


class TestAttestor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.attestor = Attestor(
            adapter=LocalLedgerAdapter(path=os.path.join(self.tmp, "l.jsonl")),
            model_fingerprint="test-1",
        )

    def tearDown(self):
        for f in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, f))
        os.rmdir(self.tmp)

    def test_anchor_produces_verifiable_attestation(self):
        digests = [sha256_hex(f"r{i}") for i in range(10)]
        att = self.attestor.anchor(digests, context={"task": "t1"})
        self.assertEqual(att.leaf_count, 10)
        self.assertEqual(att.merkle_root, merkle_root(sorted(digests)))
        self.assertTrue(self.attestor.verify_report(att, "报告正文"))

    def test_each_leaf_is_independently_verifiable(self):
        digests = [sha256_hex(f"r{i}") for i in range(9)]
        att = self.attestor.anchor(digests, context={})
        for i in range(len(att.leaf_digests)):
            self.assertTrue(self.attestor.verify_leaf(att, i))

    def test_same_evidence_same_root(self):
        d = [sha256_hex(f"r{i}") for i in range(5)]
        a1 = self.attestor.anchor(d, context={})
        a2 = self.attestor.anchor(list(reversed(d)), context={})
        self.assertEqual(a1.merkle_root, a2.merkle_root)

    def test_verify_rejects_unknown_index(self):
        att = self.attestor.anchor([sha256_hex("a")], context={})
        self.assertFalse(self.attestor.verify_leaf(att, 42))


if __name__ == "__main__":
    unittest.main()