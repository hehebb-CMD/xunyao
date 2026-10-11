"""防线二：六维反作弊识别。"""

import os
import sys
import unittest
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from zhigou.antifraud import AntifraudCleaner, CorpusContext
from zhigou.collectors import SimulatedCollector, TaskParameter, freeze
from zhigou.models import (
    MediaEvidence, MediaKind, Platform, Review, Verdict, utcnow,
)

NOW = utcnow()


def mk_review(**kw) -> Review:
    base = dict(
        review_id="r1",
        platform=Platform.TAOBAO,
        author_id="u1",
        content="用了一个月，续航确实扎实，做工也很细腻。",
        rating=5.0,
        posted_at=NOW,
        purchased_at=NOW - timedelta(days=10),
        account_created_at=NOW - timedelta(days=2000),
        author_review_count=50,
        review_category_count=2,
        geo="北京",
        logistics_geo="北京",
    )
    base.update(kw)
    r = Review(**base)
    if not r.snapshot.content:
        r.snapshot = freeze(r.content, collector="test")
    return r


class TestTextFingerprint(unittest.TestCase):
    def test_long_specific_review_is_clean(self):
        r = mk_review(content=(
            "用了一个月，续航确实扎实，出差一周不用充电。"
            "做工比想象中细腻，边缘没有毛刺，放口袋里刮花不明显。"
            "充电速度也快，早上洗漱时间能充进去大半。"))
        cleaner = AntifraudCleaner()
        ctx = cleaner._build_context([r])
        res = [d for d in cleaner._clean_one(r, ctx).dimensions if d.name == "文本指纹"][0]
        self.assertLess(res.suspicion, 0.4)

    def test_vague_praise_is_suspicious(self):
        r = mk_review(content="宝贝很好，物流很快，客服态度好，无脑推荐，闭眼入！")
        cleaner = AntifraudCleaner()
        ctx = cleaner._build_context([r])
        res = [d for d in cleaner._clean_one(r, ctx).dimensions if d.name == "文本指纹"][0]
        self.assertGreater(res.suspicion, 0.4)

    def test_near_duplicate_detection(self):
        """两条几乎相同的模板文本应触发雷同。"""
        tpl = "宝贝很好，五星好评，物流很快，客服也nice，下次还会来买的！"
        a = mk_review(review_id="a", content=tpl)
        b = mk_review(review_id="b", content=tpl)
        cleaner = AntifraudCleaner()
        ctx = cleaner._build_context([a, b])
        self.assertIn("b", ctx.near_duplicates["a"])
        res = [d for d in cleaner._clean_one(a, ctx).dimensions if d.name == "文本指纹"][0]
        self.assertGreater(res.suspicion, 0.8)


class TestAccountBehavior(unittest.TestCase):
    def test_new_account_instant_five_star(self):
        r = mk_review(
            posted_at=NOW,
            purchased_at=NOW - timedelta(minutes=20),
            account_created_at=NOW - timedelta(days=5),
            rating=5.0,
        )
        cleaner = AntifraudCleaner()
        ctx = cleaner._build_context([r])
        res = [d for d in cleaner._clean_one(r, ctx).dimensions if d.name == "账号行为"][0]
        self.assertGreater(res.suspicion, 0.7)

    def test_mature_account_normal_pace_is_clean(self):
        r = mk_review()
        cleaner = AntifraudCleaner()
        ctx = cleaner._build_context([r])
        res = [d for d in cleaner._clean_one(r, ctx).dimensions if d.name == "账号行为"][0]
        self.assertLess(res.suspicion, 0.3)


class TestIncentiveChain(unittest.TestCase):
    def test_cashback_phrase(self):
        r = mk_review(content="晒图返现 20 块，加微信领红包，秒回好评")
        cleaner = AntifraudCleaner()
        ctx = cleaner._build_context([r])
        res = [d for d in cleaner._clean_one(r, ctx).dimensions if d.name == "激励链路"][0]
        self.assertGreater(res.suspicion, 0.8)

    def test_incentive_card_flag(self):
        r = mk_review(content="还不错", incentive_card=True)
        cleaner = AntifraudCleaner()
        ctx = cleaner._build_context([r])
        res = [d for d in cleaner._clean_one(r, ctx).dimensions if d.name == "激励链路"][0]
        self.assertGreater(res.suspicion, 0.8)

    def test_ordinary_review_has_no_incentive_signal(self):
        r = mk_review(content="续航不错，充电很快。")
        cleaner = AntifraudCleaner()
        ctx = cleaner._build_context([r])
        res = [d for d in cleaner._clean_one(r, ctx).dimensions if d.name == "激励链路"][0]
        self.assertEqual(res.suspicion, 0.0)


class TestRelationGraph(unittest.TestCase):
    def test_device_cluster_downgrades_group(self):
        reviews = [
            mk_review(review_id=f"g{i}", author_id=f"a{i}", device_hash="DEV-X")
            for i in range(4)
        ]
        cleaner = AntifraudCleaner()
        cleaned = cleaner.clean(reviews)
        for cr in cleaned:
            res = [d for d in cr.dimensions if d.name == "关系图谱"][0]
            self.assertGreater(res.suspicion, 0.8)

    def test_shared_address_alone_is_not_enough(self):
        """仅两条共享地址不足以判定团伙——家庭共用地址很常见。"""
        reviews = [
            mk_review(review_id=f"s{i}", author_id=f"b{i}", address_hash="ADDR-Y")
            for i in range(2)
        ]
        cleaner = AntifraudCleaner()
        cleaned = cleaner.clean(reviews)
        for cr in cleaned:
            res = [d for d in cr.dimensions if d.name == "关系图谱"][0]
            self.assertLess(res.suspicion, 0.5)


class TestSpatiotemporal(unittest.TestCase):
    def test_geo_mismatch(self):
        r = mk_review(geo="乌鲁木齐", logistics_geo="深圳")
        cleaner = AntifraudCleaner()
        ctx = cleaner._build_context([r])
        res = [d for d in cleaner._clean_one(r, ctx).dimensions if d.name == "时空聚集"][0]
        self.assertGreater(res.suspicion, 0.5)

    def test_positive_burst(self):
        reviews = [
            mk_review(review_id=f"p{i}", author_id=f"c{i}",
                      posted_at=NOW + timedelta(minutes=i * 3))
            for i in range(6)
        ]
        cleaner = AntifraudCleaner()
        cleaned = cleaner.clean(reviews)
        res = [d for d in cleaned[0].dimensions if d.name == "时空聚集"][0]
        self.assertGreater(res.suspicion, 0.4)


class TestMultimodal(unittest.TestCase):
    def test_duplicated_media_hash(self):
        dup = "MH-1"
        reviews = [
            mk_review(review_id=f"d{i}", author_id=f"d{i}", media=[MediaEvidence(
                kind=MediaKind.VIDEO, media_hash=dup, script_visual_mismatch=True)])
            for i in range(3)
        ]
        cleaner = AntifraudCleaner()
        cleaned = cleaner.clean(reviews)
        for cr in cleaned:
            res = [d for d in cr.dimensions if d.name == "多模态证据"][0]
            self.assertGreater(res.suspicion, 0.6)

    def test_no_media_is_neutral(self):
        r = mk_review()
        cleaner = AntifraudCleaner()
        ctx = cleaner._build_context([r])
        res = [d for d in cleaner._clean_one(r, ctx).dimensions if d.name == "多模态证据"][0]
        self.assertEqual(res.suspicion, 0.0)


class TestVerdictRouting(unittest.TestCase):
    """三池分流：可信 / 存疑 / 剔除，且低分不删除。"""

    def test_clean_review_is_trusted(self):
        r = mk_review()
        cr = AntifraudCleaner().clean([r])[0]
        self.assertEqual(cr.verdict, Verdict.TRUSTED)

    def test_obvious_fake_is_rejected(self):
        r = mk_review(
            content="宝贝很好，五星好评，物流很快，客服态度好，无脑推荐！",
            posted_at=NOW,
            purchased_at=NOW - timedelta(minutes=5),
            account_created_at=NOW - timedelta(days=2),
            incentive_card=True,
        )
        cr = AntifraudCleaner().clean([r])[0]
        self.assertEqual(cr.verdict, Verdict.REJECTED)

    def test_moderate_suspicion_goes_to_doubt_pool(self):
        """中等可疑 → 存疑而非剔除。这是「不误伤」的设计底线。"""
        r = mk_review(
            content="续航不错，物流很快，客服态度好。",
            posted_at=NOW,
            purchased_at=NOW - timedelta(hours=3),
            account_created_at=NOW - timedelta(days=10),
        )
        cr = AntifraudCleaner().clean([r])[0]
        self.assertIn(cr.verdict, (Verdict.DOUBTED, Verdict.REJECTED))

    def test_nothing_is_ever_discarded(self):
        """清洗只改变权重与归属，不销毁任何证据。"""
        reviews = [mk_review(review_id=f"x{i}") for i in range(3)]
        cleaned = AntifraudCleaner().clean(reviews)
        self.assertEqual(len(cleaned), len(reviews))
        for cr in cleaned:
            self.assertTrue(cr.review.snapshot.verify())


class TestSimulatedCorpus(unittest.TestCase):
    """模拟语料应包含可被检出的噪声，且结果可复现。"""

    def _corpus(self):
        col = SimulatedCollector(seed=12345, authentic_count=20)
        return col.fetch_reviews(TaskParameter(task_id="t", product_id="P1"))

    def test_deterministic(self):
        a = [r.review_id for r in self._corpus()]
        b = [r.review_id for r in self._corpus()]
        self.assertEqual(a, b)

    def test_noise_is_detected(self):
        cleaned = AntifraudCleaner().clean(self._corpus())
        rejected = [c for c in cleaned if c.verdict == Verdict.REJECTED]
        self.assertGreater(len(rejected), 0, "模拟语料中的刷单噪声应被识别")

    def test_authentic_reviews_survive(self):
        cleaned = AntifraudCleaner().clean(self._corpus())
        trusted = [c for c in cleaned if c.verdict == Verdict.TRUSTED]
        self.assertGreater(len(trusted), 20, "真实评价不应被大规模误伤")


if __name__ == "__main__":
    unittest.main()