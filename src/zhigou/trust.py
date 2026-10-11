"""防线三：多源交叉验证 —— 不迷信任何单一来源。

核心规则只有一条：**只有被两个及以上「独立」平台印证的结论，才允许进入购买建议。**

「独立」是这里的关键字。淘宝与天猫、京东与京东自营属同一集团，
它们的评价很可能来自同一批用户、同一套话术。若把它们当作两个独立信源，
就会把「一条说辞被两个渠道复制」误判成「两个来源共同印证」——
这是交叉验证最容易犯、也最致命的错误。

防线五：可信度量化 —— 把判断权交还给用户。
防线六：持续监控与反馈回流 —— 错误会被纠正。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .analysis import ASPECT_LEXICON
from .models import (
    AuthorityAnchor,
    CleaningResult,
    Claim,
    Platform,
    Product,
    ReputationEvent,
    Review,
    Verdict,
)

# ---------------------------------------------------------------- 交叉验证


@dataclass
class CrossValidator:
    """跨平台口径比对 + 孤证降权。"""

    min_independent_sources: int = 2

    def validate(self, claims: List[Claim]) -> List[Claim]:
        """就地标注每条结论的 corroboration 状态。"""
        for c in claims:
            groups = {p.independence_group for p in c.platforms}
            c.independent_source_count = len(groups)
            c.independence_groups = sorted(groups)
            c.corroborated = len(groups) >= self.min_independent_sources
            if not c.corroborated and c.independent_source_count == 1:
                c.tag = "孤证，待验证"
        return claims

    @staticmethod
    def check_selling_points(product: Product, results: List[CleaningResult]) -> List[str]:
        """跨平台口径比对：详情页宣称 vs 外部实测。

        返回被证伪的宣称（写进「避坑提示」）。
        """
        contradictions: List[str] = []
        for key, claimed in product.attrs.items():
            keyword = _claim_keyword(claimed)
            if not keyword:
                continue
            # 统计外部可信评价中提及该卖点的负面占比
            mentions_neg = 0
            mentions_pos = 0
            for cr in results:
                if cr.verdict != Verdict.TRUSTED:
                    continue
                if keyword not in cr.review.content:
                    continue
                if cr.review.is_positive:
                    mentions_pos += 1
                else:
                    mentions_neg += 1
            if mentions_neg >= 2 and mentions_neg > mentions_pos:
                contradictions.append(
                    f"详情页宣称「{key}：{claimed}」，但 {mentions_neg} 条可信外部评价反馈相反"
                )
        return contradictions

    @staticmethod
    def apply_authority_anchors(
        claims: List[Claim], anchors: Sequence[AuthorityAnchor]
    ) -> List[Claim]:
        """权威锚点修正：质检公告 / 行政处罚等硬证据直接压制相关结论。

        锚点不受商家控制，因此权重高于任何口碑数据。
        """
        for anchor in anchors:
            if anchor.severity < 2:
                continue
            hit = [c for c in claims if anchor.kind in c.text or anchor.detail in c.text]
            if hit:
                for c in hit:
                    c.weight *= 0.3
                    c.tag = (c.tag + "｜权威锚点压制").strip("｜")
        return claims


def _claim_keyword(claimed_value: str) -> str:
    """从属性值中抽取用于比对的关键词（取最长的中文词）。"""
    for word in sorted(_ALL_KEYWORDS, key=len, reverse=True):
        if word in claimed_value:
            return word
    return ""


_ALL_KEYWORDS: Set[str] = set()
for _words in ASPECT_LEXICON.values():
    _ALL_KEYWORDS |= _words


# ---------------------------------------------------------------- 防线五：可信度


@dataclass
class TrustQuantifier:
    """把「这个结论有多可信」算出来一起交付。

    设计上刻意保留了「宁可输出信息不足，也不输出看似完整但不可信」的退路：
    样本量不足或来源单一时，主动降级而不是硬给一个分数。
    """

    min_evidence: int = 20
    min_sources: int = 2
    low_confidence_cutoff: float = 0.5

    def quantify(
        self,
        results: List[CleaningResult],
        pros: List[Claim],
        cons: List[Claim],
    ) -> Tuple[float, str, int, int, str]:
        trusted = [r for r in results if r.verdict == Verdict.TRUSTED]
        evidence_count = len(trusted)
        groups = {r.review.platform.independence_group for r in trusted}
        source_count = len(groups)

        if evidence_count == 0:
            return 0.0, "信息不足", 0, 0, "未发现可信评价"

        # 有效评价占比：剔除比例过高说明数据池本身被污染
        effective_ratio = evidence_count / max(len(results), 1)

        # 置信度 = 样本量饱和度 × 来源多样性 × 有效率
        sample_factor = min(1.0, evidence_count / max(self.min_evidence, 1))
        source_factor = min(1.0, source_count / max(self.min_sources, 1))
        confidence = sample_factor * source_factor * effective_ratio

        # 结论可被交叉印证的占比也影响整体可信度
        all_claims = pros + cons
        if all_claims:
            corroborated = sum(1 for c in all_claims if c.corroborated)
            corroboration_factor = 0.6 + 0.4 * (corroborated / len(all_claims))
            confidence *= corroboration_factor

        confidence = round(max(0.0, min(1.0, confidence)), 4)

        if confidence >= 0.8:
            level = "高"
        elif confidence >= 0.6:
            level = "中"
        elif confidence >= self.low_confidence_cutoff:
            level = "低"
        else:
            level = "低"

        # 降级：样本或来源不足时主动降级为「信息有限，建议观望」
        if evidence_count < self.min_evidence or source_count < self.min_sources:
            level = "信息有限"
            reason = f"仅 {evidence_count} 条可信评价、{source_count} 个独立信源，样本不足以支撑明确结论"
            return confidence, level, evidence_count, source_count, reason

        reason = (
            f"{evidence_count} 条可信评价，覆盖 {source_count} 个独立信源，"
            f"有效率 {effective_ratio * 100:.0f}%"
        )
        return confidence, level, evidence_count, source_count, reason


# ---------------------------------------------------------------- 防线六：监控回流


@dataclass
class ReputationMonitor:
    """口碑突变预警 + 回访回流纠错。"""

    def detect_anomalies(
        self,
        history: Sequence[Sequence[Review]],
    ) -> List[ReputationEvent]:
        """history 按时间顺序存放每个快照批次的评价。

        检测两类突变：
          - 好评涌入：最新批次好评量远超历史均值
          - 差评批量消失：历史存在的差评在最新批次中消失
        """
        events: List[ReputationEvent] = []
        if len(history) < 2 or not history[-1]:
            return events

        def positives(batch: Sequence[Review]) -> List[Review]:
            return [r for r in batch if r.is_positive]

        def negatives(batch: Sequence[Review]) -> List[Review]:
            return [r for r in batch if not r.is_positive]

        hist_pos = [len(positives(b)) for b in history[:-1]]
        hist_neg = [len(negatives(b)) for b in history[:-1]]

        avg_pos = sum(hist_pos) / len(hist_pos)
        if avg_pos >= 3 and len(positives(latest)) > avg_pos * 2:
            events.append(ReputationEvent(
                detected_at=max(r.posted_at for r in latest),
                kind="好评涌入",
                magnitude=len(positives(latest)) / max(avg_pos, 1e-6),
                detail=f"最新批次好评 {len(positives(latest))} 条，历史均值 {avg_pos:.1f} 条",
            ))

        avg_neg = sum(hist_neg) / len(hist_neg)
        latest_neg = negatives(latest)
        if avg_neg >= 2 and len(latest_neg) < avg_neg * 0.5:
            events.append(ReputationEvent(
                detected_at=max(r.posted_at for r in latest),
                kind="差评批量消失",
                magnitude=avg_neg / max(len(latest_neg), 1e-6),
                detail=f"历史差评均值 {avg_neg:.1f} 条，最新批次仅 {len(latest_neg)} 条",
            ))

        return events

    @staticmethod
    def recompute_after_followups(
        pros: List[Claim],
        cons: List[Claim],
        followups: Sequence,
    ) -> Tuple[List[Claim], List[Claim]]:
        """回访与报告系统性偏离时，调整相关结论权重。

        回访由真实购买者产生，是商家无法伪造的一手数据。
        """
        disputed = [f.detail for f in followups if not f.agreed_with_report]
        if not disputed:
            return pros, cons

        for c in pros + cons:
            if any(c.text in d for d in disputed):
                c.weight *= 0.6
                c.tag = (c.tag + "｜回访反馈偏离").strip("｜")
        return pros, cons


__all__ = ["CrossValidator", "TrustQuantifier", "ReputationMonitor"]