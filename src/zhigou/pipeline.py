"""四步闭环编排：解析商品 → 聚合口碑 → 清洗真伪 → 给出决策。

每一步都可能被防线拦截，而任一防线被突破时后续防线仍能兜底。
流水线对上层只暴露 `run()`，内部顺序是刻意的：
先固化证据（防线一），再判断可信（防线二/三/五），
最后才产出结论（防线四上链）——**先有证据，后有结论**，
顺序反过来就会出现「结论已出、证据后补」的不可验证状态。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .analysis import ClaimAggregator, SentimentAnalyzer
from .antifraud import AntifraudCleaner
from .attestation import Attestor, LocalLedgerAdapter
from .collectors import Collector, SimulatedCollector, TaskParameter, get_collector
from .models import (
    AuthorityAnchor,
    Claim,
    CleaningResult,
    FollowUp,
    Product,
    ReputationEvent,
    Review,
    ShoppingReport,
    Verdict,
    canonical_json,
    iso,
    sha256_hex,
    utcnow,
)
from .report import render_text, render_html
from .trust import CrossValidator, ReputationMonitor, TrustQuantifier

# 模型指纹：参与存证，保证「同一证据集 + 同一模型 = 可复现结果」。
# 本实现是确定性规则法，版本号随规则变更递增。
MODEL_VERSION = "rules-1.0.0"
MODEL_FINGERPRINT = sha256_hex(canonical_json({
    "version": MODEL_VERSION,
    "kind": "deterministic-rules",
    "aspects": "aspect-lexicon-v1",
}))


@dataclass
class PipelineConfig:
    collector: str = "simulated"
    collector_kwargs: Dict[str, Any] = field(default_factory=dict)
    ledger_path: str = "ledger.jsonl"
    min_independent_sources: int = 2
    trust_threshold: float = 0.45
    reject_threshold: float = 0.75
    enable_attestation: bool = True
    max_claims: int = 5


@dataclass
class Pipeline:
    """智购参谋主流程。"""

    config: PipelineConfig = field(default_factory=PipelineConfig)

    # -- 装配 ------------------------------------------------------

    def _collector(self) -> Collector:
        if self.config.collector == "simulated":
            return SimulatedCollector(**self.config.collector_kwargs)
        return get_collector(self.config.collector, **self.config.collector_kwargs)

    def _attestor(self) -> Attestor:
        return Attestor(
            adapter=LocalLedgerAdapter(path=self.config.ledger_path),
            model_fingerprint=MODEL_FINGERPRINT,
        )

    # -- 主流程 ----------------------------------------------------

    def run(
        self,
        task: TaskParameter,
        followups: Optional[Sequence[FollowUp]] = None,
        history: Optional[Sequence[Sequence[Review]]] = None,
        anchors: Optional[Sequence[AuthorityAnchor]] = None,
    ) -> ShoppingReport:
        warnings: List[str] = []
        collector = self._collector()

        # === 第一步：解析商品（防线一：采集即快照）===
        product = collector.fetch_product(task)
        if product is None:
            raise RuntimeError("商品解析失败，无法继续")

        # === 第二步：聚合口碑（防线一：每条评价固化快照）===
        reviews = collector.fetch_reviews(task)
        for r in reviews:
            if not r.snapshot.verify():
                # 理论上不可能发生——digest 在 __post_init__ 就已固定。
                # 真发生意味着内容被事后改动，必须中止而非继续出报告。
                raise RuntimeError(f"快照校验失败：{r.review_id} 内容与哈希不一致")
        total = len(reviews)

        # === 第三步：清洗真伪（防线二：六维反作弊）===
        cleaner = AntifraudCleaner(
            trust_threshold=self.config.trust_threshold,
            reject_threshold=self.config.reject_threshold,
        )
        cleaned = cleaner.clean(reviews)

        trusted = [c for c in cleaned if c.verdict == Verdict.TRUSTED]
        doubted = [c for c in cleaned if c.verdict == Verdict.DOUBTED]
        rejected = [c for c in cleaned if c.verdict == Verdict.REJECTED]

        # === 第三步之二：交叉验证（防线三）===
        aggregator = ClaimAggregator(SentimentAnalyzer())
        pros, cons, contested = aggregator.aggregate(cleaned)
        validator = CrossValidator(self.config.min_independent_sources)
        validator.validate(pros + cons + contested)

        contradictions = validator.check_selling_points(product, cleaned)
        if anchors:
            CrossValidator.apply_authority_anchors(pros + cons, anchors)

        # 防线六：回访回流纠错
        reputation_events: List[ReputationEvent] = []
        if followups:
            pros, cons = ReputationMonitor.recompute_after_followups(pros, cons, followups)
        if history:
            reputation_events = ReputationMonitor().detect_anomalies(history)
            if reputation_events:
                warnings.append(
                    "检测到口碑异动（" + "、".join(e.kind for e in reputation_events) + "），建议观望"
                )

        # === 第四步：给出决策（防线五：可信度量化）===
        quantifier = TrustQuantifier()
        conf, level, ev_count, src_count, reason = quantifier.quantify(cleaned, pros, cons)

        # 结论裁剪：未获双源印证的结论不进入「购买建议」，只留在报告正文
        k = self.config.max_claims
        advice = self._build_advice(product, pros, cons, contested, contradictions, k)

        authenticity = {
            "total_collected": total,
            "trusted": len(trusted),
            "doubted": len(doubted),
            "rejected": len(rejected),
            "effective_ratio": round(len(trusted) / total, 4) if total else 0.0,
            "effective_sample": len(trusted),
            "doubt_pool_reasons": self._top_doubt_reasons(doubted),
            "selling_point_contradictions": contradictions,
        }

        report = ShoppingReport(
            product=product,
            generated_at=utcnow(),
            total_collected=total,
            trusted=len(trusted),
            doubted=len(doubted),
            rejected=len(rejected),
            pros=pros[:k],
            cons=cons[:k],
            contested=contested[:k],
            advice=advice,
            authenticity=authenticity,
            reputation_events=reputation_events,
            warnings=warnings,
        )

        # === 交付形态：附证据、置信度、存证编号 ===
        from .models import VerdictSummary
        report.summary = VerdictSummary(
            confidence=conf, level=level,
            evidence_count=ev_count, independent_sources=src_count,
            reason=reason,
        )

        # === 防线四：存证（先有证据，后有结论）===
        if self.config.enable_attestation:
            digests = [c.review.snapshot.digest for c in cleaned]
            report.attestation = self._attestor().anchor(
                digests,
                context={
                    "task_id": task.task_id,
                    "product_id": product.product_id,
                    "generated_at": iso(report.generated_at),
                },
            )

        return report

    # -- 辅助 ------------------------------------------------------

    @staticmethod
    def _build_advice(
        product: Product,
        pros: List[Claim],
        cons: List[Claim],
        contested: List[Claim],
        contradictions: List[str],
        k: int,
    ) -> Dict[str, Any]:
        """购买建议：只采用经双源印证的结论。

        这是「少给一条结论，好过给一条假结论」的直接实现。
        """
        confirmed_pro = [c for c in pros[:k] if c.corroborated]
        confirmed_con = [c for c in cons[:k] if c.corroborated]

        suitable = [c.text for c in confirmed_pro] or ["样本不足，暂无明确优势结论"]
        unsuitable = [c.text for c in confirmed_con] or ["样本不足，暂无明确劣势结论"]

        caveats: List[str] = []
        caveats.extend(c.text for c in contested[:k])
        caveats.extend(contradictions)

        weak = [c for c in (pros + cons) if not c.corroborated][:3]
        if weak:
            caveats.append(
                "以下线索仅单一信源提及，未采信：" + "、".join(c.text for c in weak)
            )

        return {
            "suitable_for": suitable,
            "not_suitable_for": unsuitable,
            "caveats": caveats,
            "price": product.price,
        }

    @staticmethod
    def _top_doubt_reasons(doubted: List[CleaningResult], limit: int = 3) -> List[str]:
        """汇总存疑池的主要成因——这些是要向用户解释「为什么少算了」的地方。"""
        counter: Dict[str, int] = {}
        for cr in doubted:
            for d in cr.dimensions:
                if d.suspicion >= 0.5 and d.evidence:
                    counter[d.name] = counter.get(d.name, 0) + 1
        return [f"{name}（{cnt} 条）" for name, cnt in
                sorted(counter.items(), key=lambda x: -x[1])[:limit]]


__all__ = ["Pipeline", "PipelineConfig", "MODEL_VERSION", "MODEL_FINGERPRINT"]