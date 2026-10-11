"""领域模型。

设计原则：所有进入系统的数据必须携带 `Snapshot`，对应防线一「采集即快照」——
内容一旦采集即被哈希固化，后续任何环节都无法改写它本身，只能在其之上附加判断。
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

# ---------------------------------------------------------------- 基础工具


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def sha256_hex(data: Any) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """稳定序列化：键排序、无多余空白。

    哈希必须建立在确定性字节序列上，否则同一份内容两次存证会得到不同摘要，
    复现一致性（指标体系第 5 项）无从谈起。
    """
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------- 枚举


class Platform(str, Enum):
    """来源平台。`independence_group` 相同的平台不算独立信源。"""

    TAOBAO = "taobao"
    JD = "jd"
    XIAOHONGSHU = "xiaohongshu"
    DOUYIN = "douyin"
    BILIBILI = "bilibili"
    ZHIHU = "zhihu"
    SMZDM = "smzdm"

    @property
    def label(self) -> str:
        return _PLATFORM_LABELS[self]

    @property
    def independence_group(self) -> str:
        """同集团 / 同生态的平台视为非独立信源。

        淘宝与天猫、京东与京东自营属同一集团；它们的评价很可能来自同一批用户，
        交叉验证时若把它们当作两个独立信源，会把「一条说辞被两个渠道复制」
        误判为「两个来源共同印证」。
        """
        return _PLATFORM_GROUPS[self]


_PLATFORM_LABELS = {
    Platform.TAOBAO: "淘宝",
    Platform.JD: "京东",
    Platform.XIAOHONGSHU: "小红书",
    Platform.DOUYIN: "抖音",
    Platform.BILIBILI: "B 站",
    Platform.ZHIHU: "知乎",
    Platform.SMZDM: "什么值得买",
}

_PLATFORM_GROUPS = {
    Platform.TAOBAO: "alibaba",
    Platform.JD: "jd",
    Platform.XIAOHONGSHU: "xiaohongshu",
    Platform.DOUYIN: "bytedance",
    Platform.BILIBILI: "bilibili",
    Platform.ZHIHU: "zhihu",
    Platform.SMZDM: "smzdm",
}


class MediaKind(str, Enum):
    NONE = "none"
    IMAGE = "image"
    VIDEO = "video"


class Verdict(str, Enum):
    """单条评价的清洗结论。"""

    TRUSTED = "trusted"      # 计入结论
    DOUBTED = "doubted"      # 存疑池 —— 保留证据，可申诉，不计入主结论
    REJECTED = "rejected"    # 剔除池 —— 基本可判定为刷单

    @property
    def label(self) -> str:
        return {
            Verdict.TRUSTED: "可信",
            Verdict.DOUBTED: "存疑",
            Verdict.REJECTED: "剔除",
        }[self]


# ---------------------------------------------------------------- 快照（防线一）


@dataclass
class Snapshot:
    """采集瞬间的原始内容 + 哈希。

    这是整个真实性体系的锚：下游所有结论最终都能回溯到这里的 digest，
    而 digest 在采集那一刻就已确定，此后不可改。
    """

    content: str
    collected_at: datetime
    collector: str = "unknown"
    content_type: str = "text/plain"
    source_url: str = ""
    digest: str = ""

    def __post_init__(self) -> None:
        if not self.digest:
            self.digest = sha256_hex(self.content)

    @property
    def size_bytes(self) -> int:
        return len(self.content.encode("utf-8"))

    def verify(self) -> bool:
        """重算哈希，确认内容未被改动。"""
        return sha256_hex(self.content) == self.digest

    def to_dict(self) -> Dict[str, Any]:
        return {
            "digest": self.digest,
            "collected_at": iso(self.collected_at),
            "collector": self.collector,
            "content_type": self.content_type,
            "source_url": self.source_url,
            "size_bytes": self.size_bytes,
        }


# ---------------------------------------------------------------- 原始数据


@dataclass
class MediaEvidence:
    """多模态证据（防线二 · 维度三）。"""

    kind: MediaKind = MediaKind.NONE
    media_hash: str = ""                      # 图片/视频指纹，识别搬运重剪
    shows_usage: bool = False                 # 是否出现真实使用痕迹（磨损、烟渍、水渍）
    only_packaging: bool = False              # 只晒包装，未进入使用场景
    script_visual_mismatch: bool = False      # 口播文案与画面内容脱节
    duration_sec: float = 0.0


@dataclass
class Review:
    """一条原始评价。

    刻意保留了大量「反作弊特征」字段（device_hash / address_hash / review_category_count …），
    因为六维识别的本质就是把平台上看不见的关联信号显式化后再做判断。
    """

    review_id: str
    platform: Platform
    author_id: str
    content: str
    rating: float                              # 1–5
    posted_at: datetime
    purchased_at: Optional[datetime] = None
    is_followup: bool = False                  # 追评：使用一段时间后的反馈，天然难刷
    media: List[MediaEvidence] = field(default_factory=list)
    snapshot: Snapshot = field(default_factory=lambda: Snapshot("", utcnow()))
    # 账号与时空信号
    account_created_at: Optional[datetime] = None
    author_review_count: int = 1
    review_category_count: int = 1             # 历史评价涉及的品类数，跨品类刷单会偏高
    device_hash: str = ""
    address_hash: str = ""
    follows: List[str] = field(default_factory=list)   # 关注关系，用于水军团伙识别
    geo: str = ""
    logistics_geo: str = ""
    # 商业化信号
    ad_disclosed: bool = False                 # 是否标注广告合作
    incentive_card: bool = False               # 平台「好评返现」卡片
    item_url: str = ""

    @property
    def hours_since_purchase(self) -> Optional[float]:
        if self.purchased_at is None:
            return None
        return (self.posted_at - self.purchased_at).total_seconds() / 3600.0

    @property
    def account_age_days(self) -> Optional[float]:
        if self.account_created_at is None:
            return None
        return (self.posted_at - self.account_created_at).total_seconds() / 86400.0

    @property
    def is_positive(self) -> bool:
        return self.rating >= 4.0

    @property
    def geo_mismatch(self) -> bool:
        """评价所在地与物流收货地不一致。"""
        return bool(self.geo and self.logistics_geo and self.geo != self.logistics_geo)


@dataclass
class Product:
    product_id: str
    title: str
    price: float
    shop: str = ""
    categories: List[str] = field(default_factory=list)
    attrs: Dict[str, str] = field(default_factory=dict)
    source_url: str = ""


@dataclass
class AuthorityAnchor:
    """权威锚点（防线三）。

    质检公告、行政处罚、投诉量——这些不受商家控制，是交叉验证里权重最高的硬证据。
    """

    kind: str          # "质检公告" / "行政处罚" / "投诉"
    detail: str
    severity: int = 1  # 1=中性 2=轻微 3=严重
    source_url: str = ""


@dataclass
class ClaimCheck:
    """对平台宣称卖点的外部核验结果（防线三 · 跨平台口径比对）。"""

    selling_point: str
    supports: List[Platform] = field(default_factory=list)
    contradicts: List[Platform] = field(default_factory=list)


# ---------------------------------------------------------------- 中间产物


@dataclass
class DimensionResult:
    """单个反作弊维度的判定结果。"""

    name: str
    suspicion: float                       # 0=清白 1=高度可疑
    evidence: List[str] = field(default_factory=list)

    @property
    def weight_contribution(self) -> float:
        return 1.0 - self.suspicion


@dataclass
class CleaningResult:
    review: Review
    dimensions: List[DimensionResult] = field(default_factory=list)
    trusted_weight: float = 1.0
    verdict: Verdict = Verdict.TRUSTED
    notes: List[str] = field(default_factory=list)

    @property
    def digest(self) -> str:
        return self.review.snapshot.digest


@dataclass
class Claim:
    """报告中的一条结论（优点 / 缺点 / 争议点）。"""

    text: str
    polarity: str                 # "pro" | "con" | "contested"
    weight: float = 0.0           # 证据加权和
    platforms: List[Platform] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    independence_groups: List[str] = field(default_factory=list)
    independent_source_count: int = 0
    confidence: float = 0.0
    corroborated: bool = False
    tag: str = ""                 # "孤证，待验证" 等

    @property
    def platform_labels(self) -> List[str]:
        return [p.label for p in self.platforms]


@dataclass
class VerdictSummary:
    """可信度量化（防线五）。交付的不只是结论，还有「这个结论有多可信」。"""

    confidence: float
    level: str                   # 高 / 中 / 低 / 信息不足
    evidence_count: int
    independent_sources: int
    reason: str = ""

    @property
    def display(self) -> str:
        return f"{self.level}（{self.confidence * 100:.0f}%）"


@dataclass
class FollowUp:
    """购买回访（防线六）。由真实购买者产生，商家无法伪造。"""

    review_id: str
    agreed_with_report: bool
    detail: str
    visited_at: datetime


@dataclass
class ReputationEvent:
    """口碑突变事件（防线六）。"""

    detected_at: datetime
    kind: str                    # "好评涌入" / "差评批量消失"
    magnitude: float
    detail: str


@dataclass
class Attestation:
    """链上存证凭证（防线四）。"""

    merkle_root: str
    leaf_count: int
    leaf_digests: List[str]
    ledger_index: int
    ledger_hash: str
    anchored_at: datetime
    chain: str                   # 适配器名称
    model_fingerprint: str = ""  # 模型版本 + 参数指纹，保证可复现

    def to_dict(self) -> Dict[str, Any]:
        return {
            "merkle_root": self.merkle_root,
            "leaf_count": self.leaf_count,
            "ledger_index": self.ledger_index,
            "ledger_hash": self.ledger_hash,
            "anchored_at": iso(self.anchored_at),
            "chain": self.chain,
            "model_fingerprint": self.model_fingerprint,
        }


# ---------------------------------------------------------------- 报告


@dataclass
class ShoppingReport:
    product: Product
    generated_at: datetime
    total_collected: int = 0
    trusted: int = 0
    doubted: int = 0
    rejected: int = 0
    pros: List[Claim] = field(default_factory=list)
    cons: List[Claim] = field(default_factory=list)
    contested: List[Claim] = field(default_factory=list)
    advice: Dict[str, Any] = field(default_factory=dict)
    summary: VerdictSummary = field(default_factory=lambda: VerdictSummary(0.0, "信息不足", 0, 0))
    authenticity: Dict[str, Any] = field(default_factory=dict)
    attestation: Optional[Attestation] = None
    reputation_events: List[ReputationEvent] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def effective_sample(self) -> int:
        return self.trusted

    def to_dict(self) -> Dict[str, Any]:
        def claim(c: Claim) -> Dict[str, Any]:
            return {
                "text": c.text,
                "polarity": c.polarity,
                "weight": round(c.weight, 4),
                "platforms": c.platform_labels,
                "independent_sources": c.independent_source_count,
                "evidence_ids": c.evidence_ids[:10],
                "confidence": round(c.confidence, 4),
                "corroborated": c.corroborated,
                "tag": c.tag,
            }

        return {
            "product": {
                "product_id": self.product.product_id,
                "title": self.product.title,
                "price": self.product.price,
                "shop": self.product.shop,
                "source_url": self.product.source_url,
            },
            "generated_at": iso(self.genered_at),
            "authenticity": {
                **self.authenticity,
                "attestation": self.attestation.to_dict() if self.attestation else None,
            },
            "conclusions": {
                "pros": [claim(c) for c in self.pros],
                "cons": [claim(c) for c in self.cons],
                "contested": [claim(c) for c in self.contested],
            },
            "verdict": {
                "level": self.summary.level,
                "confidence": round(self.summary.confidence, 4),
                "display": self.summary.display,
                "evidence_count": self.summary.evidence_count,
                "independent_sources": self.summary.independent_sources,
                "reason": self.summary.reason,
            },
            "advice": self.advice,
            "warnings": self.warnings,
        }


__all__ = [
    "utcnow", "iso", "sha256_hex", "canonical_json",
    "Platform", "MediaKind", "Verdict",
    "Snapshot", "MediaEvidence", "Review", "Product",
    "AuthorityAnchor", "ClaimCheck",
    "DimensionResult", "CleaningResult", "Claim",
    "VerdictSummary", "FollowUp", "ReputationEvent", "Attestation",
    "ShoppingReport",
]