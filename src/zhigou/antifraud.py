"""防线二：六维反作弊识别。

单一维度的刷单识别极易被绕过——模板换个词就绕过了句式检测，换一批号就绕过了账号检测。
因此本模块要求六个维度**交叉打分**，输出每条评价的可信权重。

六个维度对应文档 1.4 节的前三类威胁：
  ① 文本指纹  ② 账号行为  ③ 多模态证据  ④ 关系图谱  ⑤ 时空聚集  ⑥ 激励链路

关键设计：**低于阈值不删除，进存疑池**。
误伤真实评价的代价（商家申诉、用户失去有效信息）远高于放过一条可疑评价，
且删除会让反作弊本身变成一件可以被武器化的工具。
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, List, Sequence, Set, Tuple

from .models import (
    DimensionResult,
    MediaKind,
    Platform,
    Review,
    Verdict,
    CleaningResult,
)

# ---------------------------------------------------------------- 词表

# 空泛好评：不含任何具体信息的通用赞美。刷单最显著的特征之一。
VAGUE_PRAISE = {
    "很好", "不错", "好评", "推荐", "满意", "质量很好", "发货很快", "物流快",
    "值得购买", "性价比高", "完全符合预期", "五星好评", "非常满意", "物美价廉",
    "客服态度好", "包装完好", "会再回购", "无脑推荐", "闭眼入",
}

# 返现 / 激励诱导话术
INCENTIVE_PATTERNS = [
    r"返[现现]\s*\d+",
    r"返[现现].{0,6}(现金|红包|优惠券|积分)",
    r"晒图.{0,4}(返|送).{0,4}(现|红包|券)",
    r"五星.{0,4}截图.{0,6}(客服|发我|领取)",
    r"加(微信|威信|vx|VX).{0,6}(红包|返|优惠)",
    r"私聊.{0,4}(有|给).{0,4}(红包|优惠|礼品)",
    r"确认收货.{0,6}(返|退|补).{0,4}(现|款|红包)",
    r"(免费|白拿).{0,4}(送|领).{0,4}(样机|礼品)",
    r"专业(好评|刷单|接单|水军)",
    r"(接单|派单).{0,4}(群|单)",
]

INCENTIVE_RE = [re.compile(p) for p in INCENTIVE_PATTERNS]

# 模板化结构：刷单常用「产品优点 + 使用感受 + 推荐理由」的固定三段式
TEMPLATE_MARKERS = [
    "首先", "其次", "再次", "最后", "总体来说", "综上所述",
    "第一", "第二", "第三",
]

# 停用词：计算文本相似度时剔除，避免「的/了/是」主导距离
STOPWORDS = {
    "的", "了", "是", "我", "你", "他", "她", "它", "这", "那", "就", "都", "和",
    "也", "很", "有", "在", "不", "一个", "一个", "上", "下", "中", "为", "以",
    "而且", "但是", "所以", "因为", "如果", "可以", "自己", "没有", "什么",
    "the", "a", "an", "is", "to", "of", "and", "it",
}

_PUNCT_RE = re.compile(r"[，。！？；：、,.!?;:\s]+")


# ---------------------------------------------------------------- 文本工具


def normalize(text: str) -> str:
    return text.strip().lower()


def shingles(text: str, n: int = 3) -> Set[str]:
    """中文按字切 n-gram。中文没有空格分词，字符 n-gram 是最稳的无依赖近似。"""
    s = _PUNCT_RE.sub("", normalize(text))
    if len(s) < n:
        return {s} if s else set()
    return {s[i:i + n] for i in range(len(s) - n + 1)}


def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if inter == 0:
        return 0.0
    return inter / len(a | b)


def content_tokens(text: str) -> Set[str]:
    """用于「是否空泛」的实词集合：剔除停用词后的 2-gram。"""
    s = _PUNCT_RE.sub("", normalize(text))
    toks = {s[i:i + 2] for i in range(len(s) - 1)}
    return {t for t in toks if t not in STOPWORDS}


# ---------------------------------------------------------------- 维度定义


class Dimension:
    """单个反作弊维度。`score` 返回 0..1 的可疑度。"""

    name = "base"
    weight = 1.0

    def score(self, review: Review, ctx: "CorpusContext") -> DimensionResult:
        raise NotImplementedError


@dataclass
class CorpusContext:
    """一次清洗任务的全局上下文。

    关系图谱与文本雷同检测本质上是**跨条目**的判断，
    必须在一次批处理内完成，不能逐条独立评估。
    """

    reviews: List[Review] = None  # type: ignore[assignment]
    #: review_id -> 语料中与之文本高度相似的其他 review_id
    near_duplicates: Dict[str, List[str]] = None  # type: ignore[assignment]
    #: author_id -> 所属团伙标签（同一团伙整组降权）
    device_clusters: Dict[str, str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.reviews is None:
            self.reviews = []
        if self.near_duplicates is None:
            self.near_duplicates = defaultdict(list)
        if self.device_clusters is None:
            self.device_clusters = {}

    def max_similarity(self, review: Review) -> Tuple[float, List[str]]:
        peers = self.near_duplicates.get(review.review_id, [])
        if not peers:
            return 0.0, []
        return 1.0, peers  # 相似度已在上游归并时算过

    def cluster_of(self, review: Review) -> str:
        if review.device_hash:
            return self.device_clusters.get(review.device_hash, "")
        return ""


# ---------------------------------------------------------------- 维度①文本指纹


class TextFingerprint(Dimension):
    """模板化句式、批量雷同、无细节空泛好评。"""

    name = "文本指纹"
    weight = 0.20

    def score(self, review: Review, ctx: CorpusContext) -> DimensionResult:
        ev: List[str] = []
        text = review.content

        # 1) 空泛好评：泛化词命中密度高、实词密度低
        #    归一到「每 30 字的命中数」而非绝对命中数——
        #    一条 35 字的长评里出现一次「不错」是正常表达，不构成刷单证据。
        vague_hits = sum(1 for w in VAGUE_PRAISE if w in text)
        tokens = content_tokens(text)
        vague_density = vague_hits / max(len(text) / 30.0, 1.0)
        emptiness = max(0.0, 1.0 - len(tokens) / 12.0)   # 实词不足 → 空洞
        sub = min(1.0, 0.4 * vague_density + 0.4 * emptiness)
        if vague_hits >= 3:
            ev.append(f"含 {vague_hits} 处空泛好评套话")
        if emptiness > 0.6:
            ev.append("实词密度极低，疑似无真实使用细节")

        # 2) 模板化结构
        markers = sum(1 for m in TEMPLATE_MARKERS if m in text)
        if markers >= 2:
            sub = max(sub, 0.45)
            ev.append(f"出现 {markers} 个模板化结构标记")

        # 3) 与语料中其他条目的相似度（雷同 = 批量生成）
        peers = ctx.near_duplicates.get(review.review_id, [])
        if peers:
            sub = max(sub, 0.9)
            ev.append(f"与 {len(peers)} 条其他评价文本高度雷同（疑似同一批模板生成）")

        # 4) 正常长文含具体细节，不应被判高
        if len(tokens) >= 25 and not peers and vague_hits <= 1:
            sub = min(sub, 0.25)

        return DimensionResult(self.name, round(min(sub, 1.0), 4), ev)


# ---------------------------------------------------------------- 维度②账号行为


class AccountBehavior(Dimension):
    name = "账号行为"
    weight = 0.18

    def score(self, review: Review, ctx: CorpusContext) -> DimensionResult:
        ev: List[str] = []
        sub = 0.0

        age = review.account_age_days
        if age is not None and age < 30:
            sub = max(sub, 0.5)
            ev.append(f"账号注册仅 {age:.0f} 天")

        # 秒评 / 隔夜集中评
        hrs = review.hours_since_purchase
        if hrs is not None:
            if hrs < 1:
                sub = max(sub, 0.8)
                ev.append("购买后 1 小时内即评价（秒评）")
            elif hrs < 24:
                sub = max(sub, 0.35)
                ev.append("购买后 24 小时内评价，间隔偏短")

        # 跨品类刷评
        if review.review_category_count >= 5:
            sub = max(sub, 0.4)
            ev.append(f"历史评价横跨 {review.review_category_count} 个品类")

        # 只好评、无追评（正常用户使用一段时间后常有补充）
        if review.is_positive and not review.is_followup and review.author_review_count > 5:
            sub = max(sub, 0.25)
            ev.append("老账号只输出好评且无追评")

        # 加权：五星比四星更可疑（刷单集中在满分）
        if review.rating >= 4.9 and age is not None and age < 180:
            sub = max(sub, 0.3)
            ev.append("新账号给出满分评价")

        return DimensionResult(self.name, round(min(sub, 1.0), 4), ev)


# ---------------------------------------------------------------- 维度③多模态证据


class MultimodalEvidence(Dimension):
    name = "多模态证据"
    weight = 0.15

    def score(self, review: Review, ctx: CorpusContext) -> DimensionResult:
        ev: List[str] = []
        sub = 0.0
        media = review.media
        if not media:
            return DimensionResult(self.name, 0.0, ["纯文本，无多模态证据可校验"])

        for m in media:
            if m.kind == MediaKind.NONE:
                continue
            # 只晒包装，未进入真实使用场景
            if m.only_packaging:
                sub = max(sub, 0.5)
                ev.append("素材仅展示包装，未见真实使用场景")
            # 口播与画面脱节
            if m.script_visual_mismatch:
                sub = max(sub, 0.6)
                ev.append("口播文案与画面内容明显脱节")
            # 搬运重剪：同一素材指纹多次出现
            if m.media_hash:
                dup = sum(
                    1 for r in ctx.reviews
                    for o in r.media
                    if o.media_hash and o.media_hash == m.media_hash and r.review_id != review.review_id
                )
                if dup >= 2:
                    sub = max(sub, 0.75)
                    ev.append(f"素材指纹与另外 {dup} 条内容重复（疑似搬运重剪）")
            # 短视频但无任何真实使用痕迹
            if m.kind == MediaKind.VIDEO and not m.shows_usage and not m.only_packaging:
                sub = max(sub, 0.3)
                ev.append("视频未见真实使用痕迹")

        return DimensionResult(self.name, round(min(sub, 1.0), 4), ev)


# ---------------------------------------------------------------- 维度④关系图谱


class RelationGraph(Dimension):
    name = "关系图谱"
    weight = 0.20

    def score(self, review: Review, ctx: CorpusContext) -> DimensionResult:
        ev: List[str] = []
        cluster = ctx.cluster_of(review)

        # 同一设备指纹团伙：整组降权
        if cluster:
            size = sum(1 for r in ctx.reviews if ctx.cluster_of(r) == cluster)
            if size >= 3:
                return DimensionResult(
                    self.name, 0.85,
                    [f"与另外 {size - 1} 条评价共享同一设备/收货指纹（水军团伙）"],
                )

        same_addr = 0
        mutual = 0
        sub = 0.0

        # 同收货地址关联
        if review.address_hash:
            same_addr = sum(
                1 for r in ctx.reviews
                if r.address_hash and r.address_hash == review.address_hash
                and r.author_id != review.author_id
            )
            if same_addr >= 3:
                ev.append(f"{same_addr} 个不同账号使用同一收货地址指纹")
                sub = 0.6

        # 互相关注的账号集中好评（组织化水军）
        if review.follows:
            others = {r.author_id: r for r in ctx.reviews}
            for uid in review.follows:
                other = others.get(uid)
                if other and review.author_id in other.follows:
                    mutual += 1
            if mutual >= 3:
                ev.append(f"与 {mutual} 个互关账号同期好评，疑似有组织刷评")
                sub = max(sub, 0.55)

        return DimensionResult(self.name, round(sub, 4), ev)


# ---------------------------------------------------------------- 维度⑤时空聚集


class Spatiotemporal(Dimension):
    name = "时空聚集"
    weight = 0.14

    def score(self, review: Review, ctx: CorpusContext) -> DimensionResult:
        ev: List[str] = []
        sub = 0.0

        # 大促前夜集中好评：统计同商品 48h 内的评价密度
        #
        # 必须与该语料自身的基线密度比较，而不能用固定绝对阈值。
        # 语料整体较密时（如 100 条分布在 30 天，任一 48h 窗口本就有十几条），
        # 「48h 内 ≥5 条」这种阈值会把全部评价一网打尽，包括真实的。
        if ctx.reviews:
            posts = [r.posted_at for r in ctx.reviews]
            span_days = max((max(posts) - min(posts)).total_seconds() / 86400.0, 0.5)
            expected_48h = len(ctx.reviews) / span_days * 2.0

            window = [
                r for r in ctx.reviews
                if abs((r.posted_at - review.posted_at).total_seconds()) <= 172800
            ]
            floor = max(expected_48h * 3.0, 10.0)
            if len(window) > floor:
                ev.append(
                    f"48 小时内出现 {len(window)} 条评价，"
                    f"远超基线（预期约 {expected_48h:.0f} 条）"
                )
                sub = max(sub, 0.5)

        # 地理位置与物流不匹配
        if review.geo_mismatch:
            ev.append(f"评价定位 {review.geo} 与物流收货地 {review.logistics_geo} 不一致")
            sub = max(sub, 0.55)

        # 好评在极短时间窗内爆发（而非均匀到达）
        positives = sorted(
            r.posted_at for r in ctx.reviews
            if r.is_positive and abs((r.posted_at - review.posted_at).total_seconds()) <= 3600
        )
        if len(positives) >= 4:
            span = (positives[-1] - positives[0]).total_seconds() / 60.0
            if span <= 30:
                ev.append(f"{len(positives)} 条好评集中在 {span:.0f} 分钟内到达")
                sub = max(sub, 0.6)

        return DimensionResult(self.name, round(sub, 4), ev)


# ---------------------------------------------------------------- 维度⑥激励链路


class IncentiveChain(Dimension):
    name = "激励链路"
    weight = 0.13

    def score(self, review: Review, ctx: CorpusContext) -> DimensionResult:
        ev: List[str] = []
        sub = 0.0

        for rx in INCENTIVE_RE:
            if rx.search(review.content):
                ev.append(f"命中返现/诱导话术：{rx.pattern}")
                sub = max(sub, 0.85)
                break

        if review.incentive_card:
            ev.append("平台已标记「好评返现」卡片")
            sub = max(sub, 0.9)

        return DimensionResult(self.name, round(sub, 4), ev)


DEFAULT_DIMENSIONS: List[Dimension] = [
    TextFingerprint(),
    AccountBehavior(),
    MultimodalEvidence(),
    RelationGraph(),
    Spatiotemporal(),
    IncentiveChain(),
]


# ---------------------------------------------------------------- 清洗器


class AntifraudCleaner:
    """六维交叉打分 → 可信权重 → 三池分流。"""

    def __init__(self, dimensions: Sequence[Dimension] = None,
                 trust_threshold: float = 0.45,
                 reject_threshold: float = 0.75) -> None:
        """
        trust_threshold: 可信权重低于此值 → 存疑池
        reject_threshold: 可信权重低于此值 → 剔除池
        """
        self.dimensions = list(dimensions or DEFAULT_DIMENSIONS)
        self.trust_threshold = trust_threshold
        self.reject_threshold = reject_threshold

    # -- 语料级预处理 ------------------------------------------------

    def _build_context(self, reviews: List[Review]) -> CorpusContext:
        ctx = CorpusContext(reviews=list(reviews))

        # 文本雷同：两两比较（语料规模有限，用 O(n²) 换取实现简洁与确定性）
        grams = {r.review_id: shingles(r.content, 3) for r in reviews}
        dup_threshold = 0.72
        for i, a in enumerate(reviews):
            for b in reviews[i + 1:]:
                sim = jaccard(grams[a.review_id], grams[b.review_id])
                if sim >= dup_threshold:
                    ctx.near_duplicates[a.review_id].append(b.review_id)
                    ctx.near_duplicates[b.review_id].append(a.review_id)

        # 设备/地址指纹聚类：出现 >= 3 次的指纹才认定为团伙，避免误伤家庭共用地址
        counts: Dict[str, int] = defaultdict(int)
        for r in reviews:
            if r.device_hash:
                counts[r.device_hash] += 1
        for r in reviews:
            if r.device_hash and counts[r.device_hash] >= 3:
                ctx.device_clusters[r.device_hash] = r.device_hash

        return ctx

    # -- 主流程 ----------------------------------------------------

    def clean(self, reviews: List[Review]) -> List[CleaningResult]:
        ctx = self._build_context(reviews)
        results = [self._clean_one(r, ctx) for r in reviews]
        return results

    def _clean_one(self, review: Review, ctx: CorpusContext) -> CleaningResult:
        dims = [d.score(review, ctx) for d in self.dimensions]

        # 加权平均得到综合可疑度
        total_w = sum(d.weight for d in self.dimensions) or 1.0
        suspicion = sum(d.suspicion * d.weight for d in self.dimensions) / total_w

        # 强信号直达：任一维度极高可疑时直接压制，避免被其余维度平均稀释
        for d in dims:
            if d.suspicion >= 0.9:
                suspicion = max(suspicion, d.suspicion)

        trusted_weight = round(max(0.0, 1.0 - suspicion), 4)

        if trusted_weight < self.reject_threshold:
            verdict = Verdict.REJECTED
        elif trusted_weight < self.trust_threshold:
            verdict = Verdict.DOUBTED
        else:
            verdict = Verdict.TRUSTED

        notes = [f"{d.name}：{d.suspicion:.2f}" for d in dims if d.suspicion > 0]
        return CleaningResult(
            review=review,
            dimensions=dims,
            trusted_weight=trusted_weight,
            verdict=verdict,
            notes=notes,
        )


__all__ = [
    "AntifraudCleaner",
    "CorpusContext",
    "Dimension",
    "TextFingerprint",
    "AccountBehavior",
    "MultimodalEvidence",
    "RelationGraph",
    "Spatiotemporal",
    "IncentiveChain",
    "DEFAULT_DIMENSIONS",
]