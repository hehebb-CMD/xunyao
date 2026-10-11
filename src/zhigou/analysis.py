"""评价情感极性与观点聚合。

情感分析采用词典 + 否定 + 程度副词的规则法。理由很务实：
  - 零外部依赖，可离线运行，结果确定可复现（指标体系要求「复现一致性」）
  - 规则法的缺陷是领域漂移，但本场景的评价语料高度口语化且领域集中，
    词典覆盖度比通用模型更可控

若要升级为模型，只需替换 `SentimentAnalyzer.analyze`，其余流水线不受影响。
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import Claim, Platform, Review, CleaningResult, Verdict

# ---------------------------------------------------------------- 情感词典

POSITIVE_WORDS = {
    "好": 1.0, "很好": 1.5, "不错": 1.0, "优秀": 2.0, "满意": 1.2, "喜欢": 1.3,
    "推荐": 1.2, "划算": 1.3, "性价比": 1.2, "超值": 1.6, "惊艳": 2.0,
    "方便": 1.0, "流畅": 1.3, "清晰": 1.1, "结实": 1.2, "耐用": 1.4,
    "轻便": 1.1, "舒适": 1.3, "安静": 1.2, "省心": 1.3, "贴心": 1.2,
    "给力": 1.5, "良心": 1.5, "靠谱": 1.5, "物美价廉": 1.8, "质量好": 1.5,
    "颜值高": 1.4, "手感好": 1.3, "速度快": 1.2, "续航强": 1.4, "散热好": 1.2,
    "做工好": 1.4, "颜值高": 1.4, "手感好": 1.3, "充电快": 1.3, "屏幕清晰": 1.4,
}

NEGATIVE_WORDS = {
    "差": 1.2, "很差": 1.8, "糟糕": 2.0, "失望": 1.6, "后悔": 1.8,
    "垃圾": 2.0, "坑": 1.6, "智商税": 2.0, "不值": 1.6, "亏": 1.4,
    "贵": 0.8, "卡": 1.2, "卡顿": 1.5, "发热": 1.4, "烫手": 1.6,
    "掉漆": 1.3, "异味": 1.5, "噪": 1.2, "吵": 1.3, "漏电": 2.0,
    "破损": 1.8, "坏": 1.6, "坏了": 1.8, "故障": 1.8, "退货": 1.5,
    "售后差": 1.9, "客服差": 1.7, "拖延": 1.3, "欺骗": 2.0, "虚假": 1.8,
    "货不对板": 2.0, "以次充好": 2.0, "偷工减料": 1.8, "做工粗糙": 1.6,
    "续航差": 1.6, "掉电快": 1.5, "屏幕差": 1.3, "手感差": 1.3,
}

NEGATIONS = {"不", "没", "没有", "无", "别", "莫", "未", "非", "不太", "不是很", "并不"}

DEGREE_WORDS = {
    "非常": 1.5, "特别": 1.5, "很": 1.3, "超": 1.4, "极其": 1.8, "太": 1.4,
    "有点": 0.6, "稍微": 0.5, "略": 0.5, "比较": 0.8, "还算": 0.7,
}

# 观点聚合的主题词典：把自由文本映射到可比较的「卖点/槽位」
ASPECT_LEXICON: Dict[str, Set[str]] = {
    "续航": {"续航", "电池", "电量", "待机", "充电"},
    "发热": {"发热", "烫", "散热", "温度", "过热"},
    "屏幕": {"屏幕", "显示", "分辨率", "刷新率", "色彩"},
    "做工": {"做工", "用料", "质感", "品控", "工艺"},
    "售后": {"售后", "客服", "退货", "换货", "维修"},
    "物流": {"物流", "发货", "快递", "配送", "到货"},
    "性价比": {"性价比", "划算", "价格", "便宜", "贵", "值"},
    "噪音": {"噪音", "噪声", "吵", "安静", "异响"},
    "外观": {"外观", "颜值", "设计", "好看", "丑"},
    "手感": {"手感", "手感好", "握持", "重量", "便携"},
    "包装": {"包装", "盒", "快递箱", "破损"},
    "水印": {"水印", "漏光", "坏点", "亮点"},
    "卡顿": {"卡顿", "卡", "流畅", "死机", "闪退"},
    "容量": {"容量", "内存", "存储", "空间"},
}

_PUNCT = re.compile(r"[，。！？；：、,.!?;:\s~…]+")
_TOKEN_SPLIT = re.compile(r"[,，。;；:：、\s]+")


# ---------------------------------------------------------------- 情感


@dataclass
class SentimentResult:
    polarity: float          # -1.0（负面）~ +1.0（正面）
    score: float             # 原始加权得分，便于展示
    matched_pos: List[str] = field(default_factory=list)
    matched_neg: List[str] = field(default_factory=list)
    aspects: List[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.polarity >= 0.3:
            return "正面"
        if self.polarity <= -0.3:
            return "负面"
        return "中性"

    @property
    def is_polarized(self) -> bool:
        return abs(self.polarity) >= 0.3


class SentimentAnalyzer:
    def __init__(
        self,
        positive: Dict[str, float] = None,
        negative: Dict[str, float] = None,
    ) -> None:
        self.positive = dict(POSITIVE_WORDS) if positive is None else positive
        self.negative = dict(NEGATIVE_WORDS) if negative is None else negative

    def analyze(self, text: str) -> SentimentResult:
        pos, neg = self._score_terms(text)
        pos_score = sum(pos.values())
        neg_score = sum(neg.values())
        total = pos_score + neg_score

        if total == 0:
            polarity = 0.0
        else:
            # 以负面为分母，让「零星负面」的惩罚大于「零星正面」的加分：
            # 差评比好评更值得被报告指出。
            polarity = (pos_score - neg_score) / max(pos_score + neg_score, 1e-6)
            polarity = max(-1.0, min(1.0, polarity))

        aspects = self._aspects(text)
        return SentimentResult(
            polarity=polarity,
            score=pos_score - neg_score,
            matched_pos=[w for w, _ in sorted(pos.items(), key=lambda x: -x[1])],
            matched_neg=[w for w, _ in sorted(neg.items(), key=lambda x: -x[1])],
            aspects=aspects,
        )

    def _score_terms(self, text: str) -> Tuple[Dict[str, float], Dict[str, float]]:
        pos: Dict[str, float] = {}
        neg: Dict[str, float] = {}

        # 长词优先匹配，避免「很好」被「好」抢先命中而丢失程度信息
        for lexicon, sink in ((self.positive, pos), (self.negative, neg)):
            for word in sorted(lexicon, key=len, reverse=True):
                start = 0
                while True:
                    idx = text.find(word, start)
                    if idx < 0:
                        break
                    weight = lexicon[word]
                    prefix = text[max(0, idx - 3):idx]
                    flipped = False
                    for neg in NEGATIONS:
                        if neg in prefix:
                            flipped = True
                            break
                    deg = 1.0
                    for d, dw in DEGREE_WORDS.items():
                        if d in prefix:
                            deg = dw
                            break
                    val = weight * deg * (-1.0 if flipped else 1.0)
                    # 否定翻转后归入相反极性桶
                    if flipped:
                        other = neg if sink is pos else pos
                        other[word] = other.get(word, 0.0) + abs(val)
                    else:
                        sink[word] = sink.get(word, 0.0) + val
                    start = idx + len(word)
        return pos, neg

    @staticmethod
    def _aspects(text: str) -> List[str]:
        return [name for name, words in ASPECT_LEXICON.items() if any(w in text for w in words)]

    def analyze_bulk(self, texts: Sequence[str]) -> List[SentimentResult]:
        return [self.analyze(t) for t in texts]


# ---------------------------------------------------------------- 观点聚合


class ClaimAggregator:
    """把散落的评价聚合成可比较的结论（优点 / 缺点 / 争议点）。

    每条结论的权重是**可信权重之和**而非简单计数——
    一条刷单好评和一条真实好评不应该贡献同样的分量。
    """

    def __init__(self, sentiment: SentimentAnalyzer = None,
                 min_evidence: int = 2) -> None:
        self.sentiment = sentiment or SentimentAnalyzer()
        self.min_evidence = min_evidence

    def aggregate(
        self,
        results: List[CleaningResult],
    ) -> Tuple[List[Claim], List[Claim], List[Claim]]:
        """返回 (优点, 缺点, 争议点)。"""
        buckets: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        evidence: Dict[str, List[str]] = defaultdict(list)
        platforms: Dict[str, Set[Platform]] = defaultdict(set)

        for cr in results:
            # 只让可信评价进入结论；存疑与剔除池仅保留证据供复核
            if cr.verdict != Verdict.TRUSTED:
                continue
            r = cr.review
            sent = self.sentiment.analyze(r.content)
            if not sent.is_polarized and r.rating == 3.0:
                # 中性且三星：不表达明确观点，跳过
                continue
            aspect = sent.aspects[0] if sent.aspects else "其他"
            buckets[aspect][sent.polarity] += cr.trusted_weight
            buckets[aspect].setdefault("_total", 0.0)
            buckets[aspect]["_total"] += cr.trusted_weight
            evidence[aspect].append(r.review_id)
            platforms[aspect].add(r.platform)

        pros: List[Claim] = []
        cons: List[Claim] = []
        contested: List[Claim] = []

        for aspect, scores in buckets.items():
            total = scores.get("_total", 0.0)
            if total < self.min_evidence:
                continue
            pos_w = scores.get(1.0, 0.0)
            neg_w = scores.get(-1.0, 0.0)

            groups = {platforms[aspect]}
            claim_base = {
                "text": aspect,
                "weight": round(total, 4),
                "platforms": sorted(platforms[aspect], key=lambda p: p.value),
                "evidence_ids": evidence[aspect],
                "independence_groups": sorted(g.independence_group for g in groups),
            }

            balance = (pos_w - neg_w) / max(total, 1e-6)
            if abs(balance) < 0.25 and total >= self.min_evidence * 2:
                contested.append(Claim(
                    polarity="contested", tag="两极分化",
                    independent_source_count=len(claim_base["independence_groups"]),
                    **{k: claim_base[k] for k in ("text", "weight", "platforms", "evidence_ids")},
                ))
            elif balance >= 0:
                pros.append(Claim(
                    polarity="pro", independent_source_count=len(claim_base["independence_groups"]),
                    **{k: claim_base[k] for k in ("text", "weight", "platforms", "evidence_ids")},
                ))
            else:
                cons.append(Claim(
                    polarity="con", independent_source_count=len(claim_base["independence_groups"]),
                    **{k: claim_base[k] for k in ("text", "weight", "platforms", "evidence_ids")},
                ))

        pros.sort(key=lambda c: -c.weight)
        cons.sort(key=lambda c: -c.weight)
        contested.sort(key=lambda c: -c.weight)
        return pros, cons, contested


__all__ = ["SentimentAnalyzer", "SentimentResult", "ClaimAggregator", "ASPECT_LEXICON"]