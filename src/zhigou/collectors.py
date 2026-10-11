"""防线一：采集保真 —— 数据从源头就固定。

本模块提供采集器接口与两个实现：
  - `SimulatedCollector`：内置确定性模拟数据，无需网络即可跑通全链路
  - `HttpCollector`：真实采集器骨架，封装 robots 检查、限速与快照固化

**防投毒隔离**：用户提交的内容（链接、描述）只作为 `task_parameter` 传给采集器，
绝不拼进任何提示词或参与模型推理。真实实现里若引入 LLM，此边界必须保持。
"""

from __future__ import annotations

import json
import random
import re
import time
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .models import (
    MediaEvidence,
    MediaKind,
    Platform,
    Product,
    Review,
    Snapshot,
    utcnow,
)

# ---------------------------------------------------------------- 采集器接口


@dataclass
class TaskParameter:
    """任务参数。**用户输入只允许以这个形态进入系统。**

    这是防线四「防投毒隔离」的架构落点：参数与数据严格分离，
    任何 `content` 字段都不参与模型提示构造。
    """

    task_id: str
    product_id: str
    target_platforms: List[Platform] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)


class Collector(ABC):
    """采集器接口。实现者必须对每条产出调用 `Snapshot` 固化。"""

    name = "base"

    @abstractmethod
    def fetch_product(self, task: TaskParameter) -> Optional[Product]:
        ...

    @abstractmethod
    def fetch_reviews(self, task: TaskParameter) -> List[Review]:
        ...


# ---------------------------------------------------------------- 快照固化


def freeze(text: str, *, collector: str, source_url: str = "",
           content_type: str = "text/plain", at: Optional[datetime] = None) -> Snapshot:
    """把采集到的原始文本固化为不可变快照。"""
    return Snapshot(
        content=text,
        collected_at=at or utcnow(),
        collector=collector,
        content_type=content_type,
        source_url=source_url,
    )


# ---------------------------------------------------------------- HTTP 采集器

ROBOTS_CACHE: Dict[str, str] = {}


class HttpCollector(Collector):
    """真实采集器骨架。

    已内置的合规约束：
      - 遵循 robots.txt
      - 默认限速 1 请求 / 2 秒
      - 内容一律经 `freeze()` 固化

    尚未实现（需按平台逐一适配，且必须评估法律边界）：
      - 登录态与反爬对抗
      - 各平台页面结构解析
    """

    name = "http"

    def __init__(self, user_agent: str = "ZhigouBot/0.1 (+https://example.com/bot)",
                 delay: float = 2.0, timeout: float = 10.0,
                 obey_robots: bool = True) -> None:
        self.user_agent = user_agent
        self.delay = delay
        self.timeout = timeout
        self.obey_robots = obey_robots
        self._last_request_at = 0.0

    # -- robots ----------------------------------------------------

    @staticmethod
    def _robots_allows(url: str) -> bool:
        parts = urllib.parse.urlparse(url)
        robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
        if robots_url not in ROBOTS_CACHE:
            try:
                req = urllib.request.Request(robots_url, headers={"User-Agent": "ZhigouBot"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    ROBOTS_CACHE[robots_url] = resp.read().decode("utf-8", "replace")
            except Exception:
                ROBOTS_CACHE[robots_url] = ""   # 取不到视为不限制，但调用方应知晓
        rules = ROBOTS_CACHE[robots_url]
        if not rules:
            return True
        path = parts.path or "/"
        for line in rules.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("disallow:"):
                blocked = line.split(":", 1)[1].strip()
                if blocked and path.startswith(blocked):
                    return False
        return True

    # -- 请求 ------------------------------------------------------

    def _get(self, url: str) -> Optional[str]:
        if self.obey_robots and not self._robots_allows(url):
            raise PermissionError(f"robots.txt 禁止抓取：{url}")

        elapsed = time.time() - self._last_request_at
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)

        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                body = resp.read().decode(charset, "replace")
        except Exception:
            return None
        finally:
            self._last_request_at = time.time()
        return body

    def fetch_product(self, task: TaskParameter) -> Optional[Product]:
        url = task.params.get("product_url", "")
        if not url:
            return None
        body = self._get(url)
        if body is None:
            return None
        freeze(body, collector=self.name, source_url=url, content_type="text/html")
        # 解析逻辑按平台实现，此处保留接口
        return None

    def fetch_reviews(self, task: TaskParameter) -> List[Review]:
        # 真实实现需按平台适配解析；此处不臆造解析规则
        return []


# ---------------------------------------------------------------- 模拟采集器


_PLATFORM_MIX = [
    Platform.TAOBAO, Platform.JD,
    Platform.XIAOHONGSHU, Platform.DOUYIN, Platform.BILIBILI, Platform.ZHIHU,
]

# --------------------------------------------------------------------------
# 真实评价的文本生成
#
# 刻意用「片段组合」而不是从一个固定句库里随机抽取。
# 后者会导致同一条文案在语料中重复出现多次，进而被雷同检测正确地判为刷单——
# 那样模拟器就在制造假阳性，既不真实，也会掩盖真正的检测缺陷。
# 组合空间足够大（数百种），真实评价之间不会产生高相似度。
# --------------------------------------------------------------------------

_POS_OPENING = [
    "用了两个月", "入手快三个月了", "买回来用了半个月", "上手一周有余",
    "用了大半年", "作为主力耳机用了两个月", "刚到货没几天", "断续用了三周",
]
_POS_DETAIL = [
    "续航确实扎实，出差一周不用充电，日常够用",
    "做工比想象中细腻，边缘没有毛刺，放口袋里刮花不明显",
    "屏幕素质不错，看电影 HDR 效果自然，户外亮度也够看",
    "充电速度很快，早上洗漱的时间能充进去大半",
    "噪音控制做得好，放在床头几乎听不到风扇声，晚上睡觉不受影响",
    "佩戴舒服，耳压感很轻，长时间戴着也不闷",
    "重量控制得不错，单手能握，夹在脖子上也不会觉得沉",
    "通话降噪超出预期，地铁上对方听不清环境噪音",
    "连接稳定，蓝牙在十米内没有断流，切手机也很顺畅",
    "app 调节均衡器很直观，eq 可以存好几组预设",
]
_POS_TAIL = [
    "总体来说这个价位挺值的",
    "同价位里我觉得算稳的",
    "会考虑给家人再买一个",
    "日常通勤完全够用了",
    "推荐给在意佩戴感的同学",
]

_NEG_OPENING = [
    "用了一个月", "买回来三个月", "用了两周", "上手一个多月",
    "用了小半年", "刚开始还挺满意，后来", "作为主力用了两个月",
]
_NEG_DETAIL = [
    "开始发热，打游戏的时候烫手，影响使用体验",
    "续航没有宣传的好，标称五千毫安实际撑不到一天，得中午补电",
    "做工一般，边框有细微毛刺，按键手感偏硬，长期用有点累",
    "用久了掉漆，底部的保护套磨损很快，两个星期就磨出痕",
    "屏幕有暗角，边缘发红，客服说是正常现象，但我还是不满意",
    "风扇噪音大，高负载的时候声音明显，影响室友休息",
    "容量虚标，系统显示的可用空间比标称少了一个多 G",
    "包装简陋，快递箱破损，倒出来外壳已经有磕碰",
    "充电口接触不良，有时候要反复插拔才认得出来",
    "降噪开了反而有压迫感，耳鸣的时候不太舒服",
]
_NEG_TAIL = [
    "总结来说不太推荐",
    "花这个价有点不值",
    "有点后悔没多看看别的牌子",
    "客服态度还行，但解决不了问题",
    "希望后续固件能改善一下",
]

_FOLLOWUP_OPENING = [
    "用了三个月回来追评", "用了半年补一条评价", "时隔四个月追加反馈",
    "用了两个月后的补充说明",
]
_FOLLOWUP_DETAIL = [
    "之前的担心多余了，现在依然稳定，续航衰减不明显",
    "发热问题在更新系统后改善了不少，之前确实烫得受不了",
    "品控确实一般，同批次里我那个出现了屏幕坏点",
    "佩戴体验比刚上手时更好，磨合期过了之后贴合度高很多",
    "电池健康度掉到九成左右，续航从一周变成五天",
    "客服主动联系过，做了妥善处理，这点要给个好评",
]
_FOLLOWUP_TAIL = [
    "所以当初的选择现在依然不后悔",
    "综合下来还是给四星",
    "写给后面想买的人做个参考",
    "希望后续能继续优化",
    "总的来说是越用越顺手",
]

# 刷单模板：高度雷同、空泛、诱导。前两条各出现两次以触发雷同检测
_FAKE_TEMPLATES = [
    "宝贝很好，五星好评，物流很快，客服也nice，下次还会来买的！",
    "质量很好，物流很快，客服态度好，无脑推荐，闭眼入不踩雷！",
    "宝贝很好，五星好评，物流很快，客服也nice，下次还会来买的！",
    "质量很好，物流很快，客服态度好，无脑推荐，闭眼入不踩雷！",
]


def _compose(rng: random.Random, openings: List[str],
             details: List[str], tails: List[str]) -> str:
    """组合出一条真实评价。

    8 × 10 × 5 = 400 种组合，足以让 60 条样本互不雷同，
    避免模拟器自己制造出本该只存在于刷单里的「批量复制」特征。
    """
    return "，".join([
        rng.choice(openings),
        rng.choice(details),
        rng.choice(tails) + "。",
    ])


class SimulatedCollector(Collector):
    """确定性模拟数据源。

    用固定随机种子生成**可复现**的语料——同一 seed 必得同一结果，
    这是指标体系里「复现一致性」的前提，也便于回归测试。

    刻意混入四类噪声：模板刷单、设备团伙、返现诱导、差评被控。
    """

    name = "simulated"

    def __init__(self, seed: int = 20261011, authentic_count: int = 60) -> None:
        self.seed = seed
        self.authentic_count = authentic_count
        self._rng = random.Random(seed)
        self._clock = datetime(2026, 10, 1, 9, 0, 0)

    def _tick(self) -> datetime:
        self._clock += timedelta(minutes=self._rng.randint(40, 900))
        return self._clock

    def fetch_product(self, task: TaskParameter) -> Product:
        return Product(
            product_id=task.product_id,
            title="星海 X7 无线降噪耳机",
            price=799.0,
            shop="星海官方旗舰店",
            categories=["3C数码", "耳机"],
            attrs={
                "续航": "单次 40 小时",
                "降噪": "深度降噪",
                "重量": "轻便",
            },
            source_url=f"https://example-shop.com/item/{task.product_id}",
        )

    def fetch_reviews(self, task: TaskParameter) -> List[Review]:
        rng = self._rng
        reviews: List[Review] = []
        rid = 0

        def next_id() -> str:
            nonlocal rid
            rid += 1
            return f"rev-{rid:04d}"

        # --- 真实好评 ---
        for _ in range(self.authentic_count):
            platform = rng.choice(_PLATFORM_MIX)
            posted = self._tick()
            content = _compose(rng, _POS_OPENING, _POS_DETAIL, _POS_TAIL)
            has_media = rng.random() < 0.3
            reviews.append(Review(
                review_id=next_id(),
                platform=platform,
                author_id=f"user-{rng.randint(1000, 9999)}",
                content=content,
                rating=rng.choice([4.0, 4.5, 5.0, 5.0]),
                posted_at=posted,
                purchased_at=posted - timedelta(hours=rng.randint(48, 400)),
                is_followup=rng.random() < 0.15,
                account_created_at=posted - timedelta(days=rng.randint(400, 3000)),
                author_review_count=rng.randint(5, 200),
                review_category_count=rng.randint(1, 4),
                geo=rng.choice(["北京", "上海", "广州", "成都"]),
                logistics_geo=rng.choice(["北京", "上海", "广州", "成都"]),
                media=[MediaEvidence(
                    kind=MediaKind.IMAGE if has_media else MediaKind.NONE,
                    media_hash=f"mh-{rng.randint(1, 999)}" if has_media else "",
                    shows_usage=has_media,
                )] if has_media else [],
                snapshot=freeze(content, collector=self.name),
            ))

        # --- 真实差评 ---
        for _ in range(self.authentic_count // 3):
            platform = rng.choice(_PLATFORM_MIX)
            posted = self._tick()
            content = _compose(rng, _NEG_OPENING, _NEG_DETAIL, _NEG_TAIL)
            reviews.append(Review(
                review_id=next_id(),
                platform=platform,
                author_id=f"user-{rng.randint(1000, 9999)}",
                content=content,
                rating=rng.choice([1.0, 2.0, 2.5, 3.0]),
                posted_at=posted,
                purchased_at=posted - timedelta(hours=rng.randint(48, 500)),
                is_followup=rng.random() < 0.25,
                account_created_at=posted - timedelta(days=rng.randint(300, 2800)),
                author_review_count=rng.randint(8, 150),
                review_category_count=rng.randint(1, 5),
                geo=rng.choice(["北京", "上海", "广州", "成都"]),
                logistics_geo=rng.choice(["北京", "上海", "广州", "成都"]),
                snapshot=freeze(content, collector=self.name),
            ))

        # --- 追评（天然难刷，权重高于首评）---
        for _ in range(6):
            posted = self._tick()
            content = _compose(rng, _FOLLOWUP_OPENING, _FOLLOWUP_DETAIL, _FOLLOWUP_TAIL)
            reviews.append(Review(
                review_id=next_id(),
                platform=rng.choice(_PLATFORM_MIX),
                author_id=f"user-{rng.randint(1000, 9999)}",
                content=content,
                rating=rng.choice([3.0, 4.0, 5.0]),
                posted_at=posted,
                purchased_at=posted - timedelta(days=rng.randint(60, 100)),
                is_followup=True,
                account_created_at=posted - timedelta(days=rng.randint(800, 3000)),
                author_review_count=rng.randint(20, 300),
                review_category_count=rng.randint(1, 3),
                snapshot=freeze(content, collector=self.name),
            ))

        # --- 噪声①：模板刷单（文本雷同 + 空泛 + 新号 + 秒评）---
        shared_device = "dev-GANG-01"
        for i, tpl in enumerate(_FAKE_TEMPLATES):
            posted = self._tick()
            reviews.append(Review(
                review_id=next_id(),
                platform=Platform.TAOBAO,
                author_id=f"bot-{i:03d}",
                content=tpl,
                rating=5.0,
                posted_at=posted,
                purchased_at=posted - timedelta(minutes=rng.randint(2, 40)),  # 秒评
                account_created_at=posted - timedelta(days=rng.randint(1, 20)),  # 新号
                author_review_count=rng.randint(1, 3),
                review_category_count=rng.randint(6, 9),   # 跨品类
                device_hash=shared_device,                  # 同一设备团伙
                address_hash="addr-GANG-01",
                snapshot=freeze(tpl, collector=self.name),
            ))

        # --- 噪声②：返现诱导 ---
        for i, text in enumerate([
            "晒图返现 20 块，加微信领红包，秒回好评",
            "五星截图发客服领优惠券，确认收货返现",
            "接单群 专业好评 有需要私聊",
        ]):
            posted = self._tick()
            reviews.append(Review(
                review_id=next_id(),
                platform=Platform.TAOBAO,
                author_id=f"cash-{i:03d}",
                content=text,
                rating=5.0,
                posted_at=posted,
                purchased_at=posted - timedelta(hours=rng.randint(2, 20)),
                account_created_at=posted - timedelta(days=rng.randint(2, 30)),
                incentive_card=True,
                snapshot=freeze(text, collector=self.name),
            ))

        # --- 噪声③：搬运重剪（同一素材多次出现）---
        shared_media = "mhash-DUPE-777"
        for i in range(3):
            posted = self._tick()
            content = "开箱体验，颜值真的高，戴着很舒服，续航也不错。"
            reviews.append(Review(
                review_id=next_id(),
                platform=Platform.DOUYIN,
                author_id=f"dup-{i:03d}",
                content=content,
                rating=5.0,
                posted_at=posted,
                account_created_at=posted - timedelta(days=rng.randint(30, 200)),
                media=[MediaEvidence(
                    kind=MediaKind.VIDEO,
                    media_hash=shared_media,
                    shows_usage=False,
                    script_visual_mismatch=True,
                )],
                snapshot=freeze(content, collector=self.name),
            ))

        # --- 噪声④：异地刷（评价地 ≠ 物流地 + 好评突发聚集）---
        burst_base = self._tick()
        for i in range(5):
            posted = burst_base + timedelta(minutes=i * 4)   # 20 分钟内 5 条好评
            content = "确实不错，推荐购买，物流很快。"
            reviews.append(Review(
                review_id=next_id(),
                platform=Platform.JD,
                author_id=f"far-{i:03d}",
                content=content,
                rating=5.0,
                posted_at=posted,
                account_created_at=posted - timedelta(days=rng.randint(5, 60)),
                geo="乌鲁木齐",
                logistics_geo="深圳",
                snapshot=freeze(content, collector=self.name),
            ))

        return reviews


# ---------------------------------------------------------------- 注册表

COLLECTORS: Dict[str, type] = {
    "simulated": SimulatedCollector,
    "http": HttpCollector,
}


def get_collector(name: str, **kwargs) -> Collector:
    if name not in COLLECTORS:
        raise KeyError(f"未知采集器：{name}，可选：{list(COLLECTORS)}")
    return COLLECTORS[name](**kwargs)


__all__ = [
    "TaskParameter",
    "Collector",
    "HttpCollector",
    "SimulatedCollector",
    "COLLECTORS",
    "get_collector",
    "freeze",
]