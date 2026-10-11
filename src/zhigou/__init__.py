"""智购参谋 · AI 购物决策副驾驶。

四步闭环：解析商品 → 聚合口碑 → 清洗真伪 → 给出决策
六道防线：采集保真 → 六维反作弊 → 多源交叉验证 → 链上存证 → 可信度量化 → 监控回流

核心原则：一份基于虚假好评的完整报告，比没有报告更危险。
因此系统在「不确定」时主动降级为「信息有限，建议观望」，
而不是硬给一个看起来很完整但不可信的分数。
"""

from .models import (
    Attestation,
    Claim,
    CleaningResult,
    Platform,
    Product,
    Review,
    ShoppingReport,
    Snapshot,
    Verdict,
)
from .pipeline import Pipeline, PipelineConfig
from .collectors import TaskParameter, SimulatedCollector, HttpCollector
from .report import render_text, render_html

__version__ = "0.1.0"

__all__ = [
    "Pipeline",
    "PipelineConfig",
    "TaskParameter",
    "SimulatedCollector",
    "HttpCollector",
    "render_text",
    "render_html",
    "Platform",
    "Product",
    "Review",
    "Snapshot",
    "Verdict",
    "CleaningResult",
    "Claim",
    "Attestation",
    "ShoppingReport",
    "__version__",
]