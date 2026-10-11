# 智购参谋 · 代码实现

《「智购参谋」项目最终方案 V2.0》的可运行实现。四步闭环 + 六道防线。

> **重要**：本机没有可用的 Python 运行时，代码**未经执行验证**。
> 所有核心逻辑仅用标准库编写，装好 Python 即可运行。详见下方「运行」。

---

## 快速开始

```bash
cd zhigou

# 1) 跑测试
python -m unittest discover -s tests -v

# 2) 生成一份报告（内置模拟语料，无需网络）
python -m zhigou run --product X7-001

# 3) 输出 HTML / JSON 交付物
python -m zhigou run --product X7-001 --html report.html --json report.json

# 4) 校验存证
python -m zhigou audit
```

无需 `pip install`，`src` 已在测试与运行路径中。
若想安装为命令：`pip install -e .` 后可用 `zhigou run --product X7-001`。

---

## 架构对应关系

| 文档章节 | 代码位置 | 说明 |
|---|---|---|
| 四步闭环 | `pipeline.py::Pipeline.run` | 解析 → 聚合 → 清洗 → 决策 |
| 防线一 采集保真 | `collectors.py::freeze`、`models.py::Snapshot` | 采集即快照 + SHA-256 固化 |
| 防线二 六维反作弊 | `antifraud.py` | 六个 `Dimension` 子类交叉打分 |
| 防线三 多源交叉验证 | `trust.py::CrossValidator` | 独立信源判定 + 孤证降权 + 权威锚点 |
| 防线四 链上存证 | `attestation.py` | 默克尔树 + 哈希链账本 + 验证路径 |
| 防线五 可信度量化 | `trust.py::TrustQuantifier` | 含「信息有限」主动降级 |
| 防线六 监控回流 | `trust.py::ReputationMonitor` | 口碑突变 + 回访纠错 |
| 技术架构 3.3 | `collectors.py` / `analysis.py` / `attestation.py` | 采集 / 分析 / 存证三层 |

---

## 六维反作弊如何实现

每个维度返回 0–1 的可疑度，加权求和得综合分 → 可信权重 → 三池分流。

| 维度 | 类 | 核心信号 |
|---|---|---|
| ① 文本指纹 | `TextFingerprint` | 中文 3-gram Jaccard 雷同聚类、空泛好评词表、模板化结构标记 |
| ② 账号行为 | `AccountBehavior` | 账号注册时长、购买-评价间隔、跨品类集中度、是否只好评无追评 |
| ③ 多模态证据 | `MultimodalEvidence` | 素材指纹重复（搬运重剪）、口播画面脱节、只晒包装未使用 |
| ④ 关系图谱 | `RelationGraph` | 设备/地址指纹聚类、互关账号同期好评 |
| ⑤ 时空聚集 | `Spatiotemporal` | 48h 评价密度异常、短时好评爆发、评价地与物流地不一致 |
| ⑥ 激励链路 | `IncentiveChain` | 返现话术正则集、平台「好评返现」卡片标记 |

两个刻意的设计选择：

**1. 阈值分流而非删除。** 可信权重 < 0.45 → 存疑池，< 0.75 → 剔除池。
存疑的评价**不销毁**，保留证据供商家申诉与用户复核。误伤真实评价的代价高于放过一条可疑评价。

**2. 强信号直达，不被平均稀释。** 任一维度可疑度 ≥ 0.9 时直接压制总分。
否则「激励链路 1.0 + 账号行为 0.9」会被其余四个维度的低分平均掉，刷单就漏了。

---

## 关键设计决策

### 交叉验证的「独立」判定

同一集团下的平台**不算独立信源**（`Platform.independence_group`）：
淘宝/天猫同属 `alibaba`，京东自营同属 `jd`。

若把它们当两个独立信源，会把「一条说辞被两个渠道复制」误判成「两个来源共同印证」——
这是交叉验证最容易犯也最致命的错误。

### 信源不足时主动降级

`TrustQuantifier` 在可信评价 < 20 条或独立信源 < 2 个时，返回
`level = "信息有限"`，而不是硬凑一个分数。

> 宁可输出「信息不足」，也不输出「看似完整但不可信」的报告。

### 购买建议只用被印证过的结论

`Pipeline._build_advice` 只采用 `corroborated == True` 的结论。
单一信源提及的线索会出现在「避坑提示」里并标注「未采信」，而不是被当作结论输出。

### 先有证据，后有结论

存证发生在报告生成之后，但锚定的是**全部快照摘要**而非报告正文。
报告若被修改，重算默克尔根必然对不上——这正是「一键验真」的实现基础。

---

## 明确的能力边界

这一节很重要，因为方案里的承诺有一部分**当前实现并不满足**：

| 项 | 状态 | 说明 |
|---|---|---|
| 真实平台采集 | ❌ 未实现 | `HttpCollector` 只有骨架（robots + 限速 + 快照），**无页面解析**。各平台页面结构必须逐一适配，且需先评估法律边界 |
| 联盟链上链 | ❌ 未实现 | `LocalLedgerAdapter` 是本地文件账本，提供**篡改可检测**而非「不可篡改」。无分布式共识，不具备司法效力。对接至信链/蚂蚁链需实现 `ChainAdapter` |
| LLM 报告生成 | ❌ 未实现 | 报告由规则法产出。接入 LLM 只需替换 `SentimentAnalyzer`，流水线不受影响 |
| 情感分析 | ⚠️ 规则法 | 词典 + 否定 + 程度副词。零依赖、可复现，但存在领域漂移 |
| 多模态分析 | ⚠️ 依赖上游标注 | 本系统**消费**平台已标注的多模态信号（素材指纹、是否摆拍），自身不做视频/图像识别 |
| 价格监控 | ❌ 未实现 | 文档 3.1 模块 ⑥ 未包含 |
| 小程序前端 | ❌ 未实现 | 仅输出 HTML 报告 |

这些缺口不是遗漏，而是**在无法联网、无法运行的环境下刻意不写**——
写一个跑不起来的爬虫或上链适配器，比留一个诚实的接口更糟。

---

## 目录结构

```
zhigou/
├── pyproject.toml
├── README.md
├── src/zhigou/
│   ├── models.py       # 领域模型（快照、评价、结论、凭证）
│   ├── collectors.py   # 防线一：采集器接口 + 模拟器 + HTTP 骨架
│   ├── antifraud.py    # 防线二：六维反作弊
│   ├── validation → trust.py   # 防线三/五/六
│   ├── analysis.py     # 情感分析 + 观点聚合
│   ├── attestation.py  # 防线四：默克尔树 + 哈希链账本
│   ├── report.py       # 报告渲染（文本 / HTML）
│   ├── pipeline.py     # 四步闭环编排
│   └── cli.py          # 命令行入口
└── tests/
    ├── test_antifraud.py
    ├── test_attestation.py
    └── test_pipeline.py
```

---

## 扩展点

**接入真实联盟链** —— 实现 `ChainAdapter` 即可，其余逻辑不变：

```python
class ToalinkAdapter(ChainAdapter):
    name = "toalink"
    def anchor(self, payload): 
        return {"tx_hash": ..., "index": ...}
```

**替换情感分析为模型**：

```python
pipeline = Pipeline(PipelineConfig(...))
# ClaimAggregator(SentimentAnalyzer()) 换成你的实现即可
```

**接入 LLM 生成自然语言报告**：
注意防线四的防投毒约束——`TaskParameter.params` 中的用户输入**绝不可**拼进提示词，
只有 `Review.snapshot.content`（已哈希固化）可以进。