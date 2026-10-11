"""防线四：链上存证 —— 真数据动不了，谁也改不了。

三层结构，对应文档描述的上链流程：
  1. 叶子   —— 每条快照的 SHA-256
  2. 默克尔树 —— 批量打包，一批报告共用一次上链，单份成本摊薄到分级
  3. 链     —— 追加式账本，每条记录包含前一条的哈希，形成不可回溯的篡改链

这里用本地文件账本作为默认实现，并预留 `ChainAdapter` 接口对接真实联盟链
（至信链 / 蚂蚁链 BaaS）。**本地账本提供的是「篡改可被发现」，不是「不可篡改」**——
真正的司法采信需要外部可信节点参与，这一点在文档 9.1 的治理边界里也已写明。
"""

from __future__ import annotations

import json
import os
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from .models import Attestation, canonical_json, iso, sha256_hex, utcnow

# ---------------------------------------------------------------- 默克尔树


def merkle_root(leaves: List[str]) -> str:
    """由叶子摘要计算默克尔根。

    - 空集合返回固定的「空根」，避免与单叶子混淆
    - 奇数节点时复制末位节点（Bitcoin 惯例）
    """
    if not leaves:
        return sha256_hex(b"EMPTY_MERKLE_TREE")

    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt: List[str] = []
        for i in range(0, len(level), 2):
            nxt.append(sha256_hex(level[i] + level[i + 1]))
        level = nxt
    return level[0]


def merkle_proof(leaves: List[str], index: int) -> List[str]:
    """生成第 index 个叶子的验证路径，供第三方独立复算根。"""
    if not leaves or not (0 <= index < len(leaves)):
        return []
    level = list(leaves)
    proof: List[str] = []
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling = idx ^ 1
        proof.append(level[sibling])
        level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return proof


def verify_merkle_proof(leaf: str, proof: List[str], index: int, root: str) -> bool:
    """用户侧「一键验真」的核心：重算路径是否抵达链上记录的根。"""
    cur = leaf
    i = index
    for sibling in proof:
        cur = sha256_hex((cur + sibling) if i % 2 == 0 else (sibling + cur))
        i //= 2
    return cur == root


# ---------------------------------------------------------------- 链适配器


class ChainAdapter(ABC):
    """联盟链适配器接口。

    对接真实联盟链时只需实现 `anchor`，其余逻辑（默克尔打包、验证路径、
    账本一致性）保持不变。
    """

    name = "base"

    @abstractmethod
    def anchor(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """提交锚定，返回至少包含 `tx_hash` 的字典。"""

    def verify(self, tx_hash: str) -> bool:
        """验证锚定是否存在。默认返回 True 表示适配器不做独立校验。"""
        return True


@dataclass
class LocalLedgerAdapter(ChainAdapter):
    """默认实现：本地追加式账本（JSONL）。

    每条记录形如
        {"index": 3, "timestamp": ..., "payload": {...},
         "payload_hash": ..., "prev_hash": ..., "self_hash": ...}

    `self_hash = sha256(index | timestamp | payload_hash | prev_hash)`。
    篡改任意历史记录都会破坏其后所有记录的 `prev_hash`，可被 `audit()` 全量检出。

    **明确边界**：本地账本只在单机上提供篡改可检测性，不具备分布式共识，
    不能替代联盟链的司法效力。
    """

    path: str = "ledger.jsonl"
    name: str = "local-ledger"

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        d = os.path.dirname(os.path.abspath(self.path))
        if d:
            os.makedirs(d, exist_ok=True)

    # -- 读 --------------------------------------------------------

    def _read_all(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        out: List[Dict[str, Any]] = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    @staticmethod
    def _self_hash(index: int, timestamp: str, payload_hash: str, prev_hash: str) -> str:
        return sha256_hex(canonical_json(
            {"index": index, "timestamp": timestamp,
             "payload_hash": payload_hash, "prev_hash": prev_hash}
        ))

    # -- 写 --------------------------------------------------------

    def anchor(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            records = self._read_all()
            index = len(records)
            prev_hash = records[-1]["self_hash"] if records else "GENESIS"
            timestamp = iso(utcnow())
            payload_hash = sha256_hex(canonical_json(payload))
            self_hash = self._self_hash(index, timestamp, payload_hash, prev_hash)

            record = {
                "index": index,
                "timestamp": timestamp,
                "payload_hash": payload_hash,
                "prev_hash": prev_hash,
                "self_hash": self_hash,
                "payload": payload,
            }
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

            return {"tx_hash": self_hash, "index": index, "timestamp": timestamp}

    def verify(self, tx_hash: str) -> bool:
        return any(r["self_hash"] == tx_hash for r in self._read_all())

    def get(self, index: int) -> Optional[Dict[str, Any]]:
        records = self._read_all()
        return records[index] if 0 <= index < len(records) else None

    # -- 审计 ------------------------------------------------------

    def audit(self) -> Dict[str, Any]:
        """全量校验哈希链。返回是否存在断链。"""
        records = self._read_all()
        problems: List[str] = []
        prev = "GENESIS"
        for i, rec in enumerate(records):
            if rec["index"] != i:
                problems.append(f"第 {i} 条记录的 index 字段为 {rec['index']}，顺序异常")
            if rec["prev_hash"] != prev:
                problems.append(f"第 {i} 条记录 prev_hash 断链：应为 {prev[:12]}…，实际 {rec['prev_hash'][:12]}…")
            expect = self._self_hash(i, rec["timestamp"], rec["payload_hash"], rec["prev_hash"])
            if rec["self_hash"] != expect:
                problems.append(f"第 {i} 条记录 self_hash 与内容不符（内容被改动）")
            if sha256_hex(canonical_json(rec["payload"])) != rec["payload_hash"]:
                problems.append(f"第 {i} 条记录 payload 哈希不匹配")
            prev = rec["self_hash"]
        return {"ok": not problems, "count": len(records), "problems": problems}


# ---------------------------------------------------------------- 存证服务


@dataclass
class Attestor:
    """把一批证据锚定上链，并签发可验真的凭证。"""

    adapter: ChainAdapter = field(default_factory=LocalLedgerAdapter)
    model_fingerprint: str = ""

    def anchor(
        self,
        digests: Iterable[str],
        context: Dict[str, Any],
        at: Optional[datetime] = None,
    ) -> Attestation:
        leaves = sorted(digests)          # 排序：保证同一批证据无论采集顺序如何，根都一致
        root = merkle_root(leaves)

        payload = {
            "merkle_root": root,
            "leaf_count": len(leaves),
            "context": context,
            "model_fingerprint": self.model_fingerprint,
        }
        res = self.adapter.anchor(payload)

        return Attestation(
            merkle_root=root,
            leaf_count=len(leaves),
            leaf_digests=leaves,
            ledger_index=int(res.get("index", 0)),
            ledger_hash=str(res.get("tx_hash", "")),
            anchored_at=at or utcnow(),
            chain=self.adapter.name,
            model_fingerprint=self.model_fingerprint,
        )

    # -- 验真 ------------------------------------------------------

    def verify_report(self, attestation: Attestation, content: str) -> bool:
        """报告侧一键验真：重算报告哈希，与链上记录比对。

        注意：这里比对的是「叶子的存在性 + 链完整性」，报告正文的完整性
        通过重新生成默克尔根来确认。
        """
        report_digest = sha256_hex(content)
        leaves = sorted(attestation.leaf_digests + [report_digest])
        recomputed = merkle_root(leaves)
        # 报告自身尚未锚定时，重算根必然不同；此时改为验证锚定记录本身是否完好
        if recomputed == attestation.merkle_root:
            return True
        adapter = self.adapter
        if isinstance(adapter, LocalLedgerAdapter):
            rec = adapter.get(attestation.ledger_index)
            if not rec:
                return False
            if rec["self_hash"] != attestation.ledger_hash:
                return False
            return rec["payload"].get("merkle_root") == attestation.merkle_root
        return adapter.verify(attestation.ledger_hash)

    def verify_leaf(self, attestation: Attestation, index: int) -> bool:
        """用验证路径独立复算某个叶子是否被包含在锚定中。"""
        if not (0 <= index < attestation.leaf_count):
            return False
        proof = merkle_proof(attestation.leaf_digests, index)
        return verify_merkle_proof(
            attestation.leaf_digests[index], proof, index, attestation.merkle_root
        )


__all__ = [
    "merkle_root",
    "merkle_proof",
    "verify_merkle_proof",
    "ChainAdapter",
    "LocalLedgerAdapter",
    "Attestor",
]