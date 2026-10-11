"""命令行入口。

    python -m zhigou run --product P123
    python -m zhigou run --product P123 --html report.html --json report.json
    python -m zhigou verify --tx <ledger_hash>
    python -m zhigou audit

不依赖任何第三方库，标准 Python 3.8+ 即可运行。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from .attestation import LocalLedgerAdapter
from .collectors import TaskParameter
from .models import Platform, FollowUp, AuthorityAnchor, utcnow
from .pipeline import MODEL_FINGERPRINT, MODEL_VERSION, Pipeline, PipelineConfig
from .report import render_html, render_text


def cmd_run(args: argparse.Namespace) -> int:
    task = TaskParameter(
        task_id=args.task or f"t-{args.product}",
        product_id=args.product,
        target_platforms=list(Platform),
    )

    cfg = PipelineConfig(
        collector=args.collector,
        collector_kwargs={"seed": args.seed} if args.collector == "simulated" else {},
        ledger_path=args.ledger,
        enable_attestation=not args.no_attest,
        max_claims=args.top,
    )
    pipeline = Pipeline(cfg)

    # 演示用：注入回访与权威锚点，验证防线五/六与三的旁路
    followups: List[FollowUp] = []
    anchors: List[AuthorityAnchor] = []
    if args.demo_extras:
        from datetime import timedelta
        now = utcnow()
        followups = [
            FollowUp("rev-demo-1", False, "报告说续航好，实际掉电很快", now - timedelta(days=2)),
        ]
        anchors = [
            AuthorityAnchor("质检", "同批次抽检发现品控缺陷", severity=3),
        ]

    report = pipeline.run(task, followups=followups or None, anchors=anchors or None)

    if args.json:
        write_file(args.json, json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        print(f"[写入] {args.json}", file=sys.stderr)
    if args.html:
        write_file(args.html, render_html(report))
        print(f"[写入] {args.html}", file=sys.stderr)

    print(render_text(report))
    print(f"\n模型指纹: {MODEL_VERSION} / {MODEL_FINGERPRINT[:16]}…")
    return 0


def write_file(path: str, content: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def cmd_verify(args: argparse.Namespace) -> int:
    adapter = LocalLedgerAdapter(path=args.ledger)
    record = None
    for i, rec in enumerate(adapter._read_all()):
        if rec["self_hash"] == args.tx:
            record = rec
            break
    if record is None:
        print("✗ 未找到该存证记录")
        return 1
    print(f"✓ 存证有效")
    print(f"  index    : {record['index']}")
    print(f"  时间     : {record['timestamp']}")
    print(f"  默克尔根 : {record['payload'].get('merkle_root')}")
    print(f"  叶子数   : {record['payload'].get('leaf_count')}")
    print(f"  prev_hash: {record['prev_hash'][:24]}…")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    adapter = LocalLedgerAdapter(path=args.ledger)
    result = adapter.audit()
    if result["ok"]:
        print(f"✓ 账本完整，共 {result['count']} 条记录，哈希链无断裂")
        return 0
    print(f"✗ 账本异常，共 {result['count']} 条记录：")
    for p in result["problems"]:
        print(f"    - {p}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zhigou",
        description="智购参谋 · AI 购物决策副驾驶（四步闭环 + 六道防线）",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="生成一份可信购物报告")
    r.add_argument("--product", required=True, help="商品 ID")
    r.add_argument("--task", default=None, help="任务 ID（默认由商品 ID 派生）")
    r.add_argument("--collector", default="simulated", choices=["simulated", "http"])
    r.add_argument("--seed", type=int, default=20261011, help="模拟数据随机种子")
    r.add_argument("--ledger", default="ledger.jsonl", help="存证账本路径")
    r.add_argument("--no-attest", action="store_true", help="跳过链上存证")
    r.add_argument("--top", type=int, default=5, help="各板块最多输出条数")
    r.add_argument("--html", default=None, help="额外输出 HTML 报告")
    r.add_argument("--json", default=None, help="额外输出 JSON 报告")
    r.add_argument("--demo-extras", action="store_true", help="注入演示用回访与权威锚点")
    r.set_defaults(func=cmd_run)

    v = sub.add_parser("verify", help="校验一条存证")
    v.add_argument("--tx", required=True)
    v.add_argument("--ledger", default="ledger.jsonl")
    v.set_defaults(func=cmd_verify)

    a = sub.add_parser("audit", help="全量审计账本哈希链")
    a.add_argument("--ledger", default="ledger.jsonl")
    a.set_defaults(func=cmd_audit)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
