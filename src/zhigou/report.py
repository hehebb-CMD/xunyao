"""报告渲染：把可信结论 + 真实性看板 + 存证凭证组装成交付物。

对应文档 3.1 的六板块报告结构：优点 / 缺点 / 争议点 / 避坑提示 / 真实性看板 / 购买建议。
"""

from __future__ import annotations

from typing import List

from .models import Claim, ShoppingReport, iso


def _claim_lines(claims: List[Claim], limit: int = 5) -> List[str]:
    lines = []
    for i, c in enumerate(claims[:limit], 1):
        srcs = "、".join(c.platform_labels)
        tag = f"（{c.tag}）" if c.tag else ""
        lines.append(
            f"  {i}. {c.text}{tag}\n"
            f"     来源：{srcs} | 独立信源 {c.independent_source_count} 个 | "
            f"证据 {len(c.evidence_ids)} 条 | 权重 {c.weight:.2f}"
        )
    return lines


def render_text(report: ShoppingReport) -> str:
    """终端可读报告。"""
    a = report.authenticity
    L: List[str] = []
    add = L.append

    add("=" * 64)
    add(f"  {report.product.title}")
    add(f"  ¥{report.product.price}  ·  {report.product.shop}")
    add(f"  生成于 {iso(report.generated_at)}")
    add("=" * 64)

    # 真实性看板
    add("")
    add("【真实性看板】")
    add(f"  采集 {a.get('total_collected', 0)} 条 → "
        f"可信 {a.get('trusted', 0)} · 存疑 {a.get('doubted', 0)} · 剔除 {a.get('rejected', 0)}")
    add(f"  有效样本 {a.get('effective_sample', 0)} 条（有效率 {a.get('effective_ratio', 0) * 100:.1f}%）")
    reasons = a.get("doubt_pool_reasons") or []
    if reasons:
        add(f"  存疑成因：{'、'.join(reasons)}")
    add(f"  可信度：{report.summary.display}")
    add(f"  说明：{report.summary.reason}")
    if report.attestation:
        add(f"  存证编号：{report.attestation.ledger_hash[:24]}… "
            f"(链：{report.attestation.chain}，叶子 {report.attestation.leaf_count})")

    # 结论
    add("")
    add("【优点】")
    L.extend(_claim_lines(report.pros) or ["  （样本不足，无可信优点结论）"])
    add("")
    add("【缺点】")
    L.extend(_claim_lines(report.cons) or ["  （样本不足，无可信缺点结论）"])
    if report.contested:
        add("")
        add("【争议点】")
        L.extend(_claim_lines(report.contested))

    contradictions = a.get("selling_point_contradictions") or []
    if contradictions:
        add("")
        add("【避坑提示】")
        for c in contradictions:
            add(f"  ! {c}")

    # 购买建议
    adv = report.advice or {}
    add("")
    add("【购买建议】")
    add(f"  适合：{'、'.join(adv.get('suitable_for', []))}")
    add(f"  不适合：{'、'.join(adv.get('not_suitable_for', []))}")
    for c in adv.get("caveats", []):
        add(f"  注意：{c}")

    for w in report.warnings:
        add("")
        add(f"  ⚠ {w}")

    add("")
    add("  本报告为信息聚合参考，非质量鉴定。结论可点击证据复核。")
    add("=" * 64)
    return "\n".join(L)


_HTML_ESC = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}


def _esc(s: str) -> str:
    out = str(s)
    for k, v in _HTML_ESC.items():
        out = out.replace(k, v)
    return out


def render_html(report: ShoppingReport) -> str:
    """单文件 HTML 报告，可直接分享。"""
    a = report.authenticity
    adv = report.advice or {}

    def claim_items(claims: List[Claim]) -> str:
        if not claims:
            return '<li class="empty">样本不足，无可信结论</li>'
        items = []
        for c in claims:
            tag = f'<span class="tag">{_esc(c.tag)}</span>' if c.tag else ""
            items.append(
                f'<li><b>{_esc(c.text)}</b>{tag}'
                f'<div class="meta">{"、".join(_esc(p) for p in c.platform_labels)}'
                f' · 独立信源 {c.independent_source_count}'
                f' · 证据 {len(c.evidence_ids)} 条 · 权重 {c.weight:.2f}</div></li>'
            )
        return "".join(items)

    at = ""
    if report.attestation:
        at = (
            f'<div class="attest">存证编号 <code>{_esc(report.attestation.ledger_hash)}</code>'
            f'<br>默克尔根 <code>{_esc(report.attestation.merkle_root)}</code>'
            f' · {report.attestation.leaf_count} 个叶子 · 链 {_esc(report.attestation.chain)}</div>'
        )

    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(report.product.title)} · 智购参谋报告</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
background:#fdfcf9;color:#1f2329;line-height:1.8;padding:28px 16px;font-size:15px}}
.wrap{{max-width:720px;margin:0 auto}}
h1{{font-size:24px;margin-bottom:4px}}
.price{{color:#4e5969;font-size:14px;margin-bottom:20px}}
.board{{background:#fff;border:1px solid #e5e6eb;border-top:3px solid #1f4e79;
padding:18px 20px;margin-bottom:22px}}
.board h2{{font-size:16px;color:#1f4e79;margin-bottom:10px}}
.bar{{height:8px;background:#f0f2f5;border-radius:99px;overflow:hidden;margin:8px 0}}
.bar i{{display:block;height:100%;background:#2e75b6}}
.stats{{display:flex;gap:18px;flex-wrap:wrap;font-size:13px;color:#4e5969;margin:8px 0}}
.stats b{{color:#1f2329;font-size:19px;display:block}}
.sec{{background:#fff;border:1px solid #e5e6eb;padding:18px 20px;margin-bottom:14px}}
.sec h3{{font-size:15px;margin-bottom:10px;color:#1f4e79}}
ul{{list-style:none}}
li{{padding:8px 0;border-bottom:1px dashed #e5e6eb}}
li:last-child{{border:0}}
.meta{{font-size:12.5px;color:#6b7480;margin-top:2px}}
.tag{{background:#fdf8ec;color:#a97a06;font-size:11.5px;padding:1px 7px;
border-radius:4px;margin-left:8px}}
.empty{{color:#8a929e;font-size:14px}}
.warn{{background:#fdf2f2;border-left:4px solid #c0392b;padding:12px 16px;margin-bottom:14px;font-size:14px}}
.attest{{background:#f2f7fc;border-left:4px solid #2e75b6;padding:12px 16px;
margin-top:14px;font-size:12.5px;word-break:break-all}}
code{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px}}
.foot{{color:#8a929e;font-size:12.5px;text-align:center;margin-top:28px;padding-top:18px;
border-top:1px solid #e5e6eb}}
</style></head><body><div class="wrap">
<h1>{_esc(report.product.title)}</h1>
<div class="price">¥{report.product.price} · {_esc(report.product.shop)} · {iso(report.generated_at)}</div>

<div class="board">
  <h2>真实性看板 · 可信度 {report.summary.display}</h2>
  <div class="stats">
    <div><b>{a.get('total_collected', 0)}</b>采集</div>
    <div><b>{a.get('trusted', 0)}</b>可信</div>
    <div><b>{a.get('doubted', 0)}</b>存疑</div>
    <div><b>{a.get('rejected', 0)}</b>剔除</div>
    <div><b>{a.get('effective_ratio', 0) * 100:.0f}%</b>有效率</div>
  </div>
  <div class="bar"><i style="width:{a.get('effective_ratio', 0) * 100:.0f}%"></i></div>
  <div class="meta">{_esc(report.summary.reason)}</div>
  {at}
</div>

{''.join(f'<div class="warn">{_esc(w)}</div>' for w in report.warnings)}

<div class="sec"><h3>优点</h3><ul>{claim_items(report.pros)}</ul></div>
<div class="sec"><h3>缺点</h3><ul>{claim_items(report.cons)}</ul></div>
<div class="sec"><h3>争议点</h3><ul>{claim_items(report.contested)}</ul></div>

<div class="sec"><h3>购买建议</h3>
<div class="meta">适合：{_esc('、'.join(adv.get('suitable_for', [])))}</div>
<div class="meta">不适合：{_esc('、'.join(adv.get('not_suitable_for', [])))}</div>
<ul>{''.join(f'<li>{_esc(c)}</li>' for c in adv.get('caveats', [])) or '<li class="empty">无</li>'}</ul>
</div>

<div class="foot">本报告为信息聚合参考，非质量鉴定；存证仅证明「当时的记录是什么」，不替代司法鉴定。</div>
</div></body></html>"""


__all__ = ["render_text", "render_html"]