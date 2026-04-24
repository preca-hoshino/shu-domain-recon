"""
结果报告模块
============
将探活结果输出为:
  - 终端彩色表格（rich）
  - results_<domain>.txt   纯文本，适合复制
  - results_<domain>.csv   结构化，可用 Excel 打开
  - results_<domain>.json  结构化 JSON，含元信息，便于与下游工具对接
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from src.prober import ProbeResult

console = Console()


class Reporter:
    COLUMNS = [
        "domain",
        "url",
        "status",
        "requires_auth",
        "title",
        "server",
        "powered_by",
        "tech",
        "ip",
        "latency_ms",
        "error",
    ]

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    # ── 终端彩色表格 ───────────────────────────────────────────
    def print_table(self, results: list[ProbeResult]) -> None:
        alive = [r for r in results if r.alive]
        if not alive:
            console.print("[yellow]没有存活的域名。")
            return

        table = Table(
            title=f"存活资产汇总 ({len(alive)} / {len(results)})",
            show_lines=True,
            highlight=True,
        )
        table.add_column("状态", justify="center", style="bold", no_wrap=True)
        table.add_column("认证", justify="center", no_wrap=True)
        table.add_column("域名 / URL", style="cyan", no_wrap=False)
        table.add_column("标题", style="white")
        table.add_column("技术栈", style="magenta")
        table.add_column("IP", style="dim")
        table.add_column("延迟(ms)", justify="right", style="green")

        for r in sorted(alive, key=lambda x: x.status):
            status_style = (
                "green" if 200 <= r.status < 300
                else "yellow" if 300 <= r.status < 400
                else "red"
            )

            # 如果发生了重定向或路径跳转，同时展示源域名
            base_urls = (f"http://{r.domain}", f"https://{r.domain}", f"http://{r.domain}/", f"https://{r.domain}/")
            display_url = f"{r.domain}\n[dim]->{r.url}[/]" if r.url not in base_urls else r.url

            # 认证标记
            auth_cell = "[yellow]🔒 SSO[/]" if r.requires_auth else "[dim]-[/]"

            table.add_row(
                f"[{status_style}]{r.status}[/]",
                auth_cell,
                display_url,
                r.title[:60] if r.title else "-",
                r.tech_str[:40],
                r.ip,
                str(r.latency_ms),
            )

        console.print(table)

    # ── 纯文本 ─────────────────────────────────────────────────
    # 已被简化移除，请直接查看 subdomains.txt 或 results.csv

    # ── CSV ───────────────────────────────────────────────────
    def save_csv(self, results: list[ProbeResult]) -> Path:
        out = self.output_dir / "results.csv"
        with out.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=self.COLUMNS)
            writer.writeheader()
            for r in results:
                writer.writerow(
                    {
                        "domain": r.domain,
                        "url": r.url,
                        "status": r.status,
                        "requires_auth": "🔒 SSO" if r.requires_auth else "",
                        "title": r.title,
                        "server": r.server,
                        "powered_by": r.powered_by,
                        "tech": r.tech_str,
                        "ip": r.ip,
                        "latency_ms": r.latency_ms,
                        "error": r.error,
                    }
                )
        console.print(f"[✓] CSV → {out}")
        return out

    # ── JSON ──────────────────────────────────────────────────
    def save_json(self, results: list[ProbeResult], target: str = "target") -> Path:
        """输出带元信息的结构化 JSON，便于与 Nuclei / ELK 等工具对接。"""
        out = self.output_dir / "results.json"
        alive = [r for r in results if r.alive]
        payload = {
            "metadata": {
                "target": target,
                "scan_time": datetime.now().astimezone().isoformat(),
                "total_found": len(results),
                "total_alive": len(alive),
            },
            "records": [
                {
                    "domain": r.domain,
                    "url": r.url,
                    "status": r.status,
                    "requires_auth": r.requires_auth,
                    "sso_url": r.sso_url or None,
                    "title": r.title,
                    "server": r.server,
                    "powered_by": r.powered_by,
                    "technologies": r.tech,
                    "ip": r.ip,
                    "latency_ms": r.latency_ms,
                    "alive": r.alive,
                    "error": r.error or None,
                }
                for r in results
            ],
        }
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"[✓] JSON → {out}")
        return out

    # ── Markdown 分析报告 ──────────────────────────────────────────
    def save_md(self, results: list[ProbeResult], target_b_classes: set[str], target_c_classes: set[str]) -> Path:
        import html
        out = self.output_dir / "analysis_report.md"
        alive = [r for r in results if r.alive]
        
        def _has_chinese(s: str) -> bool:
            """判断字符串中是否含有中文字符。"""
            return any('\u4e00' <= c <= '\u9fff' for c in s)

        def get_sort_key(r):
            """
            排序规则（三层优先级，同层内按域名字典序保证每次输出稳定）：
              1 → 有中文标题（含中文字符，排最前，便于重点关注内部系统）
              2 → 有英文/数字标题但无中文（正常可访问页面）
              3 → 无标题 / 错误页面（403/404/502/error 等）
            同一层内按域名字典序（稳定，与输入顺序无关），方便 git diff 追踪变更。
            """
            title_raw = str(r.title).strip() if r.title else ""
            title_lower = title_raw.lower()
            is_empty_or_error = (
                not title_raw
                or title_lower == "-"
                or any(kw in title_lower for kw in ["403", "404", "502", "error"])
            )
            if is_empty_or_error:
                weight = 3
            elif _has_chinese(title_raw):
                weight = 1
            else:
                weight = 2
            return (weight, r.domain)

        sorted_alive = sorted(alive, key=get_sort_key)
        
        lines = []
        lines.append("**子域名探测分析**")
        lines.append("")
        lines.append(f"域名数量：{len(alive)}/{len(results)}")
        lines.append("")
        
        lines.append("| 状态 | 域名 / URL | 标题 | 技术栈 | IP |")
        lines.append("| :---: | :--- | :--- | :--- | :--- |")
        
        for r in sorted_alive:
            # 防止标题和技术栈中的特殊字符破坏 Markdown 表格和渲染
            title = html.escape(r.title or "-").replace("|", "\\|").replace("\n", " ")
            tech = html.escape(r.tech_str).replace("|", "\\|").replace("\n", " ")
            
            # 不记录跳转页面，去掉 http 前缀，只展示域名
            display_domain = r.domain
            
            auth = "🔒 " if r.requires_auth else ""
            lines.append(f"| {r.status} | {auth}{display_domain} | {title} | {tech} | {r.ip} |")
            
        lines.append("")
        lines.append("**IP段推断分析**")
        lines.append("")
        
        if target_b_classes or target_c_classes:
            if target_b_classes:
                lines.append("发现的 B 段 ( /16 ):")
                for b in sorted(target_b_classes, key=lambda x: [int(p) for p in x.split('.')]):
                    lines.append(f"- `{b}.0.0/16`")
                lines.append("")
            
            if target_c_classes:
                lines.append("发现的 C 段 ( /24 ):")
                for c in sorted(target_c_classes, key=lambda x: [int(p) for p in x.split('.')]):
                    lines.append(f"- `{c}.0/24`")
                lines.append("")
        else:
            lines.append("未发现显著的 IP 段信息。")
            lines.append("")
            
        out.write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[✓] MD报告 → {out}")
        return out
