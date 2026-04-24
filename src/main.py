"""
domain-recon  —  上海大学域名侦察工具
======================================

用法:
  python main.py <目标域名> <最高并发量> [选项]

位置参数:
  目标域名      例: shu.edu.cn
  最高并发量    各模块并发上限，推荐 200~1000

步骤控制选项 (默认全部启用，指定 --skip-* 可跳过对应阶段):
  --skip-passive      跳过被动子域名枚举 (9 个数据源查询)
  --skip-brute        跳过 DNS 字典爆破 (含 AXFR 检测 + 变异爆破)
  --skip-probe        跳过 HTTP 探活及 JS/SourceMap 深度分析
  --skip-ip-scan      跳过 IP 空间横向扫描 (PTR 反查 + TLS 证书)
  --skip-js           在 HTTP 探活阶段跳过 JS/SourceMap 深度分析

认证及过滤选项:
  --curl curl.cmd               直接加载 Chrome DevTools 导出的 curl.cmd 文件，自动提取请求头和 Cookie
  --blacklist blacklist.txt     黑名单域名文件，包含在内的域名将被跳过

并发量分配比例:
  DNS 字典爆破  (aiodns)  = max_concurrency        (轻量 UDP，可高并发)
  HTTP 探活     (httpx)   = max_concurrency // 10   (TCP 连接，适当收窄)
  PTR 反向查询  (aiodns)  = max_concurrency // 2    (UDP，中等并发)
  TLS 证书探测  (socket)  = max_concurrency // 10   (TCP 握手，与 HTTP 一致)

示例:
  python run.py shu.edu.cn 500
  python run.py shu.edu.cn 300 --skip-brute --skip-ip-scan
  python run.py shu.edu.cn 200 --skip-passive --skip-js
  python run.py shu.edu.cn 300 --curl curl.cmd
  python run.py shu.edu.cn 300 --blacklist blacklist.txt

流程:
  被动枚举(7源+Wayback+GitHub) → DNS字典爆破(含AXFR检测+变异爆破+Simhash过滤) → 多级递归爆破 → 合并去重
  → HTTP探活(含CSP/CORS精化提取+JS/SourceMap深度分析)
  → IP空间扫描(PTR反查 + TLS证书SAN提取)
  → 输出报告 (TXT / CSV / JSON + 终端表格)
"""

import argparse
import asyncio
import io
import sys
from pathlib import Path

# Windows 终端默认 GBK，强制改为 UTF-8 以支持中文和特殊字符
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from src.bruteforcer import DNSBruteForcer
from src.curl_parser import parse_curl_cmd, summarize as curl_summarize
from src.enumerator import SubdomainEnumerator
from src.ip_scanner import IPScanner
from src.prober import DomainProber
from src.reporter import Reporter

# ── 固定配置 ─────────────────────────────────────────────────
OUTPUT_DIR    = Path("output")
PROBE_TIMEOUT = 15   # HTTP 请求超时（秒），已拉高以兼容响应慢的站点


def _parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(
        prog="domain-recon",
        description="上海大学域名侦察工具 — 自动化多阶段子域名发现与探活",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python run.py shu.edu.cn 500\n"
            "  python run.py shu.edu.cn 300 --skip-brute --skip-ip-scan\n"
            "  python run.py shu.edu.cn 300 --curl curl.cmd --blacklist blacklist.txt\n"
        ),
    )
    parser.add_argument("domain",       metavar="目标域名",   help="例: shu.edu.cn")
    parser.add_argument("concurrency",  metavar="最高并发量", type=int,
                        help="各模块并发上限，推荐 200~1000")
    # 步骤控制开关
    parser.add_argument("--skip-passive",    action="store_true", help="跳过被动子域名枚举")
    parser.add_argument("--skip-brute",      action="store_true", help="跳过 DNS 字典爆破")
    parser.add_argument("--skip-probe",      action="store_true", help="跳过 HTTP 探活")
    parser.add_argument("--skip-ip-scan",    action="store_true", help="跳过 IP 空间横向扫描")
    parser.add_argument("--skip-js",         action="store_true", help="HTTP 探活时跳过 JS/SourceMap 深度分析")
    parser.add_argument("--skip-recursive",  action="store_true", help="跳过多级递归子域名爆破")
    # 认证选项
    parser.add_argument(
        "--curl",
        metavar="CURL_CMD_FILE",
        default="",
        help="Chrome DevTools 导出的 curl.cmd 文件路径，自动提取 Cookie + 请求头",
    )
    parser.add_argument(
        "--blacklist",
        metavar="BLACKLIST_FILE",
        default="",
        help="黑名单域名文件路径（每行一个），匹配的域名及其子域名将被跳过",
    )
    parser.add_argument(
        "--md-only",
        action="store_true",
        help="只生成 Markdown 报告，不输出其他格式文件",
    )
    parser.add_argument(
        "--recursive-depth",
        metavar="N",
        type=int,
        default=2,
        help="递归爆破的最大层数（默认 2 层）",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="关闭动态进度条，改为逐行静态日志输出，适配 GitHub Actions 等 CI 环境",
    )
    return parser.parse_args()


def _print_banner(domain: str, concurrency: int, args: argparse.Namespace) -> None:
    """打印启动横幅及配置摘要。"""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    c = Console()

    # 步骤启用状态
    steps = {
        "被动枚举   (7源+Wayback)": not args.skip_passive,
        "DNS 字典爆破 (AXFR + 变异 + Simhash过滤)": not args.skip_brute,
        "多级递归爆破 (容器型节点)": not args.skip_brute and not args.skip_recursive,
        "HTTP 探活  (CSP/CORS/HTML 解析)": not args.skip_probe,
        "JS/SourceMap 深度分析": not args.skip_probe and not args.skip_js,
        "IP 空间扫描 (PTR + TLS 证书)": not args.skip_ip_scan,
        "动态进度条 (CI 模式)": not getattr(args, "no_progress", False),
    }


    # 并发量分配
    brute_c = concurrency
    probe_c = max(5, concurrency // 10)
    ptr_c   = max(10, concurrency // 2)
    tls_c   = max(5, concurrency // 10)

    table = Table(show_header=True, header_style="bold magenta", box=None)
    table.add_column("探测阶段", style="cyan", width=32)
    table.add_column("状态", justify="center", width=8)
    table.add_column("并发量", justify="right", width=8)

    concurrency_map = {
        "被动枚举   (7源+Wayback)": "-",
        "DNS 字典爆破 (AXFR + 变异 + Simhash过滤)": str(brute_c),
        "多级递归爆破 (容器型节点)": str(brute_c),
        "HTTP 探活  (CSP/CORS/HTML 解析)": str(probe_c),
        "JS/SourceMap 深度分析": str(probe_c),
        "IP 空间扫描 (PTR + TLS 证书)": f"PTR={ptr_c} / TLS={tls_c}",
    }

    for step_name, enabled in steps.items():
        status = "[green]✓ 启用[/]" if enabled else "[red]✗ 跳过[/]"
        table.add_row(step_name, status, concurrency_map[step_name])

    c.print(Panel(
        table,
        title=f"[bold cyan]domain-recon[/]  [dim]→[/]  [yellow]{domain}[/]",
        subtitle=f"[dim]最高并发量: {concurrency}[/]",
        border_style="bright_blue",
        padding=(0, 1),
    ))

    # 若用户传入了认证信息，打印提示
    if args.curl:
        try:
            curl_cookies, curl_headers = parse_curl_cmd(args.curl)
            c.print(
                f"[bold green][✓] curl.cmd 已加载[/] — "
                f"{curl_summarize(curl_cookies, curl_headers)}"
            )
        except Exception as e:
            c.print(f"[red][⚠] 读取 curl 文件失败: {e}[/]")

    if args.blacklist:
        c.print(f"[bold green][✓] 黑名单文件已指定[/] — {args.blacklist}")


async def main(domain: str, max_concurrency: int, args: argparse.Namespace) -> None:
    from rich.console import Console
    c = Console()

    # 解析 curl 文件
    cookies = {}
    extra_headers = {}
    if args.curl:
        try:
            cookies, extra_headers = parse_curl_cmd(args.curl)
        except Exception:
            pass  # 错误已在 banner 阶段提示

    # 解析黑名单
    blacklist: set[str] = set()
    if args.blacklist:
        try:
            blacklist_path = Path(args.blacklist)
            if blacklist_path.exists():
                for line in blacklist_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        blacklist.add(line)
        except Exception as e:
            c.print(f"[yellow][!] 读取黑名单失败: {e}[/]")

    def is_blacklisted(d: str) -> bool:
        if not blacklist:
            return False
        for b in blacklist:
            if d == b or d.endswith("." + b):
                return True
        return False

    # 按比例计算各模块并发上限
    brute_concurrency = max_concurrency
    probe_concurrency = max(5,  max_concurrency // 10)
    ptr_concurrency   = max(10, max_concurrency // 2)
    tls_concurrency   = max(5,  max_concurrency // 10)

    # 按照目标域名创建专属输出文件夹，避免文件混淆
    domain_output_dir = OUTPUT_DIR / domain
    domain_output_dir.mkdir(parents=True, exist_ok=True)

    passive_domains: list[str] = []
    brute_domains:   list[str] = []

    # ── 阶段 1: 被动枚举 ─────────────────────────────────────────
    if not args.skip_passive:
        enumerator = SubdomainEnumerator(domain, no_progress=args.no_progress)
        passive_domains = await enumerator.run()
        c.print(f"[bold green][✓] 被动枚举完成[/] — 共发现 [yellow]{len(passive_domains)}[/] 个子域名")
    else:
        c.print("[dim][→] 被动枚举已跳过[/]")

    # ── 阶段 2: 主动 DNS 字典爆破（含 AXFR 检测 + 变异爆破）──────
    if not args.skip_brute:
        bruteforcer = DNSBruteForcer(domain=domain, concurrency=brute_concurrency, no_progress=args.no_progress)
        brute_domains = await bruteforcer.run()
    else:
        c.print("[dim][→] DNS 字典爆破已跳过[/]")

    # ── 阶段 3: 合并去重，保存子域名列表 ─────────────────────────
    merged_set = set(passive_domains) | set(brute_domains)
    if blacklist:
        original_count = len(merged_set)
        merged_set = {d for d in merged_set if not is_blacklisted(d)}
        filtered_count = original_count - len(merged_set)
        if filtered_count > 0:
            c.print(f"[dim][→] 根据黑名单过滤了 {filtered_count} 个已知域名[/]")

    merged = sorted(merged_set)
    enum_file = domain_output_dir / "subdomains.txt"
    if not getattr(args, "md_only", False):
        enum_file.write_text("\n".join(merged), encoding="utf-8")

    # ── 阶段 3.5: 多级递归爆破 ────────────────────────────────
    if not args.skip_brute and not getattr(args, "skip_recursive", False):
        from src.recursive_bruter import RecursiveBruter
        recursive_depth = getattr(args, "recursive_depth", 2)
        recursive_bruter = RecursiveBruter(
            base_domain=domain,
            concurrency=brute_concurrency,
            max_depth=recursive_depth,
            no_progress=args.no_progress,
        )
        recursive_new = await recursive_bruter.run(merged)
        if recursive_new:
            if blacklist:
                recursive_new = [d for d in recursive_new if not is_blacklisted(d)]
            merged_set.update(recursive_new)
            merged = sorted(merged_set)
            if not getattr(args, "md_only", False):
                enum_file.write_text("\n".join(merged), encoding="utf-8")
            c.print(
                f"[bold green][✓] 递归爆破完成[/] — 新增 [yellow]{len(recursive_new)}[/] 个子域名"
            )
    else:
        c.print("[dim][→] 多级递归爆破已跳过[/]")

    # 重新计算各来源有效数量用于展示
    valid_passive = len({d for d in passive_domains if not is_blacklisted(d)})
    c.print(
        f"[bold green][✓] 枚举汇总[/] — "
        f"被动(有效): [yellow]{valid_passive}[/]  "
        f"爆破新增: [yellow]{len(merged) - valid_passive}[/]  "
        f"合计: [cyan]{len(merged)}[/]  "
        f"→ {enum_file}"
    )

    # ── 阶段 4: HTTP 探活 (带广度优先爬取与本地缓存) ──────────────
    all_results = []
    probed_domains: set[str] = set()

    if not args.skip_probe:
        analyze_js = not args.skip_js
        prober = DomainProber(
            base_domain=domain,
            concurrency=probe_concurrency,
            timeout=PROBE_TIMEOUT,
            analyze_js=analyze_js,
            extra_headers=extra_headers,
            cookies=cookies,
            no_progress=args.no_progress,
        )

        # 尝试加载历史探活结果，避免重复扫描导致 IP 被封
        json_file = domain_output_dir / "results.json"
        if json_file.exists():
            try:
                import json
                from src.prober import ProbeResult
                data = json.loads(json_file.read_text(encoding="utf-8"))
                for record in data.get("records", []):
                    pr = ProbeResult(
                        domain=record.get("domain", ""),
                        url=record.get("url", ""),
                        status=record.get("status", 0),
                        title=record.get("title", "-"),
                        server=record.get("server", "-"),
                        powered_by=record.get("powered_by", "-"),
                        ip=record.get("ip", "-"),
                        latency_ms=record.get("latency_ms", 0),
                        alive=record.get("alive", False),
                        error=record.get("error") or "",
                        tech=record.get("technologies", [])
                    )
                    all_results.append(pr)
                    probed_domains.add(pr.domain)
                c.print(
                    f"[cyan][→] 发现本地缓存，已加载 [yellow]{len(probed_domains)}[/] 个历史探活记录，将跳过重复探测[/]"
                )
            except Exception as e:
                c.print(f"[yellow][!] 读取历史缓存失败: {e}[/]")

        unprobed_domains = set(merged) - probed_domains
        round_idx = 1

        while unprobed_domains:
            results = await prober.probe_all(list(unprobed_domains), round_idx=round_idx)
            all_results.extend(results)
            probed_domains.update(unprobed_domains)

            extracted_total: set[str] = set()
            for r in results:
                for ext_d in r.extracted_domains:
                    if not is_blacklisted(ext_d):
                        extracted_total.add(ext_d)

            unprobed_domains = extracted_total - probed_domains
            if unprobed_domains:
                c.print(
                    f"[cyan][→] 第 {round_idx} 轮解析发现新子域名 "
                    f"[yellow]{len(unprobed_domains)}[/] 个，排入第 {round_idx + 1} 轮队列...[/]"
                )
            round_idx += 1

        # 重写完整的子域名列表，包含爬虫新发现的域名
        final_subdomains = sorted(probed_domains)
        if not getattr(args, "md_only", False):
            enum_file.write_text("\n".join(final_subdomains), encoding="utf-8")

        alive_count = sum(1 for r in all_results if r.alive)
        c.print(
            f"[bold green][✓] HTTP 探活完成[/] — "
            f"探测: [yellow]{len(all_results)}[/]  "
            f"存活: [cyan]{alive_count}[/]"
        )
    else:
        c.print("[dim][→] HTTP 探活已跳过[/]")

    # ── 阶段 5: IP 空间横向扩展扫描（PTR + TLS）──────────────────
    target_b_classes: set[str] = set()
    target_c_classes: set[str] = set()
    if not args.skip_ip_scan:
        domain_ip_map: dict[str, str] = {
            r.domain: r.ip
            for r in all_results
            if r.alive and r.ip and r.ip != "-"
        }
        if domain_ip_map:
            ip_scanner = IPScanner(
                base_domain=domain,
                domain_ip_map=domain_ip_map,
                ptr_concurrency=ptr_concurrency,
                tls_concurrency=tls_concurrency,
                no_progress=args.no_progress,
            )
            ip_found_domains = await ip_scanner.run()
            target_b_classes = ip_scanner.target_b_classes
            target_c_classes = ip_scanner.target_c_classes
            
            # 将推断出的 IP 段写入文件
            if target_c_classes and not getattr(args, "md_only", False):
                ip_ranges_file = domain_output_dir / "inferred_ip_ranges.txt"
                with ip_ranges_file.open("w", encoding="utf-8") as f:
                    f.write("=== Inferred B-Classes (/16) ===\n")
                    f.write("\n".join(sorted(ip_scanner.target_b_classes)))
                    f.write("\n\n=== Inferred C-Classes (/24) ===\n")
                    for c in sorted(ip_scanner.target_c_classes):
                        f.write(f"{c}.0/24\n")
                c.print(f"[cyan][→] 已将推断出的网段保存至: {ip_ranges_file}[/]")

            # 将 IP 扫描发现的新域名加入待探活队列
            new_from_ip = set(ip_found_domains) - probed_domains
            if blacklist:
                new_from_ip = {d for d in new_from_ip if not is_blacklisted(d)}
                
            if new_from_ip:
                c.print(
                    f"[cyan][→] IP 空间扫描发现 [yellow]{len(new_from_ip)}[/] 个新域名，追加探活...[/]"
                )
                if not args.skip_probe:
                    ip_results = await prober.probe_all(list(new_from_ip), round_idx=99)
                    all_results.extend(ip_results)
                    probed_domains.update(new_from_ip)
                    # 更新子域名总列表文件
                    final_subdomains = sorted(probed_domains)
                    if not getattr(args, "md_only", False):
                        enum_file.write_text("\n".join(final_subdomains), encoding="utf-8")
                else:
                    # 探活被跳过时，仅追加到文件
                    probed_domains.update(new_from_ip)
                    if not getattr(args, "md_only", False):
                        enum_file.write_text("\n".join(sorted(probed_domains)), encoding="utf-8")
        else:
            c.print("[dim][→] 无存活 IP 信息，跳过 IP 空间扫描[/]")
    else:
        c.print("[dim][→] IP 空间扫描已跳过[/]")

    # ── 阶段 6: 输出报告（CSV + JSON + 终端表格）───────────
    # 无论 IP 扫描是否跳过，都从探活结果直接推断 B/C 段（利用已收集的 IP 信息）
    from src.ip_scanner import _get_c_class, _is_cloud_ip
    from collections import Counter
    c_class_counter: Counter[str] = Counter()
    for r in all_results:
        if r.alive and r.ip and r.ip != "-":
            if not _is_cloud_ip(r.ip):
                c_prefix = _get_c_class(r.ip)
                if c_prefix:
                    c_class_counter[c_prefix] += 1
    # 出现 >= 2 次的 C 段才纳入（过滤偶然 IP）
    inferred_c = {c_prefix for c_prefix, n in c_class_counter.items() if n >= 2}
    inferred_b: set[str] = set()
    for c_prefix in inferred_c:
        parts = c_prefix.split(".")
        if len(parts) == 3:
            inferred_b.add(f"{parts[0]}.{parts[1]}")
    # 合并 IP 扫描器可能额外发现的网段
    target_b_classes |= inferred_b
    target_c_classes |= inferred_c

    reporter = Reporter(domain_output_dir)
    if not getattr(args, "md_only", False):
        reporter.save_csv(all_results)
        reporter.save_json(all_results, target=domain)
    reporter.print_table(all_results)
    reporter.save_md(all_results, target_b_classes, target_c_classes)

    c.print(
        f"\n[bold green]✅ 全部流程完成[/]  报告已保存至: [underline]{domain_output_dir}[/]"
    )


