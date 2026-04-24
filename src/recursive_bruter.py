"""
多级子域名递归爆破模块
========================
当第一轮爆破/被动枚举发现了具有层级特征的子域名时（如 dept.shu.edu.cn），
本模块自动触发针对该子域名的下一级字典爆破（如 *.dept.shu.edu.cn）。

核心策略:
  1. 分析已发现的子域名，识别具有"部门/分类"语义的中间层级节点
  2. 对这些节点发起下一级的 DNS 字典爆破
  3. 支持最大深度限制（默认 2 级），防止无限递归
  4. 结果合并回主集合，与主流程无缝衔接

示例:
  已发现: lib.shu.edu.cn, dept.shu.edu.cn
  触发递归: *.lib.shu.edu.cn, *.dept.shu.edu.cn
  新发现: catalog.lib.shu.edu.cn, cs.dept.shu.edu.cn
"""

from __future__ import annotations

import asyncio
import random
import string
from pathlib import Path
from typing import Optional

import aiodns
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from src.progress_util import make_progress

console = Console()


# 默认公共 DNS 服务器
_DEFAULT_RESOLVERS = [
    "8.8.8.8",
    "8.8.4.4",
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
    "114.114.114.114",
]

# 具有"层级容器"语义的前缀关键词
# 当已发现的子域名前缀匹配这些词时，认为该域名下可能还有子级资产
_CONTAINER_KEYWORDS = {
    # 部门/学院/组织层级
    "dept", "dep", "sch", "school", "college", "fac", "faculty",
    "lib", "library", "center", "centre", "institute", "lab", "labs",
    "office", "bureau", "division",
    # 环境/区域层级
    "dev", "test", "uat", "sit", "staging", "prod", "pre",
    "cn", "us", "eu", "ap", "asia", "bj", "sh", "gz", "sz",
    # 业务平台层级
    "api", "service", "srv", "svc", "app", "web", "portal",
    "cloud", "data", "ai", "ml", "open", "inner", "internal",
    # 基础设施层级
    "ns", "dns", "git", "ci", "ops", "k8s", "dc",
}

# 递归爆破时使用的轻量字典（只用最高频的前缀，不用完整大字典）
_RECURSIVE_MINI_WORDLIST = [
    "www", "m", "api", "app", "admin", "portal", "dev", "test",
    "uat", "staging", "pre", "prod", "new", "old", "v1", "v2",
    "web", "service", "static", "cdn", "img", "oss", "file", "files",
    "login", "auth", "sso", "cas", "oauth",
    "mail", "smtp", "vpn",
    "git", "svn", "jenkins", "ci",
    "db", "redis", "es", "kafka",
    "ops", "monitor", "log", "logs",
    "doc", "docs", "help", "support", "wiki",
    "demo", "beta", "lab", "sandbox",
    "internal", "inner", "pub", "public",
    "gateway", "gw", "proxy", "lb",
]


def _random_str(length: int = 14) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _is_container_domain(fqdn: str, base_domain: str) -> bool:
    """
    判断一个 FQDN 是否是"中间层级容器"，值得对其发起下一级爆破。

    判定规则:
      - 去掉根域后，剩余部分只有 1 个标签（即直接子域名，如 lib.shu.edu.cn）
      - 该标签的关键词属于预定义的容器类别

    注意: 不对 www、mail 这样的终端叶节点做递归。
    """
    suffix = f".{base_domain}"
    if not fqdn.endswith(suffix):
        return False
    prefix_part = fqdn[: -len(suffix)]  # 如 "lib" 或 "api.dept"
    labels = prefix_part.split(".")
    # 只对单标签（第一级子域）做递归决策
    if len(labels) != 1:
        return False
    label = labels[0].lower()
    return label in _CONTAINER_KEYWORDS


class RecursiveBruter:
    """
    对已发现的"容器型"子域名，触发下一级 DNS 字典爆破。
    """

    def __init__(
        self,
        base_domain: str,
        concurrency: int = 200,
        max_depth: int = 2,
        resolvers: Optional[list[str]] = None,
        extra_wordlist: Optional[Path] = None,
        no_progress: bool = False,
    ) -> None:
        self.base_domain = base_domain.lower().strip()
        self.concurrency = concurrency
        self.max_depth = max_depth
        self.resolvers = resolvers or _DEFAULT_RESOLVERS
        self._extra_wordlist = extra_wordlist
        self._no_progress = no_progress
        self._results: set[str] = set()


    async def run(self, known_domains: list[str]) -> list[str]:
        """
        基于已知域名列表，找出容器型节点并逐层递归爆破。

        Args:
            known_domains: 已经通过被动/主动枚举发现的子域名列表

        Returns:
            新发现的子域名列表（不含 known_domains 中已有的）
        """
        console.rule(f"[bold cyan]多级递归爆破: {self.base_domain}")

        # 加载爆破词表
        words = self._load_words()
        if not words:
            console.print("[yellow][递归爆破] 词表为空，跳过", style="yellow")
            return []

        resolver = aiodns.DNSResolver(nameservers=self.resolvers)
        already_known = set(known_domains)

        # 找出第一批容器型候选节点
        containers = [
            d for d in known_domains
            if _is_container_domain(d, self.base_domain)
        ]

        if not containers:
            console.print(
                "[dim][递归爆破] 未发现容器型子域名节点，跳过递归爆破[/]"
            )
            return []

        console.print(
            f"[cyan][递归爆破] 发现 {len(containers)} 个容器型节点: "
            + ", ".join(containers[:5])
            + ("..." if len(containers) > 5 else "")
        )

        # 逐层递归（最多 max_depth 层）
        current_depth = 1
        targets = containers

        while targets and current_depth <= self.max_depth:
            console.print(
                f"[cyan][递归爆破] 第 {current_depth} 层递归，"
                f"目标节点 {len(targets)} 个，词表 {len(words)} 条"
            )
            new_found: set[str] = set()

            for parent in targets:
                # 泛解析检测
                wildcard_ips = await self._detect_wildcard(resolver, parent)
                if wildcard_ips:
                    console.print(
                        f"[yellow][递归爆破] {parent} 存在泛解析，脏 IP: "
                        f"{', '.join(wildcard_ips)}，进行内容感知过滤[/]"
                    )

                # 爆破
                found = await self._brute_under(
                    resolver, parent, words, wildcard_ips,
                    label=f"第{current_depth}层 {parent}"
                )
                new_found.update(found)

            # 过滤掉已知域名
            truly_new = new_found - already_known
            self._results.update(truly_new)
            already_known.update(truly_new)

            console.print(
                f"[green][递归爆破] 第 {current_depth} 层完成，"
                f"新发现 {len(truly_new)} 个子域名[/]"
            )

            # 把新发现中的容器型节点排入下一层
            targets = [
                d for d in truly_new
                if _is_container_domain(d, self.base_domain)
            ]
            current_depth += 1

        found_list = sorted(self._results)
        console.print(
            f"[bold green][递归爆破] 完成[/] — 新发现 {len(found_list)} 个子域名"
        )
        return found_list

    async def _detect_wildcard(
        self, resolver: aiodns.DNSResolver, parent_domain: str
    ) -> set[str]:
        """对 parent_domain 进行泛解析检测，返回脏 IP 集合。"""
        dirty_ips: set[str] = set()
        for _ in range(2):
            fake = f"{_random_str()}.{parent_domain}"
            try:
                result = await resolver.query(fake, "A")
                for r in result:
                    dirty_ips.add(r.host)
            except Exception:
                pass
        return dirty_ips

    async def _brute_under(
        self,
        resolver: aiodns.DNSResolver,
        parent: str,
        words: list[str],
        wildcard_ips: set[str],
        label: str = "爆破",
    ) -> set[str]:
        """在 parent 域名下爆破 words，返回存活的子域名集合。"""
        found: set[str] = set()
        semaphore = asyncio.Semaphore(self.concurrency)

        with make_progress(no_progress=self._no_progress, console=console) as progress:
            task = progress.add_task(f"递归爆破 {label}...", total=len(words))

            async def _worker(word: str) -> None:
                async with semaphore:
                    fqdn = f"{word}.{parent}"
                    try:
                        result = await resolver.query(fqdn, "A")
                        resolved_ips = {r.host for r in result}
                        if resolved_ips and not resolved_ips.issubset(wildcard_ips):
                            found.add(fqdn)
                            console.log(
                                f"[green][递归爆破] 发现: {fqdn} -> "
                                f"{', '.join(resolved_ips)}[/]"
                            )
                    except Exception:
                        pass
                    finally:
                        progress.advance(task)

            await asyncio.gather(*[_worker(w) for w in words], return_exceptions=True)


        return found

    def _load_words(self) -> list[str]:
        """加载递归爆破词表（优先使用外部传入的字典，否则用内置迷你词表）。"""
        if self._extra_wordlist and self._extra_wordlist.exists():
            try:
                text = self._extra_wordlist.read_text(encoding="utf-8")
                words = list({
                    line.strip().lower()
                    for line in text.splitlines()
                    if line.strip() and not line.startswith("#")
                })
                console.log(
                    f"[递归爆破] 加载外部词表: {self._extra_wordlist.name}，{len(words)} 条"
                )
                return words
            except Exception as e:
                console.log(f"[递归爆破] 外部词表读取失败: {e}，使用内置迷你词表", style="yellow")

        console.log(
            f"[递归爆破] 使用内置迷你词表，{len(_RECURSIVE_MINI_WORDLIST)} 条"
        )
        return list(_RECURSIVE_MINI_WORDLIST)
