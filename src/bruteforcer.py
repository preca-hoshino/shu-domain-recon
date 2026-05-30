"""
DNS 爆破枚举模块
================
通过字典遍历，主动查询目标域名下可能存在的子域名。
补充被动枚举无法发现的"未被外部引用"内部资产。

核心机制:
  1. 泛解析检测 (Wildcard DNS): 爆破前自动测试，若存在则记录脏 IP 并过滤误报
  2. 多 Resolver 轮询: 防止单点 DNS 服务器限速或封禁
  3. aiodns 异步并发: 高速 DNS A 记录 / CNAME 解析
  4. 变异爆破 (Permutation): 第一轮爆破后，基于存活前缀生成变异候选，进行二次精准爆破
"""

from __future__ import annotations

import asyncio
import itertools
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


# 内置公共 DNS 服务器列表
_DEFAULT_RESOLVERS = [
    "8.8.8.8",       # Google
    "8.8.4.4",       # Google
    "223.5.5.5",     # 阿里云
    "223.6.6.6",     # 阿里云
    "119.29.29.29",  # 腾讯 DNSpod
    "180.76.76.76",  # 百度
    "114.114.114.114",  # 114 DNS
]

# 变异词典：覆盖常见的环境标记和版本后缀
_MUTATION_WORDS = [
    "dev", "test", "uat", "sit", "staging", "stage",
    "prod", "pre", "preprod",
    "v1", "v2", "v3", "new", "old", "bk", "backup",
    "api", "app", "web", "m", "mobile",
    "admin", "manage", "portal", "internal", "int",
    "beta", "alpha", "demo",
]

# 变异时使用的分隔符
_SEPARATORS = ["-", ""]


def _random_subdomain(length: int = 16) -> str:
    """生成一个随机的垃圾子域名前缀，用于泛解析检测。"""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _generate_permutations(prefixes: list[str]) -> set[str]:
    """
    基于第一轮存活的子域名前缀，生成变异候选词典。
    策略:
      - prefix + sep + mutation_word   (如 api-dev, api-test)
      - mutation_word + sep + prefix   (如 dev-api, test-api)
    """
    candidates: set[str] = set()
    for prefix in prefixes:
        for word, sep in itertools.product(_MUTATION_WORDS, _SEPARATORS):
            if word == prefix:
                continue
            candidates.add(f"{prefix}{sep}{word}")
            candidates.add(f"{word}{sep}{prefix}")
    return candidates


class DNSBruteForcer:
    """基于字典的异步 DNS 爆破枚举器（含变异爆破阶段）。"""

    def __init__(
        self,
        domain: str,
        wordlist_path: Optional[Path] = None,
        concurrency: int = 500,
        resolvers: Optional[list[str]] = None,
        no_progress: bool = False,
    ) -> None:
        self.domain = domain.lower().strip()
        self.concurrency = concurrency
        self.resolvers = resolvers or _DEFAULT_RESOLVERS
        self._no_progress = no_progress
        self._wordlist_path = wordlist_path or (
            Path(__file__).parent.parent / "data" / "wordlist.txt"
        )
        self._wildcard_ips: set[str] = set()
        self._results: set[str] = set()
        self._resolver_cycle = 0
        self._is_fake_ip = False
        self._is_dynamic_wildcard = False
        # 解析到脏 IP 但未被确认丢弃的域名（待 Simhash 内容验证）
        self._suspicious: set[str] = set()

    # ── 公共入口 ───────────────────────────────────────────────
    async def run(self) -> list[str]:
        console.rule(f"[bold cyan]DNS 字典爆破: {self.domain}")

        # 1. 读取字典
        words = self._load_wordlist()
        if not words:
            console.print("[yellow][DNS爆破] 字典为空，跳过", style="yellow")
            return []

        # 1.5 尝试 AXFR 区域传输 (DNS漏洞探测)
        await self._check_axfr()

        # 2. 泛解析检测
        await self._detect_wildcard()
        if self._is_fake_ip:
            console.print("[bold red][!] 检测到 Fake-IP 代理劫持 (如 Clash/Surge)。")
            console.print("[bold red][!] Fake-IP 会导致所有 DNS 查询均返回假 IP，DNS 爆破无法进行！")
            console.print("[bold red][!] 请关闭代理软件的 Fake-IP 功能，或在纯净网络环境下运行。")
            return []
            
        if self._is_dynamic_wildcard:
            console.print("[bold red][!] 检测到动态泛解析 (每次请求返回不同 IP)。")
            console.print("[bold red][!] 动态泛解析会防御基于 IP 过滤的 DNS 爆破，产生巨量误报。")
            console.print("[bold yellow][!] 已自动跳过 DNS 爆破阶段，将依赖被动信息收集。")
            return []

        if self._wildcard_ips:
            console.print(
                f"[yellow][DNS爆破] 检测到泛解析 (Wildcard DNS)，脏 IP 数量: "
                f"{len(self._wildcard_ips)}，将自动过滤误报"
            )

        # 3. 第一轮：基础字典爆破
        console.print(
            f"[cyan][DNS爆破] 开始第一轮爆破，字典 {len(words)} 条，"
            f"并发 {self.concurrency}，Resolver × {len(self.resolvers)}"
        )
        resolver = self._make_resolver()
        await self._brute_words(resolver, words, label="第一轮 基础字典")

        # 4. 变异爆破 (Permutation)：基于第一轮存活结果
        await self._run_permutation_brute(resolver)

        # 5. 泏解析内容感知验证：对“疡疴列表”中的域名做 Simhash 二次确认
        if self._suspicious and self._wildcard_ips:
            console.print(
                f"[cyan][DNS爆破] 共 {len(self._suspicious)} 个域名解析到泏解析 IP，"
                f"启动 Simhash 内容感知验证以过滤误报..."
            )
            try:
                from src.wildcard_filter import verify_batch
                verified = await verify_batch(
                    domains=list(self._suspicious),
                    parent_domain=self.domain,
                    base_domain=self.domain,
                    concurrency=20,
                )
                before = len(self._results)
                self._results.update(verified)
                console.print(
                    f"[green][DNS爆破] Simhash 验证完成："
                    f"{len(self._suspicious)} 个疡疴域名 → 确认 {len(verified)} 个真实业务域名[/]"
                )
            except Exception as e:
                console.log(f"[yellow][DNS爆破] Simhash 验证异常: {e}，跳过[/]", style="yellow")

        found = sorted(self._results)
        console.print(f"[bold green][DNS爆破] 完成[/] — 发现 {len(found)} 个有效子域名")
        return found

    # ── 内部方法 ───────────────────────────────────────────────
    async def _run_permutation_brute(self, resolver: aiodns.DNSResolver) -> None:
        """
        阶段一强化：变异爆破。
        提取第一轮存活域名的前缀，生成基于命名习惯的变异候选词表，进行二次爆破。
        """
        if not self._results:
            return

        # 提取存活子域名的最近一级前缀（如 api.shu.edu.cn → api）
        alive_prefixes: list[str] = []
        for fqdn in self._results:
            # 去掉 .{domain} 后缀，取最左侧的标签
            prefix = fqdn.replace(f".{self.domain}", "").split(".")[0]
            if prefix and prefix not in alive_prefixes:
                alive_prefixes.append(prefix)

        permuted = _generate_permutations(alive_prefixes)
        # 过滤掉已在第一轮字典中存在的词（减少重复请求）
        base_words_in_results = {
            r.replace(f".{self.domain}", "") for r in self._results
        }
        permuted -= base_words_in_results

        if not permuted:
            return

        console.print(
            f"[cyan][DNS爆破] 第二轮变异爆破，基于 {len(alive_prefixes)} 个存活前缀，"
            f"生成 {len(permuted)} 个变异候选"
        )
        await self._brute_words(resolver, list(permuted), label="第二轮 变异爆破")

    async def _brute_words(
        self,
        resolver: aiodns.DNSResolver,
        words: list[str],
        label: str = "爆破",
    ) -> None:
        """通用的批量 DNS 爆破执行器。"""
        semaphore = asyncio.Semaphore(self.concurrency)

        with make_progress(no_progress=self._no_progress, console=console) as progress:
            task = progress.add_task(f"DNS {label}中...", total=len(words))

            async def _worker(word: str) -> None:
                async with semaphore:
                    await self._resolve(resolver, word)
                    progress.advance(task)

            await asyncio.gather(*[_worker(w) for w in words], return_exceptions=True)


    async def _check_axfr(self) -> None:
        """尝试进行 DNS 区域传输 (AXFR)。如果成功，能直接获取所有子域名。"""
        console.log("[DNS爆破] 尝试 DNS 区域传输 (AXFR) 检测...")
        try:
            import dns.resolver
            import dns.zone
            import dns.query
            with console.status("[bold cyan]正在解析名称服务器 (NS)...") as status:
                ns_answers = dns.resolver.resolve(self.domain, "NS")
                for ns in ns_answers:
                    ns_server = str(ns)
                    status.update(f"[bold cyan]正在对 {ns_server} 进行 AXFR 检测...")
                    try:
                        ns_ip = dns.resolver.resolve(ns_server, "A")[0].to_text()
                        z = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=5))
                        names = [str(n) for n in z.nodes.keys()]
                        console.print(f"[bold red][!] 严重漏洞: {ns_server} 允许 AXFR，直接获取到 {len(names)} 个记录![/]")
                        for name in names:
                            if name == "@":
                                self._results.add(self.domain)
                            else:
                                self._results.add(f"{name}.{self.domain}")
                    except Exception:
                        pass
        except Exception:
            pass

    def _load_wordlist(self) -> list[str]:
        """读取字典文件，返回去重后的前缀列表。"""
        try:
            text = self._wordlist_path.read_text(encoding="utf-8")
            words = list({
                line.strip().lower()
                for line in text.splitlines()
                if line.strip() and not line.startswith("#")
            })
            console.log(f"[DNS爆破] 加载字典: {self._wordlist_path.name}，{len(words)} 条")
            return words
        except FileNotFoundError:
            console.print(f"[red][DNS爆破] 字典文件不存在: {self._wordlist_path}", style="red")
            return []

    def _make_resolver(self) -> aiodns.DNSResolver:
        """创建 aiodns 解析器，使用自定义 Resolver 列表。"""
        return aiodns.DNSResolver(nameservers=self.resolvers)

    async def _detect_wildcard(self) -> None:
        """随机生成多个垃圾子域，若解析成功则判定为泛解析。
        同时检测 Fake-IP 代理（如 Clash）和动态泛解析防御。"""
        console.log("[DNS爆破] 检测泛解析 (Wildcard DNS)...")
        resolver = self._make_resolver()
        
        test_domains = [f"{_random_subdomain()}.{self.domain}" for _ in range(10)]
        
        async def _query_fake(domain: str) -> list[str]:
            try:
                result = await resolver.query(domain, "A")
                return [r.host for r in result]
            except Exception:
                return []
                
        results = await asyncio.gather(*[_query_fake(d) for d in test_domains])
        
        all_ips = set()
        resolved_count = 0
        for ips in results:
            if ips:
                resolved_count += 1
                for ip in ips:
                    all_ips.add(ip)
                    
        if resolved_count > 0:
            import ipaddress
            
            # 检测是否包含 Fake-IP (198.18.0.0/15 是常见的 Fake-IP 网段)
            fake_ip_network = ipaddress.ip_network('198.18.0.0/15')
            for ip in all_ips:
                try:
                    if ipaddress.ip_address(ip) in fake_ip_network:
                        self._is_fake_ip = True
                        return
                except ValueError:
                    pass
                    
            # 如果查询了 10 次，返回了非常多的不同 IP（例如 > 5），则是动态泛解析
            if len(all_ips) > 5 and resolved_count >= 5:
                self._is_dynamic_wildcard = True
                return
                
            # 静态泛解析，记录脏 IP
            self._wildcard_ips.update(all_ips)

    async def _resolve(self, resolver: aiodns.DNSResolver, word: str) -> None:
        """解析单个子域名，泛解析 IP 完全匹配时丢弃；
        部分匹配时（有真实 IP 也有脏 IP 混合）加入疑似列表，等待 Simhash 验证。"""
        fqdn = f"{word}.{self.domain}"
        try:
            result = await resolver.query(fqdn, "A")
            resolved_ips = {r.host for r in result}
            if not resolved_ips:
                return

            if self._wildcard_ips:
                # 解析出的 IP 完全属于脏 IP → 确定是泛解析误报，直接丢弃
                if resolved_ips.issubset(self._wildcard_ips):
                    # 加入疑似列表，等待 Simhash 内容感知二次验证
                    self._suspicious.add(fqdn)
                    return
                # 解析出的 IP 与脏 IP 没有交集 → 确定是真实域名
                self._results.add(fqdn)
                console.log(f"[green][DNS爆破] 发现: {fqdn} -> {', '.join(resolved_ips)}[/]")
            else:
                # 无泛解析，直接收录
                self._results.add(fqdn)
                console.log(f"[green][DNS爆破] 发现: {fqdn} -> {', '.join(resolved_ips)}[/]")

        except aiodns.error.DNSError:
            pass  # NXDOMAIN / 超时 — 正常情况，忽略
        except Exception:
            pass
