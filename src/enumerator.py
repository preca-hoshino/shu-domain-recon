"""
子域名枚举模块
=============
被动数据源 (全部免费公开，无需 API Key):
  1. crt.sh          — 证书透明度日志
  2. AlienVault OTX  — 开源威胁情报
  3. HackerTarget    — 免费 DNS 枚举接口
  4. RapidDNS        — DNS 历史记录查询
  5. CertSpotter     — 证书透明度监控
  6. Anubis-DB       — 子域名数据库
  7. URLScan         — 网页扫描数据
  8. Wayback Machine — 历史 URL 快照提取（含僵尸资产）

并发查询，结果合并去重。
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from src.progress_util import make_progress

console = Console()



class SubdomainEnumerator:
    """被动子域名枚举器，聚合多个公开数据源。"""

    TIMEOUT = 25  # 秒，部分慢源需要更长时间

    def __init__(self, domain: str, no_progress: bool = False, proxy: str | None = None) -> None:
        self.domain = domain.lower().strip()
        self._results: set[str] = set()
        self._no_progress = no_progress
        self._proxy = proxy


    # ── 公共入口 ───────────────────────────────────────────────
    async def run(self) -> list[str]:
        console.rule(f"[bold cyan]子域名枚举: {self.domain}")

        # ── 阶段一：7 个快速数据源并发查询 ──────────────────────
        source_count = 7
        with make_progress(no_progress=self._no_progress, console=console) as progress:
            task = progress.add_task(f"正在查询 {source_count} 个被动数据源...", total=None)

            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            async with httpx.AsyncClient(
                timeout=self.TIMEOUT, follow_redirects=True, verify=False, headers=headers,
                proxy=self._proxy,
            ) as client:
                await asyncio.gather(
                    self._query_crtsh(client),
                    self._query_alienvault(client),
                    self._query_hackertarget(client),
                    self._query_rapiddns(client),
                    self._query_certspotter(client),
                    self._query_anubis(client),
                    self._query_urlscan(client),
                )
            progress.update(task, description=f"[green]快速源查询完成，已发现 {len(self._results)} 个")

        # ── 阶段二：Wayback Machine 历史 URL 提取（较慢，单独执行）──
        console.rule("[bold cyan]Wayback Machine 历史快照提取")
        try:
            from src.wayback_scraper import WaybackScraper
            wayback = WaybackScraper(self.domain, proxy=self._proxy)
            wayback_results = await wayback.run()
            before = len(self._results)
            for d in wayback_results:
                self._add(d)
            console.print(
                f"[green][Wayback] 新增 {len(self._results) - before} 个历史子域名[/]"
            )
        except Exception as e:
            console.log(f"[yellow][Wayback] 模块异常: {e}[/]", style="yellow")

        console.print(
            f"[bold green][✓] 被动枚举全部完成[/] — 共发现 [yellow]{len(self._results)}[/] 个子域名"
        )
        return sorted(self._results)

    # ── 内部工具 ───────────────────────────────────────────────
    async def _fetch_with_retry(self, client: httpx.AsyncClient, url: str, retries: int = 3, delay: float = 2.0) -> httpx.Response:
        """带重试机制的 HTTP GET 请求，处理常见的服务器错误和连接异常。"""
        for i in range(retries):
            try:
                r = await client.get(url)
                if r.status_code in (429, 500, 502, 503, 504):
                    if i < retries - 1:
                        await asyncio.sleep(delay * (i + 1))
                        continue
                r.raise_for_status()
                return r
            except Exception as e:
                if i < retries - 1:
                    await asyncio.sleep(delay * (i + 1))
                    continue
                raise e
        raise Exception(f"达到最大重试次数: {retries}")

    def _add(self, name: str) -> None:
        """过滤、归一化后放入结果集。"""
        name = name.strip().lower().rstrip(".")
        # 排除通配符、非目标域名
        if "*" in name or (not name.endswith(f".{self.domain}") and name != self.domain):
            return
        self._results.add(name)

    # ── 数据源 1: crt.sh ──────────────────────────────────────
    async def _query_crtsh(self, client: httpx.AsyncClient) -> None:
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            r = await self._fetch_with_retry(client, url)
            data: list[dict[str, Any]] = r.json()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    self._add(name)
            console.log(f"[crt.sh] 获取 {len(data)} 条证书记录")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                console.log(f"[crt.sh] 获取 0 条证书记录 (未找到)")
            else:
                console.log(f"[crt.sh] 查询失败: HTTP {e.response.status_code}", style="yellow")
        except Exception as e:
            console.log(f"[crt.sh] 查询失败: {e}", style="yellow")

    # ── 数据源 2: AlienVault OTX ──────────────────────────────
    async def _query_alienvault(self, client: httpx.AsyncClient) -> None:
        url = (
            f"https://otx.alienvault.com/api/v1/indicators/domain/"
            f"{self.domain}/passive_dns"
        )
        try:
            r = await self._fetch_with_retry(client, url)
            data = r.json()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "")
                if hostname:
                    self._add(hostname)
            console.log(f"[AlienVault] 获取 {len(data.get('passive_dns', []))} 条 DNS 记录")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                console.log("[AlienVault] 触发 API 频率限制 (429)，跳过查询", style="yellow")
            elif e.response.status_code == 404:
                console.log(f"[AlienVault] 获取 0 条 DNS 记录 (未找到)")
            else:
                console.log(f"[AlienVault] 查询失败: HTTP {e.response.status_code}", style="yellow")
        except Exception as e:
            console.log(f"[AlienVault] 查询失败: {e}", style="yellow")

    # ── 数据源 3: HackerTarget ────────────────────────────────
    async def _query_hackertarget(self, client: httpx.AsyncClient) -> None:
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            r = await self._fetch_with_retry(client, url)
            # 返回格式: "subdomain.example.com,ip\n..."
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts:
                    self._add(parts[0])
            console.log(f"[HackerTarget] 获取 {len(r.text.splitlines())} 行数据")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                console.log(f"[HackerTarget] 获取 0 行数据 (未找到)")
            else:
                console.log(f"[HackerTarget] 查询失败: HTTP {e.response.status_code}", style="yellow")
        except Exception as e:
            console.log(f"[HackerTarget] 查询失败: {e}", style="yellow")

    # ── 数据源 4: RapidDNS ────────────────────────────────────
    async def _query_rapiddns(self, client: httpx.AsyncClient) -> None:
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        try:
            r = await self._fetch_with_retry(client, url)
            # 从 HTML 中提取域名（格式: <td>subdomain.example.com</td>）
            found = re.findall(
                r"<td>([\w.-]+\." + re.escape(self.domain) + r")</td>",
                r.text,
                re.IGNORECASE,
            )
            for name in found:
                self._add(name)
            console.log(f"[RapidDNS] 提取 {len(found)} 条记录")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                console.log(f"[RapidDNS] 提取 0 条记录 (未找到)")
            else:
                console.log(f"[RapidDNS] 查询失败: HTTP {e.response.status_code}", style="yellow")
        except Exception as e:
            console.log(f"[RapidDNS] 查询失败: {e}", style="yellow")

    # ── 数据源 5: CertSpotter ────────────────────────────────
    async def _query_certspotter(self, client: httpx.AsyncClient) -> None:
        url = (
            f"https://api.certspotter.com/v1/issuances"
            f"?domain={self.domain}&include_subdomains=true&expand=dns_names"
        )
        try:
            r = await self._fetch_with_retry(client, url)
            data: list[dict[str, Any]] = r.json()
            count = 0
            for entry in data:
                for name in entry.get("dns_names", []):
                    self._add(name)
                    count += 1
            console.log(f"[CertSpotter] 获取 {count} 条 DNS 名称")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                console.log(f"[CertSpotter] 获取 0 条 DNS 名称 (未找到)")
            else:
                console.log(f"[CertSpotter] 查询失败: HTTP {e.response.status_code}", style="yellow")
        except Exception as e:
            console.log(f"[CertSpotter] 查询失败: {e}", style="yellow")

    # ── 数据源 6: Anubis-DB ──────────────────────────────────
    async def _query_anubis(self, client: httpx.AsyncClient) -> None:
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        try:
            r = await self._fetch_with_retry(client, url)
            data: list[str] = r.json()
            for name in data:
                self._add(name)
            console.log(f"[Anubis-DB] 获取 {len(data)} 条记录")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                console.log(f"[Anubis-DB] 获取 0 条记录 (未找到)")
            else:
                console.log(f"[Anubis-DB] 查询失败: HTTP {e.response.status_code}", style="yellow")
        except Exception as e:
            console.log(f"[Anubis-DB] 查询失败: {e}", style="yellow")

    # ── 数据源 7: URLScan ────────────────────────────────────
    async def _query_urlscan(self, client: httpx.AsyncClient) -> None:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000"
        try:
            r = await self._fetch_with_retry(client, url)
            data = r.json()
            for record in data.get("results", []):
                domain = record.get("page", {}).get("domain", "")
                if domain:
                    self._add(domain)
            console.log(f"[URLScan] 获取 {len(data.get('results', []))} 条记录")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                console.log(f"[URLScan] 获取 0 条记录 (未找到)")
            else:
                console.log(f"[URLScan] 查询失败: HTTP {e.response.status_code}", style="yellow")
        except Exception as e:
            console.log(f"[URLScan] 查询失败: {e}", style="yellow")

