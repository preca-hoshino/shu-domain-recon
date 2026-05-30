"""
Wayback Machine 历史域名提取模块
=================================
通过 Wayback Machine (archive.org) 的 CDX API 查询目标域名曾经被收录的历史 URL，
从中提取出所有已知的子域名。

优势:
  - 能发现已经从 DNS 中删除但曾经公开存在的"僵尸资产"
  - 能发现历史上某个短暂开放时被收录的测试/内部域名
  - 完全被动，无需与目标服务器直接通信

API:
  CDX API: http://web.archive.org/cdx/search/cdx?url=*.shu.edu.cn&output=text&fl=original&collapse=urlkey&limit=100000
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import httpx
from rich.console import Console

if TYPE_CHECKING:
    pass

console = Console()

# Wayback CDX API 端点
_CDX_URL = "http://web.archive.org/cdx/search/cdx"
# Common Crawl 索引 (可作备选数据源，但响应慢，默认不启用)
_CC_INDEX_URL = "http://index.commoncrawl.org/CC-MAIN-2024-10-index"

# 最多拉取的 URL 条数（防止超大域名的 CDX 结果集把内存撑爆）
_CDX_LIMIT = 100_000


class WaybackScraper:
    """从 Wayback Machine CDX API 提取历史子域名。"""

    TIMEOUT = 60  # CDX API 响应慢，需要更长超时

    def __init__(self, domain: str, proxy: str | None = None) -> None:
        self.domain = domain.lower().strip()
        self._results: set[str] = set()
        self._proxy = proxy
        # 用于快速匹配目标子域名的正则
        self._pattern = re.compile(
            r"([a-zA-Z0-9][a-zA-Z0-9.-]*\." + re.escape(self.domain) + r")",
            re.IGNORECASE,
        )

    async def run(self) -> list[str]:
        """执行查询，返回发现的子域名列表。"""
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        }
        async with httpx.AsyncClient(
            timeout=self.TIMEOUT,
            follow_redirects=True,
            verify=False,
            headers=headers,
            proxy=self._proxy,
        ) as client:
            await self._query_cdx(client)

        found = sorted(self._results)
        console.log(f"[Wayback] 共提取 {len(found)} 个历史子域名")
        return found

    async def _query_cdx(self, client: httpx.AsyncClient) -> None:
        """
        使用 CDX API 的 `fl=original` 字段批量拉取 URL，
        并从中正则提取子域名。

        参数说明:
          url=*.domain      — 匹配所有子域名的历史记录
          output=text       — 纯文本输出，一行一个 URL
          fl=original       — 只返回原始 URL 字段（最省流）
          collapse=urlkey   — 按 urlkey 去重，防止同一 URL 出现几千次
          limit=N           — 限制最大返回条数
        """
        params = {
            "url": f"*.{self.domain}",
            "output": "text",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(_CDX_LIMIT),
        }
        try:
            console.log(f"[Wayback] 正在查询 CDX API: *.{self.domain} (上限 {_CDX_LIMIT} 条)...")
            resp = await client.get(_CDX_URL, params=params)
            resp.raise_for_status()

            raw_text = resp.text
            line_count = len(raw_text.splitlines())
            console.log(f"[Wayback] CDX 返回 {line_count} 行历史 URL")

            # 从所有 URL 中提取符合目标域名规则的子域名
            matches = self._pattern.findall(raw_text)
            for m in matches:
                self._add(m)

        except httpx.HTTPStatusError as e:
            console.log(
                f"[Wayback] CDX 查询失败: HTTP {e.response.status_code}",
                style="yellow",
            )
        except httpx.TimeoutException:
            console.log("[Wayback] CDX 查询超时，已跳过", style="yellow")
        except Exception as e:
            console.log(f"[Wayback] CDX 查询异常: {e}", style="yellow")

    def _add(self, name: str) -> None:
        """归一化并过滤后放入结果集。"""
        name = name.strip().lower().rstrip(".")
        # 只保留目标域名的子域（排除通配符和不合法条目）
        if (
            "*" not in name
            and ".." not in name
            and not name.startswith("-")
            and (name.endswith(f".{self.domain}") or name == self.domain)
            and len(name) <= 253
        ):
            self._results.add(name)
