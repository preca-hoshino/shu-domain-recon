"""
HTTP 探活模块
============
对每个子域名同时尝试 HTTPS 和 HTTP，提取:
  - 最终 URL（含重定向）
  - HTTP 状态码
  - 网页标题 (<title>)
  - Server 响应头
  - X-Powered-By 响应头
  - 解析 IP
  - 响应时长（毫秒）

增强功能:
  - CSP/CORS 响应头精化子域名提取（专用解析器）
  - HTML 全文域名扫描（链接/Location 等）
  - JS 资源下载与正则扫描（可通过 analyze_js=False 关闭）
  - SourceMap (.map) 文件解析（在 JS 分析启用时自动触发）

防卡死机制:
  - 每个 JS/SourceMap 请求均有独立超时（默认 8 秒）
  - 整个 JS 分析阶段有全局任务超时（默认 30 秒/域名）
  - 所有异常均被捕获，不影响主流程
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
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


_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}

# 常见 CDN/公共库域名前缀，避免下载无关 JS 资源
_CDN_KEYWORDS = {
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "ajax.googleapis.com",
    "staticcdn", "jquery", "bootstrap", "fontawesome", "unpkg.com",
    "staticfile.org", "bootcss.com",
}


# ── SSO/OAuth2 关键域名特征 ──────────────────────────────────
# 请求历史链中出现这些关键词且不属于目标域时，认定为 SSO 重定向
_SSO_HOST_KEYWORDS = {"sso", "oauth", "oauth2", "cas", "passport", "idp", "shibboleth", "auth", "login"}

# ── 进程池管理 ────────────────────────────────────────────────
_process_pool = None

def _get_process_pool() -> concurrent.futures.ProcessPoolExecutor:
    global _process_pool
    if _process_pool is None:
        import multiprocessing
        # 根据 CPU 核心数自适应设置 worker 数量，最多 4 个，避免占用过多资源
        workers = min(4, max(1, multiprocessing.cpu_count() - 1))
        _process_pool = concurrent.futures.ProcessPoolExecutor(max_workers=workers)
    return _process_pool

def force_shutdown_process_pool() -> None:
    """强制关闭进程池并终止所有子进程，防止因超大文本的正则匹配耗时过长导致主进程无法退出"""
    global _process_pool
    if _process_pool is not None:
        try:
            # 1. 停止接收新任务，取消尚未开始的任务
            _process_pool.shutdown(wait=False, cancel_futures=True)
            # 2. 强制终止底层正在执行的进程
            if hasattr(_process_pool, "_processes"):
                for process in _process_pool._processes.values():
                    try:
                        process.terminate()
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            _process_pool = None

def _extract_domains_sync(text: str, base_domain: str) -> set[str]:
    """在独立进程中执行 CPU 密集的正则匹配，避免阻塞主进程。"""
    try:
        pattern = re.compile(
            r"([a-zA-Z0-9][a-zA-Z0-9.-]*\." + re.escape(base_domain) + r")",
            re.IGNORECASE,
        )
        return set(pattern.findall(text))
    except Exception:
        return set()


# ── 结果数据类 ────────────────────────────────────────────────
@dataclass
class ProbeResult:
    domain: str
    url: str = ""
    status: int = 0
    title: str = "-"
    server: str = "-"
    powered_by: str = "-"
    ip: str = "-"
    latency_ms: int = 0
    alive: bool = False
    error: str = ""
    tech: list[str] = field(default_factory=list)
    extracted_domains: set[str] = field(default_factory=set)
    # OAuth2/SSO 认证状态
    requires_auth: bool = False  # 请求链中经过了 SSO 认证平台
    sso_url: str = ""            # 经过的 SSO 平台 URL（调试用）

    @property
    def tech_str(self) -> str:
        return ", ".join(self.tech) if self.tech else "-"


# ── 工具函数 ──────────────────────────────────────────────────
def _resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "-"


def _detect_sso_redirect(
    resp: httpx.Response, base_domain: str
) -> tuple[bool, str]:
    """
    检查完整的重定向历史链，判断是否经过了 SSO/OAuth2 认证平台。

    返回:
        (was_via_sso, sso_url)
        was_via_sso: True 表示请求链中途经过了 SSO 域名
        sso_url:     第一个检测到的 SSO 平台 URL
    """
    # 将历史跳转 URL + 最终 URL 全部纳入检测
    all_urls = [str(r.url) for r in resp.history] + [str(resp.url)]
    for url in all_urls:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        # 两种情况都检测 SSO 关键词:
        #   1. 外部域名（如 unified-auth.example.com）
        #   2. 目标域的子域名（如 newsso.shu.edu.cn / cas.shu.edu.cn）
        #      注意: SSO 平台本身常常是目标域的子域，不能简单跳过
        for kw in _SSO_HOST_KEYWORDS:
            if kw in host:
                # 排除目标站自己的路径（/login 路由不算 SSO 重定向）
                is_target_base = (host == base_domain)
                if not is_target_base:
                    return True, url
    return False, ""


def _extract_title(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "html.parser")
        tag = soup.find("title")
        if tag and tag.string:
            return tag.string.strip()[:120]
    except Exception:
        pass
    # fallback: 正则
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:120] if m else "-"


def _detect_tech(headers: httpx.Headers, html: str) -> list[str]:
    """简单指纹识别：根据响应头和 HTML 推断技术栈。"""
    tech: set[str] = set()
    server = headers.get("server", "")
    if server:
        tech.add(server.split("/")[0])  # 只取名字部分，如 nginx
    if headers.get("x-powered-by"):
        tech.add(headers["x-powered-by"])
    if headers.get("x-aspnet-version") or headers.get("x-aspnetmvc-version"):
        tech.add("ASP.NET")
    # HTML 关键词特征
    _html_lower = html[:4096].lower()
    if "shiro" in _html_lower or "rememberme" in _html_lower:
        tech.add("Apache Shiro")
    if "harbor" in _html_lower:
        tech.add("Harbor")
    if "gitlab" in _html_lower:
        tech.add("GitLab")
    if "jenkins" in _html_lower:
        tech.add("Jenkins")
    if "spring" in _html_lower:
        tech.add("Spring Boot")
    if "layui" in _html_lower:
        tech.add("Layui")
    if "vue" in _html_lower:
        tech.add("Vue.js")
    if "react" in _html_lower:
        tech.add("React")
    return sorted(tech)


def _extract_domains_from_csp(csp_value: str, domain_regex: re.Pattern) -> set[str]:
    """
    从 CSP 指令字符串中精确提取子域名。
    CSP 格式: "default-src 'self'; script-src api.shu.edu.cn cdn.example.com"
    """
    found: set[str] = set()
    # 移除 CSP 中的特殊关键字（'self', 'none', 'unsafe-inline' 等）
    cleaned = re.sub(r"'[^']*'", " ", csp_value)
    found.update(domain_regex.findall(cleaned))
    return found


def _extract_domains_from_cors(cors_value: str, domain_regex: re.Pattern) -> set[str]:
    """
    从 CORS 头部值中提取子域名。
    CORS 格式: "https://api.shu.edu.cn" 或 "*"
    """
    found: set[str] = set()
    # 去除协议前缀后再匹配
    cleaned = re.sub(r"https?://", "", cors_value)
    found.update(domain_regex.findall(cleaned))
    return found


def _is_target_js(src_url: str, base_domain: str) -> bool:
    """
    判断 JS 资源是否属于目标域名，过滤掉公共 CDN。
    """
    try:
        parsed = urlparse(src_url)
        host = parsed.netloc.lower()
        # 无 host 则为相对路径，属于目标域
        if not host:
            return True
        # 检查是否属于目标域
        if host.endswith(base_domain) or base_domain in host:
            return True
        # 过滤公共 CDN
        for cdn_kw in _CDN_KEYWORDS:
            if cdn_kw in host:
                return False
        return False
    except Exception:
        return False


# ── 核心探测器 ────────────────────────────────────────────────
class DomainProber:
    """异步并发 HTTP 探活器（含 JS/SourceMap 深度分析）。"""

    # 单个 JS/SourceMap 请求的独立超时（秒）
    _JS_REQUEST_TIMEOUT = 8
    # 整个 JS 分析阶段的全局超时（秒），防止单域名卡死整个探活流程
    _JS_ANALYZE_GLOBAL_TIMEOUT = 30

    def __init__(
        self,
        base_domain: str,
        concurrency: int = 30,
        timeout: int = 5,
        analyze_js: bool = True,
        extra_headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        no_progress: bool = False,
        proxy: Optional[str] = None,
    ) -> None:
        self.base_domain = base_domain.lower().strip()
        self.concurrency = concurrency
        self.timeout = timeout
        self.analyze_js = analyze_js
        self._no_progress = no_progress
        self._request_headers = {**_HEADERS, **(extra_headers or {})}
        self._cookies = cookies or {}
        self._proxy = proxy

        # 强制子域名必须以字母或数字开头，防止提取出 `.shu.edu.cn` 这种无效域名
        self.domain_regex = re.compile(
            r"([a-zA-Z0-9][a-zA-Z0-9.-]*\." + re.escape(self.base_domain) + r")",
            re.IGNORECASE,
        )
        # JS 文件 URL 匹配正则（提取 HTML 中的 <script src="..."> 标签）
        self._script_src_regex = re.compile(
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            re.IGNORECASE,
        )

    async def _async_extract_domains(self, text: str) -> set[str]:
        """异步封装：使用进程池提取子域名，防止阻塞主进程的 asyncio 事件循环"""
        if not text:
            return set()
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _get_process_pool(),
            _extract_domains_sync,
            text,
            self.base_domain
        )

    async def probe_all(self, domains: list[str], round_idx: int = 1) -> list[ProbeResult]:
        js_label = "含 JS 深度分析" if self.analyze_js else "仅 HTTP 响应"
        console.rule(
            f"[bold cyan]HTTP 探活 · 第 {round_idx} 轮[/]  "
            f"[dim]({len(domains)} 个域名 / {js_label})[/]"
        )
        results: list[ProbeResult] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        # 禁用 SSL 校验（目标可能有自签名证书）
        limits = httpx.Limits(max_connections=self.concurrency, max_keepalive_connections=10)
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            limits=limits,
            headers=self._request_headers,
            cookies=self._cookies,
            proxy=self._proxy,
        ) as client:
            with make_progress(no_progress=self._no_progress, console=console) as progress:
                task = progress.add_task(
                    f"HTTP 探活中... (第 {round_idx} 轮)", total=len(domains)
                )

                async def _worker(domain: str) -> ProbeResult:
                    async with semaphore:
                        r = await self._probe(client, domain)
                        progress.advance(task)
                        if r.alive:
                            auth_tag = " [yellow]🔒SSO[/]" if r.requires_auth else ""
                            console.log(
                                f"[green][{r.status}][/]{auth_tag} {r.url} "
                                f"[dim]{r.title}[/] [cyan]{r.tech_str}[/]"
                            )
                        return r

                results = list(
                    await asyncio.gather(*[_worker(d) for d in domains])
                )

        alive = sum(1 for r in results if r.alive)
        console.print(
            f"[bold green][✓] 第 {round_idx} 轮探活完成[/] — "
            f"探测: [yellow]{len(results)}[/]  存活: [cyan]{alive}[/]"
        )
        return results

    async def _probe(self, client: httpx.AsyncClient, domain: str) -> ProbeResult:
        result = ProbeResult(domain=domain)
        result.ip = _resolve_ip(domain)

        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                t0 = time.monotonic()
                resp = await client.get(url)
                elapsed = int((time.monotonic() - t0) * 1000)

                result.url = str(resp.url)
                result.status = resp.status_code
                result.latency_ms = elapsed
                result.server = resp.headers.get("server", "-")
                result.powered_by = resp.headers.get("x-powered-by", "-")

                # 安全解码：用 .content 字节流 + errors='ignore'，
                # 避免 resp.text 遇到非 UTF-8 编码时抛 UnicodeDecodeError
                # 同时截取前 1MB，防止超大页面耗尽内存
                raw = resp.content[:1024 * 1024]
                text = raw.decode("utf-8", errors="ignore")

                result.title = _extract_title(text)
                result.tech = _detect_tech(resp.headers, text)

                # ── 检测 OAuth2/SSO 重定向 ────────────────────────
                via_sso, sso_url = _detect_sso_redirect(resp, self.base_domain)
                if via_sso:
                    result.requires_auth = True
                    result.sso_url = sso_url

                # ── 阶段一强化：精化 CSP/CORS 头部提取 ──────────────
                self._extract_from_security_headers(resp.headers, result)

                # ── 阶段一强化：HTML 全文域名扫描（Location、链接等）──
                html_domains = await self._async_extract_domains(text)
                for d in html_domains:
                    self._add_domain(d, result)

                # ── JS/SourceMap 深度分析（启用时才执行，并有全局超时保护）──
                if self.analyze_js:
                    try:
                        await asyncio.wait_for(
                            self._analyze_js_resources(client, resp.url, text, result),
                            timeout=self._JS_ANALYZE_GLOBAL_TIMEOUT,
                        )
                    except asyncio.TimeoutError:
                        console.log(
                            f"[yellow][JS分析] {domain} 超时 ({self._JS_ANALYZE_GLOBAL_TIMEOUT}s)，已中断[/]"
                        )
                    except Exception:
                        pass  # JS 分析失败不影响主流程

                result.alive = True
                return result
            except httpx.TimeoutException:
                result.error = "TIMEOUT"
            except httpx.ConnectError:
                result.error = "CONNECT_ERROR"
            except Exception as e:
                result.error = type(e).__name__

        return result

    def _extract_from_security_headers(
        self, headers: httpx.Headers, result: ProbeResult
    ) -> None:
        """
        专门解析 CSP 和 CORS 响应头，精确提取子域名。
        避免把 'self'、'none' 等 CSP 关键字误识别为域名。
        """
        # Content-Security-Policy
        csp = headers.get("content-security-policy", "")
        if csp:
            for d in _extract_domains_from_csp(csp, self.domain_regex):
                self._add_domain(d, result)
            # 提取 CSP report-uri 中可能藏有的收集端点域名
            report_uri = re.search(r"report-uri\s+(https?://[^\s;]+)", csp)
            if report_uri:
                for d in self.domain_regex.findall(report_uri.group(1)):
                    self._add_domain(d, result)

        # Access-Control-Allow-Origin
        cors = headers.get("access-control-allow-origin", "")
        if cors and cors != "*":
            for d in _extract_domains_from_cors(cors, self.domain_regex):
                self._add_domain(d, result)

        # Access-Control-Allow-Headers / Expose-Headers（偶尔含有域名）
        for h in ("access-control-allow-headers", "access-control-expose-headers"):
            val = headers.get(h, "")
            if val:
                for d in self.domain_regex.findall(val):
                    self._add_domain(d, result)

    async def _analyze_js_resources(
        self,
        client: httpx.AsyncClient,
        page_url,
        html: str,
        result: ProbeResult,
    ) -> None:
        """
        下载目标 JS 文件，扫描其中的子域名；
        若存在 SourceMap，进一步解析 .map 文件中的路径和字符串。

        每个请求均使用 asyncio.wait_for 加独立超时保护，防止单个慢速
        JS/SourceMap 文件拖死整个任务（全局超时由调用方 _probe 负责）。
        """
        base_url = str(page_url)
        # 提取所有 <script src="..."> 标签的链接
        script_srcs = self._script_src_regex.findall(html)
        # 只处理前 5 个目标 JS（防止无限制下载）
        target_scripts: list[str] = []
        for src in script_srcs:
            abs_url = urljoin(base_url, src)
            if _is_target_js(abs_url, self.base_domain):
                target_scripts.append(abs_url)
            if len(target_scripts) >= 5:
                break

        for js_url in target_scripts:
            try:
                js_resp = await asyncio.wait_for(
                    client.get(js_url),
                    timeout=self._JS_REQUEST_TIMEOUT,
                )
                if js_resp.status_code != 200:
                    continue

                js_text = js_resp.content.decode("utf-8", errors="ignore")
                # 在 JS 内容中搜索子域名 (交由独立进程处理，防止卡死)
                js_domains = await self._async_extract_domains(js_text)
                for d in js_domains:
                    if self._add_domain(d, result):
                        console.log(f"[dim magenta][JS] {js_url} → {d}[/]")

                # 尝试请求对应的 SourceMap 文件
                map_url = js_url + ".map"
                try:
                    map_resp = await asyncio.wait_for(
                        client.get(map_url),
                        timeout=self._JS_REQUEST_TIMEOUT,
                    )
                    if map_resp.status_code == 200:
                        console.log(f"[dim magenta][SourceMap] 解析: {map_url}[/]")
                        # SourceMap 是 JSON，sources 字段含源码路径
                        try:
                            map_data = json.loads(map_resp.text)
                            sources = map_data.get("sources", [])
                            sources_content = map_data.get("sourcesContent", [])
                            all_map_text = " ".join(
                                [str(s) for s in sources]
                                + [str(s) for s in sources_content if s]
                            )
                        except json.JSONDecodeError:
                            all_map_text = map_resp.content.decode("utf-8", errors="ignore")

                        map_domains = await self._async_extract_domains(all_map_text)
                        for d in map_domains:
                            if self._add_domain(d, result):
                                console.log(
                                    f"[dim magenta][SourceMap] {map_url} → {d}[/]"
                                )
                except (asyncio.TimeoutError, Exception):
                    pass  # SourceMap 不存在或超时，正常情况

            except asyncio.TimeoutError:
                console.log(f"[dim yellow][JS] 请求超时，已跳过: {js_url}[/]")
            except Exception:
                pass  # JS 下载失败，忽略

    def _add_domain(self, domain: str, result: ProbeResult) -> bool:
        """
        校验并将域名添加到 extracted_domains 中。
        返回 True 表示确实是新域名（非重复）。
        """
        domain = domain.strip().lower().strip(".")
        if (
            len(domain) <= 253
            and domain.endswith(f".{self.base_domain}")
            and ".." not in domain
            and not domain.startswith("-")
        ):
            if domain not in result.extracted_domains:
                result.extracted_domains.add(domain)
                return True
        return False
