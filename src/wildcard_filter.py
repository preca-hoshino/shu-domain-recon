"""
泛解析智能穿透与内容感知过滤模块
===================================
标准泛解析过滤只通过 IP 对比来丢弃误报：如果一个爆破结果解析到了"脏 IP"，
就直接丢弃。但这有一个严重缺陷：

  ⚠️ 如果真实的业务域名恰好也解析到了这个泛解析 IP（常见于同一台反向代理/WAF 服务器），
     它会被误判为泛解析误报而被丢掉。

本模块实现"内容感知"的二次验证：
  1. 对解析到"脏 IP"的域名，发起实际 HTTP 请求
  2. 对比其响应内容与"泛解析基准页面"的内容哈希（Simhash）
  3. 如果内容显著不同（相似度 < 阈值），则认为这是一个真实的业务域名，予以保留

使用的哈希方法: Simhash（局部敏感哈希，适合文本相似度比较）
  - 计算流程: 分词 → 特征哈希 → 加权求和 → 取符号位
  - 相似度度量: 汉明距离（不同位的数量），距离越小越相似
  - 阈值选取: 汉明距离 > 8 认为是显著不同的内容（64位哈希下约 12.5% 差异）
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import re
import string
from typing import Optional

import httpx
from rich.console import Console

console = Console()

# Simhash 维度（位数）
_SIMHASH_BITS = 64
# 汉明距离阈值：超过此值认为内容不同（是真实业务页面）
_HAMMING_THRESHOLD = 8
# 内容感知 HTTP 请求超时（秒）
_VERIFY_TIMEOUT = 8
# 泛解析基准页面采样数量（采多个取平均，减少随机波动）
_BASELINE_SAMPLES = 3


def _random_str(length: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _tokenize(text: str) -> list[str]:
    """
    简单分词：提取 HTML 中的所有英文单词和中文字符作为特征 token。
    去掉脚本内容和标签，只保留可见文本特征。
    """
    # 移除 HTML 标签
    text = re.sub(r"<[^>]+>", " ", text)
    # 提取英文单词（长度 3~20）
    en_tokens = re.findall(r"[a-zA-Z]{3,20}", text)
    # 提取中文词（2~8 字）
    zh_tokens = re.findall(r"[\u4e00-\u9fff]{2,8}", text)
    return en_tokens + zh_tokens


def _simhash(text: str) -> int:
    """
    计算文本的 64 位 Simhash 值。

    算法:
      1. 分词，每个 token 计算 MD5 hash
      2. 对每个 bit 位累加权重（hash 对应位为 1 → +1，为 0 → -1）
      3. 最终每个 bit 取符号（>0 → 1，<=0 → 0）组成最终指纹
    """
    tokens = _tokenize(text)
    if not tokens:
        return 0

    v = [0] * _SIMHASH_BITS
    for token in tokens:
        h = int(hashlib.md5(token.encode("utf-8", errors="ignore")).hexdigest(), 16)
        for i in range(_SIMHASH_BITS):
            if h & (1 << i):
                v[i] += 1
            else:
                v[i] -= 1

    result = 0
    for i in range(_SIMHASH_BITS):
        if v[i] > 0:
            result |= 1 << i
    return result


def _hamming_distance(h1: int, h2: int) -> int:
    """计算两个整数的汉明距离（不同 bit 的数量）。"""
    xor = h1 ^ h2
    distance = 0
    while xor:
        distance += xor & 1
        xor >>= 1
    return distance


class WildcardFilter:
    """
    泛解析智能穿透过滤器。

    使用方法:
      1. 调用 calibrate(domain) 建立泛解析基准页面指纹
      2. 对每个"疑似泛解析误报"的域名调用 is_real(domain)
         返回 True 表示内容与泛解析不同，是真实业务域名
    """

    def __init__(
        self,
        base_domain: str,
        timeout: int = _VERIFY_TIMEOUT,
        hamming_threshold: int = _HAMMING_THRESHOLD,
    ) -> None:
        self.base_domain = base_domain
        self.timeout = timeout
        self.hamming_threshold = hamming_threshold
        self._baseline_hashes: list[int] = []  # 基准页面指纹列表
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "WildcardFilter":
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                )
            },
        )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._client:
            await self._client.aclose()

    async def calibrate(self, parent_domain: str) -> bool:
        """
        建立泛解析基准页面指纹。
        对 parent_domain 发起多次随机子域名请求，获取泛解析响应页面并计算 Simhash。

        Returns:
            True: 成功建立基准（说明存在泛解析）
            False: 请求全部失败（不存在泛解析，无需过滤）
        """
        self._baseline_hashes = []
        client = self._client
        if client is None:
            return False

        for _ in range(_BASELINE_SAMPLES):
            fake_domain = f"{_random_str()}.{parent_domain}"
            for scheme in ("https", "http"):
                url = f"{scheme}://{fake_domain}"
                try:
                    resp = await client.get(url)
                    content = resp.content[:512 * 1024].decode("utf-8", errors="ignore")
                    h = _simhash(content)
                    if h != 0:
                        self._baseline_hashes.append(h)
                    break  # HTTPS 成功就不再试 HTTP
                except Exception:
                    continue

        calibrated = len(self._baseline_hashes) > 0
        if calibrated:
            console.log(
                f"[WildcardFilter] {parent_domain} 泛解析基准已建立，"
                f"采集 {len(self._baseline_hashes)} 个样本"
            )
        return calibrated

    async def is_real(self, domain: str) -> bool:
        """
        对一个"疑似泛解析误报"的域名进行内容感知验证。

        Returns:
            True:  与基准内容显著不同，是真实业务域名
            False: 内容与基准相似，是泛解析误报
        """
        if not self._baseline_hashes:
            # 没有基准（泛解析检测失败），保守处理：保留该域名
            return True

        client = self._client
        if client is None:
            return True

        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                resp = await client.get(url)
                content = resp.content[:512 * 1024].decode("utf-8", errors="ignore")
                target_hash = _simhash(content)

                if target_hash == 0:
                    continue

                # 与所有基准样本比较，取最小汉明距离（最相似的一个）
                min_distance = min(
                    _hamming_distance(target_hash, bh)
                    for bh in self._baseline_hashes
                )

                is_different = min_distance > self.hamming_threshold
                if is_different:
                    console.log(
                        f"[WildcardFilter] ✓ 真实域名: {domain} "
                        f"(内容汉明距离={min_distance} > 阈值={self.hamming_threshold})"
                    )
                else:
                    console.log(
                        f"[WildcardFilter] ✗ 泛解析误报: {domain} "
                        f"(内容汉明距离={min_distance} ≤ 阈值={self.hamming_threshold})"
                    )
                return is_different

            except Exception:
                # 连接失败（域名不存在或超时），不是真实业务域名
                return False

        return False


async def verify_batch(
    domains: list[str],
    parent_domain: str,
    base_domain: str,
    concurrency: int = 20,
    timeout: int = _VERIFY_TIMEOUT,
    hamming_threshold: int = _HAMMING_THRESHOLD,
) -> list[str]:
    """
    批量对"疑似泛解析误报"的域名进行内容感知验证。

    Args:
        domains:           需要验证的域名列表（解析到了脏 IP 但不确定真实性）
        parent_domain:     父级域名（用于建立泛解析基准，如 dept.shu.edu.cn）
        base_domain:       根域名（如 shu.edu.cn）
        concurrency:       并发请求数
        timeout:           单次 HTTP 请求超时
        hamming_threshold: 汉明距离阈值

    Returns:
        确认为真实业务域名的域名列表
    """
    if not domains:
        return []

    real_domains: list[str] = []
    semaphore = asyncio.Semaphore(concurrency)

    async with WildcardFilter(base_domain, timeout, hamming_threshold) as wf:
        calibrated = await wf.calibrate(parent_domain)
        if not calibrated:
            console.log(
                f"[WildcardFilter] 无法建立 {parent_domain} 的泛解析基准，"
                "跳过内容感知验证，全部保留"
            )
            return domains

        async def _check(domain: str) -> Optional[str]:
            async with semaphore:
                if await wf.is_real(domain):
                    return domain
                return None

        results = await asyncio.gather(*[_check(d) for d in domains])
        real_domains = [r for r in results if r is not None]

    console.log(
        f"[WildcardFilter] 验证完成: {len(domains)} → {len(real_domains)} 个真实域名"
    )
    return real_domains
