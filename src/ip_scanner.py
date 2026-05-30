"""
IP 反查与 TLS 证书扫描模块
===========================
阶段三核心功能，脱离"基于域名"的思维，转变为"基于 IP 空间"的探测。

功能一：IP C段反查 (PTR / Reverse DNS)
  - 汇总已探测域名的 A 记录 IP
  - 统计高频出现的目标 C段（排除云厂商/CDN IP）
  - 对目标 C段批量发起 PTR 反向 DNS 查询
  - 过滤出以目标域结尾的主机名

功能二：TLS 证书主动刺探 (SAN 提取)
  - 对目标 C段 IP 的 443/8443/8444 端口发起 TLS 握手
  - 解析服务端证书的 Subject Alternative Name (SAN) 扩展字段
  - 提取匹配主域名的所有 SAN 条目
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections import Counter
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


# 已知云厂商和 CDN 的 IP 段前缀，检测后排除（避免扫描无关的公共基础设施）
_CLOUD_CDN_PREFIXES = [
    "104.", "172.64.", "172.65.", "172.66.", "172.67.",  # Cloudflare
    "151.101.",  # Fastly
    "13.", "52.", "54.", "34.", "35.",  # AWS
    "23.",  # Akamai
    "42.236.", "42.237.", "42.238.", "42.239.",  # 腾讯云部分 IP
]

# 目标 TLS 探测端口
_TLS_PORTS = [443, 8443, 8444]

# 最大并发数默认值（如果未通过构造器传入，则使用此安全默认値）
_DEFAULT_PTR_CONCURRENCY = 200
_DEFAULT_TLS_CONCURRENCY = 50


def _is_cloud_ip(ip: str) -> bool:
    """判断 IP 是否属于已知云/CDN 服务商，是则排除。"""
    for prefix in _CLOUD_CDN_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def _get_c_class(ip: str) -> Optional[str]:
    """从 IP 地址提取 C 段前缀（如 '202.120.3'）。"""
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}"
    except Exception:
        pass
    return None


class IPScanner:
    """
    基于 IP 空间的横向扩展扫描器。
    输入：存活域名的 IP 映射字典 {domain: ip_str}
    输出：新发现的子域名集合
    """

    def __init__(
        self,
        base_domain: str,
        domain_ip_map: dict[str, str],
        ptr_concurrency: int = _DEFAULT_PTR_CONCURRENCY,
        tls_concurrency: int = _DEFAULT_TLS_CONCURRENCY,
        no_progress: bool = False,
    ) -> None:
        self.base_domain = base_domain.lower().strip()
        self.domain_ip_map = domain_ip_map
        self._ptr_concurrency = ptr_concurrency
        self._tls_concurrency = tls_concurrency
        self._no_progress = no_progress
        self._new_domains: set[str] = set()
        self.target_c_classes: set[str] = set()
        self.target_b_classes: set[str] = set()


    async def run(self) -> list[str]:
        """执行完整的 IP 空间扫描流程。"""
        console.rule("[bold cyan]阶段三：IP 空间横向扩展扫描")

        # 1. 汇总目标 IP 并确定高频 C 段和 B 段
        self.target_c_classes = self._identify_target_c_classes()
        self.target_b_classes = self._identify_target_b_classes(self.target_c_classes)
        
        if not self.target_c_classes:
            console.print("[yellow][IP扫描] 未能识别出有效的目标 C段，跳过[/]")
            return []

        console.print(
            f"[cyan][IP扫描] 推断出 {len(self.target_b_classes)} 个 B段, {len(self.target_c_classes)} 个目标 C段"
        )

        # 2. 生成全部目标 IP（每个 C 段 254 个 IP）
        all_target_ips: list[str] = []
        for c_class in self.target_c_classes:
            for i in range(1, 255):
                all_target_ips.append(f"{c_class}.{i}")

        console.print(
            f"[cyan][IP扫描] 共 {len(all_target_ips)} 个 IP 待扫描"
        )

        # 3. PTR 反向 DNS 查询
        await self._ptr_scan(all_target_ips)

        # 4. TLS 证书 SAN 提取
        await self._tls_scan(all_target_ips)

        found = sorted(self._new_domains)
        console.print(
            f"[bold green][IP扫描] 完成[/] — 通过 IP 空间新发现 {len(found)} 个子域名"
        )
        return found

    # ── 内部方法 ───────────────────────────────────────────────
    def _identify_target_c_classes(self) -> set[str]:
        """
        统计域名 IP 的 C 段分布，筛选出属于目标单位的高频 C 段。
        过滤条件：
          1. 排除云/CDN IP
          2. 同一 C 段内至少有 2 个已知域名指向（避免扫描偶然 IP）
        """
        c_class_counter: Counter[str] = Counter()
        for domain, ip in self.domain_ip_map.items():
            if not ip or ip == "-":
                continue
            if _is_cloud_ip(ip):
                continue
            c = _get_c_class(ip)
            if c:
                c_class_counter[c] += 1

        # 只选择出现频率 >= 2 的 C 段（避免扫描单个偶然 IP）
        target: set[str] = {c for c, count in c_class_counter.items() if count >= 2}
        return target

    def _identify_target_b_classes(self, c_classes: set[str]) -> set[str]:
        """
        根据识别出的 C 段，推断可能拥有的 B 段（/16）。
        如果某个 B 段下包含 2 个以上的 C 段，我们推断该单位可能拥有该 B 段的部分或全部。
        """
        b_class_counter: Counter[str] = Counter()
        for c in c_classes:
            parts = c.split(".")
            if len(parts) == 3:
                b = f"{parts[0]}.{parts[1]}"
                b_class_counter[b] += 1
        
        # 只要有 >= 1 个 C段 也可以算作拥有该 B 段的子网，这里放宽条件提取所有涉及的 B 段
        target: set[str] = {b for b, count in b_class_counter.items()}
        return target

    async def _ptr_scan(self, ips: list[str]) -> None:
        """对目标 IP 列表批量发起 PTR 反向 DNS 查询。"""
        console.print(f"[cyan][PTR扫描] 开始对 {len(ips)} 个 IP 进行反向 DNS 查询...")
        resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "223.5.5.5", "119.29.29.29"])
        semaphore = asyncio.Semaphore(self._ptr_concurrency)
        found_count = 0

        with make_progress(no_progress=self._no_progress, console=console) as progress:
            task = progress.add_task("PTR 反查中...", total=len(ips))

            async def _ptr_worker(ip: str) -> None:
                nonlocal found_count
                async with semaphore:
                    try:
                        reversed_ip = ".".join(reversed(ip.split(".")))
                        ptr_name = f"{reversed_ip}.in-addr.arpa"
                        result = await resolver.query(ptr_name, "PTR")
                        for record in result:
                            hostname = str(record.host).rstrip(".")
                            if hostname.endswith(f".{self.base_domain}") or hostname == self.base_domain:
                                self._new_domains.add(hostname.lower())
                                found_count += 1
                                console.log(f"[green][PTR] {ip} → {hostname}[/]")
                    except Exception:
                        pass
                    finally:
                        progress.advance(task)

            await asyncio.gather(*[_ptr_worker(ip) for ip in ips], return_exceptions=True)


        console.print(f"[green][PTR扫描] 完成，发现 {found_count} 条有效反查记录[/]")

    async def _tls_scan(self, ips: list[str]) -> None:
        """对目标 IP 的 TLS 端口发起握手，提取证书 SAN 字段。"""
        console.print(
            f"[cyan][TLS扫描] 开始对 {len(ips)} 个 IP 的 "
            f"{_TLS_PORTS} 端口进行证书探测..."
        )
        semaphore = asyncio.Semaphore(self._tls_concurrency)
        found_count = 0
        total_tasks = len(ips) * len(_TLS_PORTS)

        with make_progress(no_progress=self._no_progress, console=console) as progress:
            task = progress.add_task("TLS 证书探测中...", total=total_tasks)


            async def _tls_worker(ip: str, port: int) -> None:
                nonlocal found_count
                async with semaphore:
                    try:
                        domains_found = await _grab_cert_san(ip, port, self.base_domain)
                        for d in domains_found:
                            if d not in self._new_domains:
                                self._new_domains.add(d)
                                found_count += 1
                                console.log(
                                    f"[magenta][TLS] {ip}:{port} 证书 SAN → {d}[/]"
                                )
                    except Exception:
                        pass
                    finally:
                        progress.advance(task)

            tasks = [
                _tls_worker(ip, port)
                for ip in ips
                for port in _TLS_PORTS
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        console.print(f"[green][TLS扫描] 完成，从证书 SAN 发现 {found_count} 个新域名[/]")


async def _grab_cert_san(ip: str, port: int, base_domain: str) -> list[str]:
    """
    对指定 IP:Port 发起 TLS 握手，获取服务端证书并解析 SAN 字段。
    返回所有与 base_domain 匹配的子域名列表。
    """
    found: list[str] = []
    loop = asyncio.get_event_loop()

    def _blocking_tls() -> list[str]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((ip, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        # getpeercert() 在 CERT_NONE 下返回空，改用 DER 解析
                        der_cert = ssock.getpeercert(binary_form=True)
                        if der_cert:
                            return _parse_san_from_der(der_cert, base_domain)
                        return []

                    result: list[str] = []
                    # 标准格式下直接读取 subjectAltName
                    for san_type, san_value in cert.get("subjectAltName", []):
                        if san_type.upper() == "DNS":
                            san_value = san_value.lower().lstrip("*.")
                            if san_value.endswith(f".{base_domain}") or san_value == base_domain:
                                result.append(san_value)
                    return result
        except Exception:
            return []

    try:
        result = await loop.run_in_executor(None, _blocking_tls)
        found.extend(result)
    except Exception:
        pass

    return found


def _parse_san_from_der(der_cert: bytes, base_domain: str) -> list[str]:
    """
    当标准 getpeercert() 不返回字段时（CERT_NONE 模式），
    使用 cryptography 库从 DER 格式证书中解析 SAN。
    若 cryptography 未安装，则降级到字符串搜索。
    """
    found: list[str] = []
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in san_ext.value.get_values_for_type(x509.DNSName):
                name = name.lower().lstrip("*.")
                if name.endswith(f".{base_domain}") or name == base_domain:
                    found.append(name)
        except x509.ExtensionNotFound:
            pass
    except ImportError:
        # cryptography 未安装：降级为正则字符串搜索（准确性略低）
        import re
        pattern = re.compile(
            r"([a-zA-Z0-9][a-zA-Z0-9.-]*\." + re.escape(base_domain) + r")",
            re.IGNORECASE,
        )
        # DER 是二进制，尝试解码为 latin-1 后搜索
        try:
            text = der_cert.decode("latin-1")
            found.extend(m.lower() for m in pattern.findall(text))
        except Exception:
            pass
    return found
