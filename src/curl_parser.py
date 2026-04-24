"""
curl.cmd 解析器
===============
将 Chrome DevTools 导出的 Windows CMD 格式 curl 命令文件解析为
cookies 字典和 extra_headers 字典，供 DomainProber 使用。

支持格式（Chrome "Copy as cURL (cmd)"）:
  curl ^"URL^" ^
    -H ^"Name: Value^" ^
    -b ^"key1=val1; key2=val2^" ^

Windows CMD 转义规则（关键）:
  ^"          参数边界引号，包裹含空格的参数内容
  [插入符][反斜杠][插入符]"  参数值内部的字面双引号（4个字符），必须比 ^" 优先匹配
  ^%          字面百分号（防止 CMD 把 %var% 当变量展开）
  ^^          字面插入符 ^
"""

from __future__ import annotations

import re
from pathlib import Path


# 侦察时不需要透传的浏览器专属头
_SKIP_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "if-modified-since",  # 缓存协商头，侦察时无意义
    "if-none-match",      # 缓存协商头，侦察时无意义
}


def _split_cmd_args(text: str) -> list[str]:
    """
    使用状态机将 Windows CMD 命令行拆分为参数列表。

    核心规则（优先级从高到低）:
      1. [^][backslash][^]" -> "   内嵌字面引号，必须先于 ^" 检测
      2. ^"  -> 切换 in_quoted 状态
      3. ^%  -> %
      4. ^^  -> ^
      5. ^ + 普通字符 -> 仅保留后续字符（CMD fallback）
      6. 普通空白（未在引号内）-> 分割 token
    """
    args: list[str] = []
    current: list[str] = []
    in_quoted = False
    i = 0

    while i < len(text):
        # ── 优先级 1: ^\^"  (4 字符，内嵌字面引号) ──
        # 匹配原始字节序列: 0x5E 0x5C 0x5E 0x22
        if i + 3 < len(text) and text[i] == '^' and text[i+1] == '\\' and text[i+2] == '^' and text[i+3] == '"':
            current.append('"')
            i += 4
            continue

        # ── 优先级 2: ^"  (引号边界) ──
        if text[i:i+2] == '^"':
            if in_quoted:
                # 关闭引号 → token 结束
                args.append("".join(current))
                current = []
                in_quoted = False
            else:
                in_quoted = True
            i += 2
            continue

        # ── 优先级 3: ^%  →  % ──
        if text[i:i+2] == '^%':
            current.append('%')
            i += 2
            continue

        # ── 优先级 4: ^^  →  ^ ──
        if text[i:i+2] == '^^':
            current.append('^')
            i += 2
            continue

        # ── 续行符 ^ + 换行 ──
        if text[i] == '^' and i + 1 < len(text) and text[i+1] in ('\r', '\n'):
            i += 2
            if i < len(text) and text[i] == '\n':
                i += 1
            continue

        # ── ^ + 普通字符 → 去掉 ^，保留后续字符（CMD fallback 规则）──
        # 例: ^2 → 2，使 ^%^2F 整体 → %2F
        if text[i] == '^' and i + 1 < len(text):
            current.append(text[i + 1])
            i += 2
            continue

        # ── 普通字符 ──
        ch = text[i]
        if in_quoted:
            current.append(ch)
        else:
            if ch in (' ', '\t', '\r', '\n'):
                if current:
                    args.append("".join(current))
                    current = []
            else:
                current.append(ch)
        i += 1

    if current:
        args.append("".join(current))

    return [a for a in args if a]


def parse_curl_cmd(
    filepath: str | Path,
) -> tuple[dict[str, str], dict[str, str]]:
    """
    解析 Windows CMD 格式的 curl 命令文件。

    参数:
        filepath: curl.cmd 文件路径

    返回:
        (cookies, extra_headers)
        cookies:       从 -b 参数中提取的 Cookie 字典
        extra_headers: 从 -H 参数中提取的请求头字典（已过滤浏览器专属头）
    """
    text = Path(filepath).read_text(encoding="utf-8", errors="replace")
    args = _split_cmd_args(text)

    cookies: dict[str, str] = {}
    extra_headers: dict[str, str] = {}

    i = 0
    while i < len(args):
        arg = args[i]

        # -b <cookie_string>
        if arg == "-b" and i + 1 < len(args):
            raw_cookies = args[i + 1]
            for pair in raw_cookies.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    cookies[k.strip()] = v.strip()
            i += 2
            continue

        # -H <Name: Value>
        if arg == "-H" and i + 1 < len(args):
            raw_header = args[i + 1]
            if ":" in raw_header:
                k, _, v = raw_header.partition(":")
                name_lower = k.strip().lower()
                if name_lower not in _SKIP_HEADERS:
                    extra_headers[k.strip()] = v.strip()
            i += 2
            continue

        i += 1

    return cookies, extra_headers


def summarize(cookies: dict[str, str], headers: dict[str, str]) -> str:
    """生成解析结果的简洁摘要字符串（用于日志输出）。"""
    cookie_keys = list(cookies.keys())
    header_keys = list(headers.keys())
    return (
        f"Cookie({len(cookie_keys)}): [{', '.join(cookie_keys[:5])}"
        f"{'...' if len(cookie_keys) > 5 else ''}]  "
        f"Header({len(header_keys)}): [{', '.join(header_keys[:5])}"
        f"{'...' if len(header_keys) > 5 else ''}]"
    )
