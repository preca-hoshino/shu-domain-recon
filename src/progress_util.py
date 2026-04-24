"""
CI 兼容的进度条适配层
====================
在支持 TTY 的终端中，正常渲染 rich.Progress 动态进度条。
在 CI 环境（或手动传入 --no-progress）中，退化为逐行 print 的静态日志，
避免 ANSI 光标控制序列干扰 GitHub Actions / Jenkins 等日志面板的渲染。

用法:
    from src.progress_util import make_progress

    with make_progress(no_progress=args.no_progress, console=console) as progress:
        task = progress.add_task("描述", total=n)
        ...
        progress.advance(task)
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from typing import Generator, Optional

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


# ── CI 兼容的哑进度条对象 ──────────────────────────────────────
class _CIProgressStub:
    """
    在 --no-progress 模式下替代 rich.Progress 的哑对象。
    接口与 rich.Progress 保持兼容，调用 add_task / advance / update
    时只打印静态日志而不产生任何 ANSI 刷新序列。
    """

    def __init__(self, console: Optional[Console] = None) -> None:
        self._console = console or Console()
        self._tasks: dict[int, dict] = {}
        self._next_id = 0
        self._interval = 500  # 每累计推进多少步打印一次进度

    def add_task(self, description: str, total: Optional[int] = None, **kwargs) -> int:
        tid = self._next_id
        self._next_id += 1
        self._tasks[tid] = {
            "description": description,
            "total": total,
            "completed": 0,
        }
        label = f"{description}" + (f" (共 {total} 项)" if total else "")
        self._console.print(f"[cyan][进度] 开始: {label}[/]")
        return tid

    def advance(self, task_id: int, advance: int = 1) -> None:
        if task_id not in self._tasks:
            return
        t = self._tasks[task_id]
        t["completed"] += advance
        completed = t["completed"]
        total = t["total"]

        # 每 _interval 步，或到达终点时，打印一次静态进度
        if total and (completed % self._interval == 0 or completed >= total):
            pct = int(completed / total * 100)
            self._console.print(
                f"[dim][进度] {t['description']}: {completed}/{total} ({pct}%)[/]"
            )

    def update(self, task_id: int, description: Optional[str] = None, **kwargs) -> None:
        if task_id not in self._tasks:
            return
        if description:
            self._tasks[task_id]["description"] = description
            self._console.print(f"[dim][进度] 状态更新: {description}[/]")

    # 兼容 with Progress(...) as progress 的 __enter__/__exit__
    def __enter__(self):
        return self

    def __exit__(self, *args):
        # 打印最终完成汇总
        for t in self._tasks.values():
            completed = t["completed"]
            total = t["total"]
            if total and completed < total:
                self._console.print(
                    f"[dim][进度] {t['description']}: 完成 {completed}/{total}[/]"
                )
        return False


# ── 工厂函数 ──────────────────────────────────────────────────
@contextmanager
def make_progress(
    *,
    no_progress: bool = False,
    console: Optional[Console] = None,
    log_interval: int = 500,
) -> Generator:
    """
    返回一个上下文管理器包裹的进度条对象。

    Args:
        no_progress:  True 时返回哑对象（CI 模式），False 时返回标准 rich.Progress。
        console:      指定输出的 Console 实例，确保日志与进度条不交叉。
        log_interval: CI 模式下每推进多少步打印一次进度汇总（默认 500）。
    """
    _console = console or Console()

    if no_progress:
        stub = _CIProgressStub(console=_console)
        stub._interval = log_interval
        yield stub
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=_console,
        ) as progress:
            yield progress
