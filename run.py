import sys
import asyncio
from pathlib import Path

# 确保能正确导入 src 模块
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.main import _parse_args, _print_banner, main

if __name__ == "__main__":
    args = _parse_args()

    _domain = args.domain.strip().lower()
    _concurrency = args.concurrency
    if _concurrency < 1:
        print("错误: 最高并发量必须为正整数")
        sys.exit(1)

    _print_banner(_domain, _concurrency, args)
    try:
        asyncio.run(main(_domain, _concurrency, args))
    except Exception as e:
        import traceback
        with open("error_trace.txt", "w") as f:
            traceback.print_exc(file=f)

    finally:
        from src.prober import force_shutdown_process_pool
        force_shutdown_process_pool()
        import os
        os._exit(0)
