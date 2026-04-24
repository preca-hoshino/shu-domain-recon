# SHU-Domain-Recon

上海大学域名资产侦察工具。基于 Python 3.11+ 异步架构实现，涵盖多阶段子域名发现、HTTP 存活探测及 CI 持续监控，适用于高校网络资产梳理场景。

## 功能概述

- **多源被动枚举**：聚合 7 个公开威胁情报数据源，叠加 Wayback Machine 历史记录抓取，覆盖最大化。
- **主动 DNS 爆破**：支持 AXFR 区域传输检测、变异字典生成，内置 Simhash 泛解析过滤机制，抑制误报。
- **多级递归发现**：对容器型节点（如 `*.sub.domain.com`）自动展开递归爆破，发现隐藏层级资产。
- **HTTP 深度探活**：异步并发探测，采集状态码、标题、服务端指纹、技术栈等字段；解析 CSP/CORS 响应头及 JS/SourceMap 文件，提取内部 API 端点与子域名引用。
- **IP 空间横向拓展**：对存活资产的 IP 执行 PTR 反向解析与 TLS 证书 SAN 字段提取，自动推断 C 段/B 段归属。
- **身份验证支持**：加载 Chrome DevTools 导出的 `curl.cmd` 文件，自动注入 Cookie 及自定义请求头，探测需要 SSO 认证的内网系统。
- **持续监控集成**：内置 GitHub Actions 工作流，定时执行侦察流程并将 Markdown 格式差异报告自动提交至仓库，实现无人值守监控。

## 安装

```bash
git clone https://github.com/preca-hoshino/shu-domain-recon.git
cd shu-domain-recon
python -m pip install -r requirements.txt
```

## 使用

命令格式：

```bash
python run.py <目标域名> <最高并发量> [选项]
```

示例：

```bash
# 全流程侦察（推荐并发量 200~500）
python run.py shu.edu.cn 300

# 仅输出 Markdown 分析报告，跳过 CSV / JSON / TXT 等附属文件（适合 CI 场景）
python run.py shu.edu.cn 300 --md-only

# 携带浏览器认证信息，跳过已知资产并排除黑名单域名
python run.py shu.edu.cn 300 --curl curl.cmd --blacklist blacklist.txt

# 仅执行被动枚举与 HTTP 探活，跳过 DNS 爆破和 IP 横向扫描
python run.py shu.edu.cn 300 --skip-brute --skip-ip-scan
```

### 参数说明

| 参数 | 说明 |
| :--- | :--- |
| `domain` | 目标根域名，例如 `shu.edu.cn`（必填） |
| `concurrency` | 各模块并发上限（必填），推荐 200~1000 |
| `--curl <file>` | Chrome DevTools 导出的 `curl.cmd` 文件路径，自动提取 Cookie 与请求头 |
| `--blacklist <file>` | 黑名单文件路径，每行一个域名，匹配项及其子域将被排除 |
| `--recursive-depth <N>` | 递归爆破最大层数，默认 `2` |
| `--skip-passive` | 跳过被动枚举阶段 |
| `--skip-brute` | 跳过 DNS 字典爆破阶段 |
| `--skip-recursive` | 跳过递归爆破阶段 |
| `--skip-probe` | 跳过 HTTP 探活阶段 |
| `--skip-js` | 探活阶段跳过 JS/SourceMap 深度分析 |
| `--skip-ip-scan` | 跳过 IP 空间横向扫描阶段 |
| `--md-only` | 仅生成 Markdown 分析报告，不写入其他格式文件 |

## 输出

所有结果写入 `output/<目标域名>/` 目录：

| 文件 | 内容 |
| :--- | :--- |
| `analysis_report.md` | 存活资产汇总分析，含 SSO 状态标记与 C/B 段推断，按中文标题资产优先排序 |
| `subdomains.txt` | 枚举阶段发现的全部子域名列表 |
| `results.csv` | 结构化探活结果，可直接用 Excel 打开 |
| `results.json` | 带元信息的完整 JSON 数据，适合对接 Nuclei、ELK 等下游工具 |
| `inferred_ip_ranges.txt` | 基于存活 IP 推断的目标网段（C 段 / B 段） |

## CI 持续监控

项目内置 GitHub Actions 工作流 (`.github/workflows/domain-recon.yml`)，配置了以下运行策略：

- **定时执行**：每日 UTC 22:00（北京时间次日 06:00）自动触发。
- **手动触发**：在 Actions 页面点击 Run workflow 可即时执行。
- **自动提交**：侦察完成后，若 `analysis_report.md` 内容发生变化，工作流自动将其 Commit 并推送至仓库，便于通过 Git 历史追踪资产变更。
