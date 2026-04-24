# SHU-Domain-Recon

上海大学域名资产侦察工具 (Domain Reconnaissance Tool) — 自动化多阶段子域名发现与深度探活。

基于 Python 3.11+ 异步编写，具备高并发、广度优先爬取、自动化资产分析以及 GitHub Actions CI 集成能力。

## 🌟 核心特性

- **多源被动枚举**：聚合 7 大公开数据源、Wayback Machine 历史记录抓取。
- **主动 DNS 爆破**：支持 AXFR 区域传输检测、动态变异字典爆破、智能 Simhash 泛解析过滤机制。
- **递归深度发现**：针对容器型节点（如 `*.a.domain.com`）自动进行多级递归爆破。
- **全方位 HTTP 探活**：异步并发探测，智能抓取 CSP/CORS 头，深度解析 HTML/JS/SourceMap 提取隐藏的 API 和内部子域名。
- **IP 空间横向拓展**：自动提取存活资产 IP，进行 C 段 / B 段推断，通过 PTR 反向解析和 TLS 证书 SAN 提取隐蔽资产。
- **认证绕过与黑名单**：支持加载 Chrome 导出的 `curl.cmd` 自动携带 Cookie 与请求头绕过 SSO；支持灵活的域名黑名单过滤。
- **自动化监控 (CI/CD)**：内置 GitHub Actions 工作流，每天自动运行并提交 Markdown 格式的资产变更报告。

## 📦 安装与配置

```bash
# 1. 克隆代码
git clone https://github.com/preca-hoshino/shu-domain-recon.git
cd shu-domain-recon

# 2. 安装依赖
python -m pip install -r requirements.txt
```

## 🚀 快速使用

基本命令格式：
```bash
python run.py <目标域名> <最高并发量> [选项]
```

### 常用命令示例

```bash
# 全流程：对 shu.edu.cn 进行全面资产侦察，最高并发 300（推荐）
python run.py shu.edu.cn 300

# 仅生成 Markdown 报告（不输出 CSV/JSON/TXT 等其他文件，适合配合 CI 自动化监控使用）
python run.py shu.edu.cn 300 --md-only

# 加载浏览器导出的 curl.cmd 以绕过身份验证，并应用黑名单
python run.py shu.edu.cn 300 --curl curl.cmd --blacklist blacklist.txt

# 指定只进行某个阶段的测试（例如跳过 DNS 爆破和 IP 空间扫描）
python run.py shu.edu.cn 300 --skip-brute --skip-ip-scan
```

### 完整参数列表

| 参数 / 选项 | 说明 |
| :--- | :--- |
| `domain` | **必填**。目标域名，例如：`shu.edu.cn` |
| `concurrency` | **必填**。模块并发上限（推荐 200~1000） |
| `--curl <file>` | 直接加载 Chrome DevTools 导出的 `curl.cmd` 自动提取 Cookie + 请求头 |
| `--blacklist <file>` | 黑名单域名文件路径（每行一个），匹配的域名将被跳过 |
| `--recursive-depth <N>` | 递归爆破的最大层数（默认 `2` 层） |
| `--skip-passive` | 跳过被动子域名枚举阶段 |
| `--skip-brute` | 跳过 DNS 字典爆破阶段 |
| `--skip-recursive` | 跳过多级递归子域名爆破阶段 |
| `--skip-probe` | 跳过 HTTP 探活阶段 |
| `--skip-js` | 在 HTTP 探活阶段跳过 JS/SourceMap 深度分析 |
| `--skip-ip-scan` | 跳过 IP 空间横向扫描阶段 |
| `--md-only` | 只生成 Markdown 分析报告，不输出其他格式的结果文件 |

## 📁 报告与输出

所有执行结果都会自动在 `output/<目标域名>/` 目录下生成专属报告：

- `analysis_report.md`：核心分析报告（包含存活资产列表、SSO 认证状态、推断的 C 段/B 段，自动按包含中文标题的页面优先级排序）。
- `subdomains.txt`：所有发现的有效子域名的纯文本列表。
- `results.csv`：结构化的存活探活结果（支持 Excel 打开）。
- `results.json`：带有 Metadata 元信息的完整 JSON 数据，便于对接 Nuclei 或 ELK。
- `inferred_ip_ranges.txt`：基于横向扫描推测出的目标网段分布。

## 🤖 自动化持续监控 (GitHub Actions)

本项目内置了自动化 CI 配置 `.github/workflows/domain-recon.yml`。
它会每天自动运行 `python run.py shu.edu.cn 300 --md-only`，并将生成的最新 `analysis_report.md` 直接 Commit 到本仓库。

**配置优势：**
- **实时显示：** 配置了 `PYTHONUNBUFFERED` 和 `FORCE_COLOR` 环境变量，能够在 Actions 的 Console 界面输出美观、无延迟的彩色终端日志。
- **免维护：** 只需要推送至 GitHub，云端即会自动按期执行侦察，实现对高校网络资产变更情况的无人值守监控。
