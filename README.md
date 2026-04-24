# domain-recon

子域名枚举 + HTTP 探活工具，使用 Python 3.12+ 异步编写。

## 功能

| 功能 | 说明 |
|------|------|
| 子域名枚举 | 聚合 crt.sh、AlienVault OTX、HackerTarget 三个被动数据源 |
| HTTP 探活 | 异步并发探测，自动尝试 HTTPS / HTTP |
| 信息提取 | 状态码、网页标题、Server 头、技术栈指纹（Nginx/Apache/Harbor/GitLab 等）、IP、延迟 |
| 报告导出 | 终端彩色表格 + TXT + CSV |

## 安装

```bash
py -m pip install -r requirements.txt
```

## 使用

```bash
# 全流程：枚举子域名 + 探活
py main.py -d shu.edu.cn

# 只枚举子域名（不探活）
py main.py -d shu.edu.cn --enum-only

# 对已有列表探活（跳过枚举）
py main.py -l subdomains.txt

# 自定义并发数和超时
py main.py -d shu.edu.cn --concurrency 50 --timeout 8

# 指定输出目录
py main.py -d shu.edu.cn -o ./my_output
```

## 输出

```
output/
  shu.edu.cn_subdomains.txt   — 枚举到的全部子域名
  results_shu.edu.cn.txt      — 探活结果（纯文本）
  results_shu.edu.cn.csv      — 探活结果（CSV，可用 Excel 打开）
```
