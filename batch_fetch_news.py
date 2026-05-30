"""
批量抓取上海大学各子域名网站的新闻集合页面
"""
import re
import urllib.request
import urllib.error
import ssl
import time
import json

# 忽略 SSL 错误
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

def fetch_html(url, timeout=10):
    """获取页面 HTML"""
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        resp = urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx)
        return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return None

def resolve_url(href, base_url):
    """将相对路径转为完整URL"""
    href = href.strip()
    if not href or href.startswith('javascript:') or href.startswith('#'):
        return None
    if href.startswith('/'):
        domain = re.match(r'https?://[^/]+', base_url)
        if domain:
            return domain.group(0) + href
    elif not href.startswith('http'):
        if base_url.endswith('/'):
            return base_url + href
        else:
            return base_url.rstrip('/') + '/' + href.lstrip('/')
    return href

# 新闻/公告类关键字
NEWS_KEYWORDS = ['新闻', '公告', '通知', '动态', '周志', '学术报告', '学术会议', 
                  '科研', '活动', '学院新闻', '部门新闻', '工作动态', '信息发布',
                  '综合新闻', '学术动态', '科研动态', '学生活动', '党建工作',
                  'News', 'Events', '通知公告', '院务公开', '信息公告']

def extract_news_pages(html, base_url):
    """从 HTML 中提取新闻集合页链接"""
    if not html:
        return []
    
    results = []
    seen = set()
    
    # 找到所有 a 标签
    links = re.findall(r'<a[^>]*href=["\']([^"\']*)["\'][^>]*>(.*?)</a>', html, re.IGNORECASE | re.DOTALL)
    
    for href, raw_text in links:
        text = re.sub(r'<[^>]+>', '', raw_text).strip()
        
        # 策略1: "更多>>" / "更多" 链接
        if text in ('更多>>', '更多', 'MORE', 'more >>', 'more'):
            url = resolve_url(href, base_url)
            if url and url not in seen:
                seen.add(url)
                results.append({'url': url, 'section': ''})
        
        # 策略2: 导航菜单中含新闻类关键词的链接
        elif any(kw in text for kw in NEWS_KEYWORDS) and len(text) <= 15:
            url = resolve_url(href, base_url)
            if url and url not in seen:
                # 排除单篇新闻文章链接（通常带 /info/数字/）
                if not re.search(r'/info/\d+/', url):
                    seen.add(url)
                    results.append({'url': url, 'section': text})
    
    # 为 "更多>>" 链接尝试匹配栏目标题
    for r in results:
        if r['section'] == '':
            # 在 HTML 中搜索链接前的 header
            escaped = re.escape(r['url'].split('/')[-1])
            pattern = re.compile(
                r'(?:<h[234][^>]*>|class=["\'][^"\']*tit[^"\']*["\']\s*>)\s*([^<]{2,30})\s*(?:</h[234]>|</(?:div|span|p)>).*?' + escaped,
                re.DOTALL | re.IGNORECASE
            )
            m = pattern.search(html)
            if m:
                r['section'] = m.group(1).strip()
    
    return results


# 从 analysis_report.md 中提取有标题的域名
report_path = r'd:\Code Library\SHU-Domain-Recon\output\shu.edu.cn\analysis_report.md'

with open(report_path, 'r', encoding='utf-8') as f:
    content = f.read()

# 提取表格行
rows = re.findall(r'\|\s*(\d+)\s*\|\s*\[([^\]]+)\]\(([^)]+)\)\s*\|\s*([^|]+)\s*\|', content)

# 过滤：有实际标题的站点（排除系统提示、错误、空白等）
skip_titles = ['-', '', ' ', '系统提示', '访问受限', '管理员登录', 'Bad Request', '系统异常',
               'HTTP500 内部服务器出错', 'HTTP状态 404 - 未找到', '404 Not Found',
               '404错误提示', '403 Forbidden', '400', '404', 'Welcome to CentOS',
               'Loading...', '上海大学统一身份认证']

sites = []
seen_urls = set()

for status, name, url, title in rows:
    title = title.strip()
    if title not in skip_titles:
        # 去重(同一主站只保留一个)
        base = re.match(r'(https?://[^/]+)', url)
        if base:
            base_url = base.group(1)
            if base_url not in seen_urls:
                seen_urls.add(base_url)
                sites.append({
                    'name': name.strip(),
                    'url': base_url,
                    'title': title
                })

print(f"待处理站点数: {len(sites)}")

# 处理每个站点
results = []
for i, site in enumerate(sites):
    print(f"[{i+1}/{len(sites)}] {site['url']} - {site['title']}")
    try:
        html = fetch_html(site['url'])
        if html:
            news_pages = extract_news_pages(html, site['url'])
            site['news_pages'] = news_pages
            if news_pages:
                print(f"  找到 {len(news_pages)} 个新闻集合页")
                for np in news_pages:
                    print(f"    -> {np['url']}")
            else:
                print(f"  未找到新闻集合页")
        else:
            site['news_pages'] = []
            print(f"  无法访问")
    except Exception as e:
        site['news_pages'] = []
        print(f"  错误: {e}")
    
    results.append(site)
    time.sleep(0.5)  # 避免请求过快

# 保存为 Markdown
output_path = r'd:\Code Library\SHU-Domain-Recon\output\shu.edu.cn\news_collections.md'
with open(output_path, 'w', encoding='utf-8') as f:
    f.write('# 上海大学子域名 - 新闻集合页面汇总\n\n')
    f.write(f'> 扫描日期: 2026-04-27\n')
    f.write(f'> 总计: {len(results)} 个站点\n\n')
    f.write('---\n\n')
    
    has_news = [s for s in results if s['news_pages']]
    no_news = [s for s in results if not s['news_pages']]
    
    f.write(f'## 有新闻集合页的站点 ({len(has_news)} 个)\n\n')
    
    for site in has_news:
        f.write(f'### {site["title"]}\n')
        f.write(f'- **主站**: {site["url"]}\n')
        f.write(f'- **新闻集合页**:\n')
        for np in site['news_pages']:
            section = f' ({np["section"]})' if np['section'] else ''
            f.write(f'  - [{np["url"]}]({np["url"]}){section}\n')
        f.write('\n')
    
    f.write(f'---\n\n')
    f.write(f'## 未找到新闻集合页的站点 ({len(no_news)} 个)\n\n')
    f.write('| 标题 | URL |\n')
    f.write('| :--- | :--- |\n')
    for site in no_news:
        f.write(f'| {site["title"]} | {site["url"]} |\n')

print(f"\n完成! 输出文件: {output_path}")
print(f"有新闻集合页: {len(has_news)} 个")
print(f"无新闻集合页: {len(no_news)} 个")
