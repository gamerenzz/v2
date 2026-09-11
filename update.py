import base64
import json
import re
import requests
import yaml
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 1. 解密密钥与偏移量 (AES-256-CBC)
KEY = b"36KeAARKZuKF39N9LFyycLUyKMhZDq0B"
IV = b"36KeAARKZuKF39N9"

# 2. 备用固定链接（用于 API 速率限制时的兜底）
STATIC_FALLBACK_URLS = [
    "https://raw.githubusercontent.com/bannedbook/fanqiang/master/docs/vsp-cn.py"
]

def get_latest_remote_urls():
    """
    通过 GitHub API 自动扫描 docs/ 目录下所有 .py 文件，
    并按最新提交时间（Commit Date）从新到旧排序返回下载链接列表。
    """
    dynamic_urls = []
    api_url = "https://api.github.com/repos/bannedbook/fanqiang/contents/docs"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        print("[*] 正在通过 GitHub API 自动探测 docs/ 目录下的最新文件...")
        resp = requests.get(api_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            files = resp.json()
            # 过滤出所有以 .py 结尾的文件
            py_files = [f for f in files if f.get("name", "").endswith(".py") and f.get("type") == "file"]
            
            # 对每一个 py 文件，获取其最后一次 commit 的修改时间进行排序
            file_with_dates = []
            for f in py_files:
                file_name = f.get("name")
                download_url = f.get("download_url")
                
                # 获取该文件的单个 commit 时间
                commit_api = f"https://api.github.com/repos/bannedbook/fanqiang/commits?path=docs/{file_name}&page=1&per_page=1"
                try:
                    c_resp = requests.get(commit_api, headers=headers, timeout=5)
                    if c_resp.status_code == 200 and len(c_resp.json()) > 0:
                        commit_date = c_resp.json()[0]["commit"]["committer"]["date"]
                    else:
                        commit_date = ""
                except Exception:
                    commit_date = ""
                
                file_with_dates.append((file_name, download_url, commit_date))

            # 按照修改时间倒序排列（最新的在最前）
            file_with_dates.sort(key=lambda x: x[2], reverse=True)

            print(f"[+] 自动发现 {len(file_with_dates)} 个文件（按最新更新时间排序）：")
            for fname, durl, fdate in file_with_dates:
                print(f"    - {fname} (更新时间: {fdate})")
                dynamic_urls.append(durl)

        else:
            print(f"[-] GitHub API 返回状态码: {resp.status_code}，将启用备用固定源")
    except Exception as e:
        print(f"[-] 自动探测异常: {e}，将启用备用固定源")

    # 将动态扫描出的最新链接放在最前面，后接备用链接去重后兜底
    final_urls = dynamic_urls + [u for u in STATIC_FALLBACK_URLS if u not in dynamic_urls]
    return final_urls

def fetch_and_decrypt():
    urls = get_latest_remote_urls()
    headers = {"User-Agent": "NekoBox/Android/6.5.0"}

    for url in urls:
        try:
            print(f"[*] 正在尝试拉取并解密: {url}")
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200 and resp.text.strip():
                encrypted_base64 = resp.text.strip()
                raw_cipher = base64.b64decode(encrypted_base64)
                cipher = AES.new(KEY, AES.MODE_CBC, IV)
                decrypted = unpad(cipher.decrypt(raw_cipher), AES.block_size).decode('utf-8')
                
                # 简单验证解密内容是否包含 vmess 节点
                if "vmess://" in decrypted:
                    print(f"[+] 成功从 {url} 获取并解密最新节点数据！")
                    return decrypted
                else:
                    print(f"[-] {url} 解密成功但未发现节点数据，尝试下一个文件...")
        except Exception as e:
            print(f"[-] 处理 {url} 失败: {e}")

    raise Exception("所有动态与静态订阅源均无法拉取或解密！")

def clean_node_name(ps_name, server_addr, existing_names):
    name = ps_name.strip()
    if name.startswith("http://") or name.startswith("https://") or not name:
        prefix = server_addr.split("-")[0] if "-" in server_addr else server_addr.split(".")[0]
        name = prefix.lower()

    original_name = name
    count = 1
    while name in existing_names:
        name = f"{original_name}-{count}"
        count += 1
    existing_names.add(name)
    return name

def parse_vmess_links(decrypted_text):
    vmess_nodes = []
    existing_names = set()
    
    links = re.findall(r'vmess://[a-zA-Z0-9+/=]+', decrypted_text)
    for link in links:
        try:
            b64_str = link.replace("vmess://", "")
            raw_json = base64.b64decode(b64_str).decode('utf-8')
            node_info = json.loads(raw_json)
            
            valid_name = clean_node_name(node_info.get("ps", ""), node_info.get("add", ""), existing_names)
            node_info["ps"] = valid_name
            
            new_b64 = base64.b64encode(json.dumps(node_info).encode('utf-8')).decode('utf-8')
            new_link = f"vmess://{new_b64}"
            
            vmess_nodes.append((new_link, node_info))
        except Exception as e:
            print(f"[-] 解析节点异常: {e}")
    return vmess_nodes

def generate_v2ray(vmess_nodes):
    all_links = "\n".join([item[0] for item in vmess_nodes])
    return base64.b64encode(all_links.encode('utf-8')).decode('utf-8')

def generate_clash(vmess_nodes):
    proxies = []
    proxy_names = []

    for _, n in vmess_nodes:
        name = n.get("ps")
        proxy_names.append(name)
        
        server_host = n.get("host") if n.get("host") else n.get("add")
        proxy_item = {
            "name": name,
            "type": "vmess",
            "server": n.get("add"),
            "port": int(n.get("port", 80)),
            "uuid": n.get("id"),
            "alterId": int(n.get("aid", 0)),
            "cipher": n.get("scy", "auto"),
            "udp": True,
            "tls": False,
            "network": "http",
            "http-opts": {
                "path": [n.get("path", "/")],
                "headers": {
                    "Host": [server_host]
                }
            }
        }
        if n.get("net") == "httpupgrade":
            proxy_item["http-opts"]["v2ray-http-upgrade"] = True
            
        proxies.append(proxy_item)

    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["AUTO"] + proxy_names
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "url": "https://cp.cloudflare.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names
            }
        ],
        "rules": [
            "DOMAIN-SUFFIX,18838005.xyz,DIRECT",
            "DOMAIN-SUFFIX,cn,DIRECT",
            "DOMAIN-KEYWORD,baidu,DIRECT",
            "DOMAIN-KEYWORD,qq,DIRECT",
            "DOMAIN-KEYWORD,weixin,DIRECT",
            "DOMAIN-KEYWORD,alipay,DIRECT",
            "DOMAIN-KEYWORD,taobao,DIRECT",
            "DOMAIN-KEYWORD,bilibili,DIRECT",
            "DOMAIN-KEYWORD,jd,DIRECT",
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY"
        ]
    }
    return yaml.dump(clash_config, allow_unicode=True, sort_keys=False)

def generate_singbox(vmess_nodes):
    node_tags = [n.get("ps") for _, n in vmess_nodes]
    
    outbounds = [
        {
            "type": "selector",
            "tag": "proxy",
            "outbounds": ["auto"] + node_tags,
            "default": "auto"
        },
        {
            "type": "urltest",
            "tag": "auto",
            "outbounds": node_tags,
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": "3m",
            "idle_timeout": "30m"
        }
    ]

    for _, n in vmess_nodes:
        server_host = n.get("host") if n.get("host") else n.get("add")
        node_outbound = {
            "type": "vmess",
            "tag": n.get("ps"),
            "server": n.get("add"),
            "server_port": int(n.get("port", 80)),
            "uuid": n.get("id"),
            "security": n.get("scy", "auto"),
            "alter_id": int(n.get("aid", 0)),
            "transport": {
                "type": n.get("net", "httpupgrade"),
                "host": server_host,
                "path": n.get("path", "/")
            }
        }
        outbounds.append(node_outbound)

    outbounds.append({"type": "direct", "tag": "direct"})
    outbounds.append({"type": "block", "tag": "block"})

    singbox_config = {
        "log": {
            "level": "debug",
            "timestamp": True
        },
        "dns": {
            "servers": [
                {
                    "type": "tcp",
                    "tag": "dns-remote",
                    "server": "8.8.8.8",
                    "server_port": 53,
                    "detour": "proxy"
                },
                {
                    "type": "udp",
                    "tag": "dns-direct",
                    "server": "223.5.5.5",
                    "server_port": 53
                }
            ],
            "rules": [
                {
                    "domain_suffix": [
                        "18838005.xyz",
                        ".cn"
                    ],
                    "server": "dns-direct"
                },
                {
                    "domain_keyword": [
                        "baidu",
                        "qq",
                        "weixin",
                        "alipay",
                        "taobao",
                        "bilibili"
                    ],
                    "server": "dns-direct"
                }
            ],
            "final": "dns-remote",
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": [
                    "172.19.0.1/30"
                ],
                "auto_route": True,
                "strict_route": True
            }
        ],
        "outbounds": outbounds,
        "route": {
            "default_domain_resolver": "dns-direct",
            "rules": [
                {
                    "action": "sniff"
                },
                {
                    "protocol": "dns",
                    "action": "hijack-dns"
                },
                {
                    "network": "udp",
                    "port": 443,
                    "action": "reject"
                },
                {
                    "ip_is_private": True,
                    "action": "route",
                    "outbound": "direct"
                },
                {
                    "domain_suffix": [
                        ".cn",
                        "18838005.xyz"
                    ],
                    "action": "route",
                    "outbound": "direct"
                },
                {
                    "domain_keyword": [
                        "baidu",
                        "qq",
                        "weixin",
                        "alipay",
                        "taobao",
                        "bilibili",
                        "jd"
                    ],
                    "action": "route",
                    "outbound": "direct"
                }
            ],
            "auto_detect_interface": True,
            "final": "proxy"
        }
    }
    return json.dumps(singbox_config, indent=2, ensure_ascii=False)

def main():
    decrypted_text = fetch_and_decrypt()
    nodes = parse_vmess_links(decrypted_text)
    print(f"[*] 成功获取并解密 {len(nodes)} 个节点：{[n['ps'] for _, n in nodes]}")

    with open("v2ray.txt", "w", encoding="utf-8") as f:
        f.write(generate_v2ray(nodes))

    with open("clash.yaml", "w", encoding="utf-8") as f:
        f.write(generate_clash(nodes))

    with open("singbox.json", "w", encoding="utf-8") as f:
        f.write(generate_singbox(nodes))

    print("[+] 全部更新完毕！")

if __name__ == "__main__":
    main()
